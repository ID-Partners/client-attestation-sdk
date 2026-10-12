package tokenvalidator

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/id-partners/client-attestation-sdk/go/internal/netpolicy"
	"github.com/id-partners/client-attestation-sdk/go/internal/sdklog"
)

// HTTPPostFunc performs a form POST and returns the parsed JSON object, for WithHTTPPost (introspection).
// The default uses net/http with the SDK's timeout, no redirects and a response size cap. A hook's error is
// logged with the reason it carries: a timeout, a *json.SyntaxError or *json.UnmarshalTypeError (malformed),
// and so on. A hook that returns a nil map and no error is logged as malformed. An error of a type the SDK
// doesn't recognise, such as the hook's own size-limit error, is logged as network.
type HTTPPostFunc func(endpoint, body string, headers map[string]string) (map[string]any, error)

// AccessTokenValidator validates access tokens for a resource server.
//
// Validate does local JWT validation in a fixed order — algorithm accepted, key resolvable, signature,
// typ (when present), iss, exp present, exp, nbf, iat not in the future, audience, then scope — returning
// the first failure's stable error code. That order is
// part of the cross-language contract so every port reports the same verdict. ValidateActive instead uses
// RFC 7662 introspection.
type AccessTokenValidator struct {
	config   *Config
	jwks     *jwksProvider
	httpGet  HTTPGetFunc
	httpPost HTTPPostFunc
	logger   *slog.Logger
	now      func() time.Time
}

// Option customizes a validator (e.g. injecting HTTP transports for tests).
type Option func(*AccessTokenValidator)

// WithHTTPGet injects the transport used to fetch a jwks_uri.
func WithHTTPGet(f HTTPGetFunc) Option { return func(v *AccessTokenValidator) { v.httpGet = f } }

// WithHTTPPost injects the transport used for introspection.
func WithHTTPPost(f HTTPPostFunc) Option { return func(v *AccessTokenValidator) { v.httpPost = f } }

// WithClock sets the clock exp, nbf and iat are checked against (default time.Now), to validate as of a
// fixed instant.
func WithClock(now func() time.Time) Option { return func(v *AccessTokenValidator) { v.now = now } }

// New builds a validator from config. It refuses a config without an issuer or an audience, with a
// negative LeewaySeconds, or with a plain-http JWKSURI or introspection endpoint on a non-loopback host
// (unless AllowInsecure is set).
//
// The validator keeps its own copy of config: changing the Config (or its slices) after New returns does
// not change what the validator accepts.
func New(config *Config, opts ...Option) (*AccessTokenValidator, error) {
	config = config.clone()
	if config.Issuer == "" {
		return nil, errors.New("tokenvalidator: issuer is required")
	}
	if len(config.Audiences) == 0 {
		return nil, errors.New("tokenvalidator: at least one audience is required")
	}
	if err := config.check(); err != nil {
		return nil, err
	}
	v := &AccessTokenValidator{config: config, httpPost: defaultHTTPPost, now: time.Now}
	for _, o := range opts {
		o(v)
	}
	provider, err := newJWKSProvider(config.JWKS, config.JWKSURI, v.httpGet)
	if err != nil {
		return nil, err
	}
	v.logger = sdklog.OrDiscard(v.logger)
	provider.logger = v.logger
	v.jwks = provider
	return v, nil
}

// Validate performs local JWT validation. requiredScopes overrides the configured RequiredScopes when non-nil.
func (v *AccessTokenValidator) Validate(token string, requiredScopes []string) Result {
	return v.logVerdict(v.validate(token, requiredScopes), "jwt")
}

func (v *AccessTokenValidator) validate(token string, requiredScopes []string) Result {
	required := requiredScopes
	if required == nil {
		required = v.config.RequiredScopes
	}

	parts, err := splitCompact(token)
	if err != nil {
		// never echo token data to the caller: the description lands in WWW-Authenticate
		return failure(ErrInvalidToken, "malformed token")
	}
	header := parts.header

	alg, _ := header["alg"].(string)
	if alg == "" || isForbiddenAlgorithm(alg) || !contains(v.config.acceptedAlgorithms(), alg) {
		return failure(ErrUnsupportedAlgorithm, "algorithm not accepted")
	}

	var key jwk.Key
	switch kid := header["kid"].(type) {
	case nil:
		key, err = v.jwks.resolve("", alg)
	case string:
		if kid != "" { // an empty kid names no key; only an absent one means "the sole key"
			key, err = v.jwks.resolve(kid, alg)
		}
	}
	if err != nil {
		// the fetch failure's detail (internal host, dial error, IdP body) went to the logger as
		// jwks.fetch_failed; the description lands in WWW-Authenticate, in front of anyone
		return failure(ErrKeyNotFound, "signing keys unavailable")
	}
	if key == nil {
		return failure(ErrKeyNotFound, "no signing key matches the token")
	}

	if !verifySignature(alg, key, parts) {
		return failure(ErrInvalidSignature, "signature verification failed")
	}
	claims, err := parseObject(parts.payload, "payload")
	if err != nil {
		return failure(ErrInvalidToken, err.Error())
	}

	if typ, present := header["typ"]; present && typ != nil && !v.acceptsType(typ) {
		return failure(ErrInvalidTokenType, "token is not a JWT access token")
	}

	if iss, _ := claims["iss"].(string); iss != v.config.Issuer {
		return failure(ErrInvalidIssuer, "unexpected issuer")
	}

	now := v.now().Unix()
	leeway := int64(v.config.leeway())
	exp, hasExp, err := numericDate(claims, "exp")
	if err != nil {
		return failure(ErrInvalidToken, err.Error())
	}
	nbf, hasNbf, err := numericDate(claims, "nbf")
	if err != nil {
		return failure(ErrInvalidToken, err.Error())
	}
	iat, hasIat, err := numericDate(claims, "iat")
	if err != nil {
		return failure(ErrInvalidToken, err.Error())
	}
	if !hasExp {
		return failure(ErrMissingExpiry, "token has no exp claim")
	}
	if now > exp+leeway {
		return failure(ErrExpired, "token has expired")
	}
	if hasNbf && now+leeway < nbf {
		return failure(ErrNotYetValid, "token is not yet valid")
	}
	if hasIat && now+leeway < iat {
		return failure(ErrIssuedInFuture, "token was issued in the future")
	}

	audience, err := audienceOf(claims)
	if err != nil {
		return failure(ErrInvalidToken, err.Error())
	}
	if !anyIn(v.config.Audiences, audience) {
		return failure(ErrInvalidAudience, "token audience is not accepted")
	}

	granted, err := scopesOf(claims)
	if err != nil {
		return failure(ErrInvalidToken, err.Error())
	}
	if missing := missingScopes(required, granted); len(missing) > 0 {
		return failure(ErrInsufficientScope, "missing scopes: "+strings.Join(missing, " "))
	}
	if err := checkSubject(claims); err != nil {
		return failure(ErrInvalidToken, err.Error())
	}

	return success(claims, granted, audience)
}

// acceptsType reports whether a present, non-null typ header is acceptable: a non-string never is (unless the
// check is off).
func (v *AccessTokenValidator) acceptsType(typ any) bool {
	s, ok := typ.(string)
	if !ok {
		return v.config.DisableTokenTypeCheck
	}
	return v.config.acceptsTokenType(s)
}

// minRSAKeyBits is the smallest RSA modulus a key may have to verify a signature (RFC 7518 section 3.3).
const minRSAKeyBits = 2048

// curveOf is the one curve an ES* algorithm verifies with.
var curveOf = map[string]jwa.EllipticCurveAlgorithm{"ES256": jwa.P256, "ES384": jwa.P384, "ES512": jwa.P521}

// verifySignature checks the JWS signature over the signing input with key, for alg only.
func verifySignature(alg string, key jwk.Key, parts *compactParts) bool {
	if !keyFits(alg, key) {
		return false
	}
	verifier, err := jws.NewVerifier(jwa.SignatureAlgorithm(alg))
	if err != nil {
		return false
	}
	return verifier.Verify(parts.signingInput, parts.signature, key) == nil
}

// keyFits reports whether alg may use key at all. jwx sizes an ECDSA signature by the key's curve but hashes
// by the header alg, so without this a P-256 key would verify an ES384 signature; and it takes an RSA key
// of any size.
func keyFits(alg string, key jwk.Key) bool {
	switch k := key.(type) {
	case jwk.ECDSAPublicKey:
		return curveOf[alg] != "" && k.Crv() == curveOf[alg]
	case jwk.RSAPublicKey:
		return new(big.Int).SetBytes(k.N()).BitLen() >= minRSAKeyBits
	}
	return true
}

// Introspect performs an RFC 7662 introspection request and returns the parsed response.
func (v *AccessTokenValidator) Introspect(token string) (map[string]any, error) {
	cfg := v.config.Introspection
	if cfg == nil {
		return nil, errors.New("no introspection endpoint configured")
	}
	form := url.Values{}
	form.Set("token", token)
	form.Set("token_type_hint", "access_token")
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "application/json",
	}
	if cfg.AuthMethod == "" || cfg.AuthMethod == "client_secret_basic" {
		creds := base64.StdEncoding.EncodeToString([]byte(cfg.ClientID + ":" + cfg.ClientSecret))
		headers["Authorization"] = "Basic " + creds
	} else {
		form.Set("client_id", cfg.ClientID)
		form.Set("client_secret", cfg.ClientSecret)
	}
	post := v.httpPost
	if post == nil {
		post = defaultHTTPPost
	}
	data, err := post(cfg.Endpoint, form.Encode(), headers)
	if err == nil && data == nil {
		err = &malformedError{err: errors.New("introspection: the response is not a JSON object")}
	}
	if err != nil {
		reason, status := failureReason(err)
		sdklog.Log(context.Background(), v.logger, slog.LevelWarn, "http.failed",
			"step", "introspection", "method", http.MethodPost,
			"host", sdklog.Host(cfg.Endpoint), "path", sdklog.Path(cfg.Endpoint),
			"status", sdklog.NonZero(int64(status)), "reason", reason)
	}
	return data, err
}

// ValidateActive introspects the token and enforces active, then scope, then the audience when the response
// carries one. A failed introspection call (no endpoint configured, a transport failure, a non-2xx answer
// or a body that is not a JSON object) is returned as an error, never as a verdict: it says nothing about
// the token.
func (v *AccessTokenValidator) ValidateActive(token string, requiredScopes []string) (Result, error) {
	data, err := v.Introspect(token)
	if err != nil {
		return Result{}, err
	}
	return v.logVerdict(v.validateActive(data, requiredScopes), "introspection"), nil
}

func (v *AccessTokenValidator) validateActive(data map[string]any, requiredScopes []string) Result {
	// RFC 7662 section 2.2: active is a boolean, so only JSON true counts
	if active, _ := data["active"].(bool); !active {
		return failure(ErrInactive, "token is not active")
	}
	required := requiredScopes
	if required == nil {
		required = v.config.RequiredScopes
	}
	granted, err := scopesOf(data)
	if err != nil {
		return failure(ErrInvalidToken, err.Error())
	}
	if missing := missingScopes(required, granted); len(missing) > 0 {
		return failure(ErrInsufficientScope, "missing scopes: "+strings.Join(missing, " "))
	}
	audience, err := audienceOf(data)
	if err != nil {
		return failure(ErrInvalidToken, err.Error())
	}
	if len(audience) > 0 && !anyIn(v.config.Audiences, audience) {
		return failure(ErrInvalidAudience, "token audience is not accepted")
	}
	if err := checkSubject(data); err != nil {
		return failure(ErrInvalidToken, err.Error())
	}
	return success(data, granted, audience)
}

// MaxIntrospectionBytes caps the size of an introspection response; a larger one is an error.
const MaxIntrospectionBytes = 1024 * 1024

// introspectionHTTPClient never follows a redirect: it would carry the resource server's credentials.
var introspectionHTTPClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: netpolicy.Transport, // an environment proxy only for https to a remote host
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("introspection: redirects are not followed")
	},
}

func defaultHTTPPost(endpoint, body string, headers map[string]string) (map[string]any, error) {
	if netpolicy.HasUserinfo(endpoint) {
		return nil, fmt.Errorf("POST %s: %w", netpolicy.Display(endpoint), netpolicy.ErrUserinfo)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, netpolicy.RedactError(err)
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := introspectionHTTPClient.Do(req)
	if err != nil {
		return nil, netpolicy.RedactError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{what: "introspection", status: resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxIntrospectionBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxIntrospectionBytes {
		return nil, &tooLargeError{msg: fmt.Sprintf("introspection: response is larger than %d bytes", MaxIntrospectionBytes)}
	}
	// like every port's shared transport, invalid UTF-8 becomes U+FFFD; the JSON itself is parsed strictly
	obj, err := parseObject(bytes.ToValidUTF8(raw, []byte("\uFFFD")), "introspection response")
	if err != nil {
		return nil, &malformedError{err: err}
	}
	return obj, nil
}

// --- claim helpers (also used by result.go's success) ---

func stringClaim(claims map[string]any, key string) string {
	if s, ok := claims[key].(string); ok {
		return s
	}
	return ""
}

func intClaim(claims map[string]any, key string) int64 {
	n, ok, err := numericDate(claims, key)
	if !ok || err != nil {
		return 0
	}
	return n
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func anyIn(want, have []string) bool {
	for _, w := range want {
		if contains(have, w) {
			return true
		}
	}
	return false
}

func missingScopes(required, granted []string) []string {
	var missing []string
	for _, r := range required {
		if !contains(granted, r) {
			missing = append(missing, r)
		}
	}
	return missing
}
