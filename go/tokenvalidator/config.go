package tokenvalidator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// DefaultAlgorithms returns the accepted-algorithm set used when a Config leaves
// AcceptedAlgorithms nil: ECDSA / RSA-PKCS1 / RSA-PSS at 256/384/512. Each call
// returns a new slice, so changing it has no effect on validation.
func DefaultAlgorithms() []string { return append([]string(nil), defaultAlgorithms...) }

// DefaultTokenTypes returns the accepted "typ" header set used when a Config
// leaves AcceptedTokenTypes nil: RFC 9068 section 2.1 at+jwt (the application/
// prefix is optional). Each call returns a new slice.
func DefaultTokenTypes() []string { return append([]string(nil), defaultTokenTypes...) }

// The defaults the validator uses. Unexported, so no other package can widen
// what a validator with a default Config accepts.
var (
	defaultAlgorithms = []string{
		"ES256", "ES384", "ES512",
		"RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
	}
	defaultTokenTypes = []string{"at+jwt"}
)

// DefaultLeewaySeconds is the clock skew allowance applied to exp/nbf/iat when a
// Config leaves LeewaySeconds at zero and ZeroLeeway unset.
const DefaultLeewaySeconds = 60

// IntrospectionConfig holds an RFC 7662 introspection endpoint and the client
// credentials the resource server uses to authenticate to the authorization
// server.
type IntrospectionConfig struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	// AuthMethod is "client_secret_basic" (the default, also chosen by "") or "client_secret_post". New
	// refuses any other value, so a typo can't move the secret from the Authorization header into the form.
	AuthMethod string
}

// The client authentication methods IntrospectionConfig.AuthMethod accepts.
const (
	authClientSecretBasic = "client_secret_basic"
	authClientSecretPost  = "client_secret_post"
)

// Config describes what a resource server accepts: the trusted issuer, its own
// audience identifier(s), the signing keys (static JWKS or a JWKSURI to fetch),
// required scopes, accepted algorithms, clock leeway, and optional
// introspection.
//
// Issuer and Audiences are required: New refuses a Config without them,
// because a validator that skips either accepts tokens minted for someone else.
// New also refuses a JWKSURI or introspection Endpoint that isn't https, unless
// its host is loopback (localhost, 127.0.0.1, ::1) or AllowInsecure is set.
type Config struct {
	// Issuer is the expected "iss" claim. Required.
	Issuer string
	// Audiences are this resource server's accepted audience identifiers.
	// At least one is required.
	Audiences []string
	// JWKS is a static JSON Web Key Set (raw JSON: {"keys":[...]}). Mutually
	// exclusive with JWKSURI.
	JWKS json.RawMessage
	// JWKSURI is fetched (and cached, refreshed on an unknown kid) when JWKS is
	// not provided.
	JWKSURI string
	// RequiredScopes must all be granted unless Validate is called with an
	// explicit override.
	RequiredScopes []string
	// AcceptedAlgorithms is the set of accepted "alg" header values. nil means
	// DefaultAlgorithms; a non-nil empty slice accepts nothing. "none" and the
	// HS* algorithms are refused even when listed.
	AcceptedAlgorithms []string
	// LeewaySeconds is the clock skew allowance for exp/nbf/iat. Zero means
	// DefaultLeewaySeconds, because an int can't tell "unset" from 0: set
	// ZeroLeeway for no allowance at all.
	LeewaySeconds int
	// ZeroLeeway allows no clock skew at all. LeewaySeconds must then be 0.
	ZeroLeeway bool
	// AcceptedTokenTypes is checked against the JWT "typ" header when the token
	// carries one, so an ID token can't stand in for an access token. nil
	// means DefaultTokenTypes; a non-nil empty slice accepts no typ (a token
	// without one is still accepted).
	AcceptedTokenTypes []string
	// DisableTokenTypeCheck turns the "typ" check off, for an issuer that
	// stamps something other than at+jwt.
	DisableTokenTypeCheck bool
	// Introspection, when set, enables ValidateActive via RFC 7662.
	Introspection *IntrospectionConfig
	// AllowInsecure permits a plain-http JWKSURI and introspection Endpoint on
	// non-loopback hosts. Without it New refuses them: an attacker on the path
	// could serve their own keys, or read the resource server's client secret.
	AllowInsecure bool
}

// clone returns a deep copy of c (its slices and Introspection too), for New to keep: a caller reusing or
// changing its Config afterwards must not change a live validator. Nil slices stay nil, since nil
// AcceptedAlgorithms and AcceptedTokenTypes mean the defaults and an empty slice means none.
func (c *Config) clone() *Config {
	cp := *c
	cp.Audiences = slices.Clone(c.Audiences)
	cp.JWKS = slices.Clone(c.JWKS)
	cp.RequiredScopes = slices.Clone(c.RequiredScopes)
	cp.AcceptedAlgorithms = slices.Clone(c.AcceptedAlgorithms)
	cp.AcceptedTokenTypes = slices.Clone(c.AcceptedTokenTypes)
	if c.Introspection != nil {
		introspection := *c.Introspection
		cp.Introspection = &introspection
	}
	return &cp
}

// check refuses a contradictory or unsafe config.
func (c *Config) check() error {
	if c.ZeroLeeway && c.LeewaySeconds != 0 {
		return errors.New("tokenvalidator: ZeroLeeway is set but LeewaySeconds is not 0")
	}
	if c.LeewaySeconds < 0 {
		return errors.New("tokenvalidator: LeewaySeconds must not be negative")
	}
	if c.JWKSURI != "" {
		if err := c.checkSecure(c.JWKSURI, "JWKSURI"); err != nil {
			return err
		}
	}
	if c.Introspection != nil && c.Introspection.Endpoint != "" {
		if err := c.checkSecure(c.Introspection.Endpoint, "introspection Endpoint"); err != nil {
			return err
		}
	}
	if c.Introspection != nil {
		switch c.Introspection.AuthMethod {
		case "", authClientSecretBasic, authClientSecretPost:
		default:
			// never echo the value: a secret passed in the wrong field would end up in the message
			return fmt.Errorf("tokenvalidator: introspection AuthMethod must be %q or %q, got a string of %d characters",
				authClientSecretBasic, authClientSecretPost, len([]rune(c.Introspection.AuthMethod)))
		}
		if c.Introspection.ClientID == "" {
			return errors.New("tokenvalidator: introspection ClientID must not be empty")
		}
		if c.Introspection.ClientSecret == "" {
			return errors.New("tokenvalidator: introspection ClientSecret must not be empty")
		}
	}
	return nil
}

// checkSecure refuses a non-https URL unless its host is loopback (localhost,
// 127.0.0.1, ::1) or AllowInsecure is set: the same rule the client applies.
func (c *Config) checkSecure(target, what string) error {
	if c.AllowInsecure {
		return nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("tokenvalidator: %s is not a valid URL: %w", what, err)
	}
	if strings.EqualFold(u.Scheme, "https") || isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("tokenvalidator: refusing insecure %s %s: https is required for non-loopback hosts "+
		"(set AllowInsecure to override)", what, target)
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}

// acceptedAlgorithms returns the configured accepted algorithms, or the
// defaults when the field is nil (an empty slice accepts nothing).
func (c *Config) acceptedAlgorithms() []string {
	if c.AcceptedAlgorithms == nil {
		return defaultAlgorithms
	}
	return c.AcceptedAlgorithms
}

// leeway returns the configured leeway: 0 with ZeroLeeway, else the default
// when LeewaySeconds is zero.
func (c *Config) leeway() int {
	if c.ZeroLeeway {
		return 0
	}
	if c.LeewaySeconds == 0 {
		return DefaultLeewaySeconds
	}
	return c.LeewaySeconds
}

// acceptsTokenType reports whether a "typ" header value is acceptable.
func (c *Config) acceptsTokenType(typ string) bool {
	if c.DisableTokenTypeCheck {
		return true
	}
	types := c.AcceptedTokenTypes
	if types == nil {
		types = defaultTokenTypes
	}
	for _, t := range types {
		if normaliseType(t) == normaliseType(typ) {
			return true
		}
	}
	return false
}

// normaliseType compares JOSE "typ" values the way RFC 7515 section 4.1.9
// says to: case-insensitively, with an optional "application/" prefix.
func normaliseType(value string) string {
	return strings.TrimPrefix(strings.ToLower(value), "application/")
}
