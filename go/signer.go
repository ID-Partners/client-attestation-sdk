package clientattestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// JwsSigner is a JWS signing capability whose private key may live outside the process (a vault, HSM, or
// KMS). Sign returns the RAW JWS signature over the signing input — for ECDSA the fixed-width r||s
// concatenation RFC 7515 requires, not ASN.1/DER. *SigningKeyPair covers the local-key case;
// *OpenBaoTransitSigner signs inside a vault.
type JwsSigner interface {
	Algorithm() string
	KeyID() string
	PublicJWK() map[string]any
	Sign(signingInput []byte) ([]byte, error)
}

// ecSignatureBytes is the length of a raw r||s JWS signature for each ECDSA algorithm.
var ecSignatureBytes = map[string]int{"ES256": 64, "ES384": 96, "ES512": 132}

// signExternal assembles a compact JWS whose signature is produced by an external signer. The header
// carries the signer's kid (external signers hold issuing keys, referenced by id, never an embedded jwk).
// The signer's algorithm must be one the SDK signs with (never "none"), and its signature must not be
// empty and, for ES*, must be the fixed-width r||s (not DER, not truncated).
func signExternal(claims map[string]any, signer JwsSigner, typ string) (string, error) {
	alg := signer.Algorithm()
	if !isSigningAlgorithm(alg) {
		return "", fmt.Errorf("external signer algorithm %q is not allowed: use ES256/384/512, RS256/384/512 or PS256/384/512", alg)
	}
	headerJSON, err := json.Marshal(map[string]any{"alg": alg, "typ": typ, "kid": signer.KeyID()})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("unable to marshal claims: %w", err)
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(payloadJSON)
	sig, err := signer.Sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	if len(sig) == 0 {
		return "", fmt.Errorf("external signer returned an empty signature")
	}
	if want, ok := ecSignatureBytes[alg]; ok && len(sig) != want {
		return "", fmt.Errorf("external signer returned a %d-byte %s signature; want the %d-byte raw r||s", len(sig), alg, want)
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

var keyTypeAlg = map[string]string{"ecdsa-p256": "ES256", "ecdsa-p384": "ES384", "ecdsa-p521": "ES512"}
var algHash = map[string]string{"ES256": "sha2-256", "ES384": "sha2-384", "ES512": "sha2-512"}
var algCurve = map[string]string{"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}

// transitKeyName is what a transit key name may contain. The name goes into the request path, so "/", "?",
// "#", "%" and dot segments would point the vault token at another vault path.
var transitKeyName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// OpenBaoTransitSigner is a JwsSigner backed by an OpenBao / HashiCorp Vault transit engine: the attestation
// is signed inside the vault (POST /v1/transit/sign/<key> with marshaling_algorithm=jws, which returns the
// fixed-width r||s) and the private key never leaves it. NewOpenBaoTransitSigner reads the key metadata to
// pin the latest version, derive the public JWK and compute its RFC 7638 kid. Fail-closed.
//
// Experimental (see docs/api.md): a client for a third-party API that authenticates with a static token
// only; its constructor will change when other auth methods are added.
type OpenBaoTransitSigner struct {
	base       string
	token      string
	keyName    string
	algorithm  string
	hash       string
	keyVersion int64
	keyID      string
	publicJWK  map[string]any
	client     *http.Client
}

// OpenBaoOption tunes NewOpenBaoTransitSigner.
type OpenBaoOption func(*openBaoOptions)

type openBaoOptions struct{ allowInsecure bool }

// WithOpenBaoAllowInsecure permits a plain-http baoAddr on a non-loopback host. Without it baoAddr must be
// https (localhost, 127.0.0.1 and ::1 are always allowed): the vault token rides on every call, and the
// public key read from the vault becomes the attester's published JWK.
func WithOpenBaoAllowInsecure() OpenBaoOption {
	return func(o *openBaoOptions) { o.allowInsecure = true }
}

// NewOpenBaoTransitSigner builds a signer for the transit key keyName, reachable at baoAddr with token.
// baoAddr must be https unless it is loopback or WithOpenBaoAllowInsecure() is given. keyName may contain
// only letters, digits, "_", "." and "-" (and is not "." or "..").
func NewOpenBaoTransitSigner(baoAddr, token, keyName string, opts ...OpenBaoOption) (*OpenBaoTransitSigner, error) {
	var o openBaoOptions
	for _, opt := range opts {
		opt(&o)
	}
	base := strings.TrimRight(baoAddr, "/")
	if !o.allowInsecure {
		if err := requireSecureURL(base, "WithOpenBaoAllowInsecure()"); err != nil {
			return nil, err
		}
	}
	if !transitKeyName.MatchString(keyName) || keyName == "." || keyName == ".." {
		return nil, fmt.Errorf("invalid transit key name %q: use only letters, digits, '_', '.' and '-'", keyName)
	}
	s := &OpenBaoTransitSigner{
		base:    base,
		token:   token,
		keyName: keyName,
		client:  safeClient(nil, 5*time.Second),
	}
	data, err := s.request(context.Background(), http.MethodGet, "/v1/transit/keys/"+keyName, nil)
	if err != nil {
		return nil, err
	}
	keyType, _ := data["type"].(string)
	alg, ok := keyTypeAlg[keyType]
	if !ok {
		return nil, fmt.Errorf("transit key %q has unsupported type for JWS signing: %s", keyName, keyType)
	}
	s.algorithm = alg
	s.hash = algHash[alg]
	s.keyVersion = int64(toFloat(data["latest_version"]))
	keys, _ := data["keys"].(map[string]any)
	latest, _ := keys[strconv.FormatInt(s.keyVersion, 10)].(map[string]any)
	pemStr, _ := latest["public_key"].(string)
	jwkMap, kid, err := ecJWKFromPEM(pemStr)
	if err != nil {
		return nil, err
	}
	if crv := asString(jwkMap["crv"]); crv != algCurve[alg] {
		return nil, fmt.Errorf("transit key %q is type %s but its public key is on %s", keyName, keyType, crv)
	}
	jwkMap["kid"] = kid
	jwkMap["alg"] = alg
	s.publicJWK = jwkMap
	s.keyID = kid
	return s, nil
}

// Algorithm returns the JWS "alg" this signer produces.
func (s *OpenBaoTransitSigner) Algorithm() string { return s.algorithm }

// KeyID returns the RFC 7638 thumbprint kid of the transit key.
func (s *OpenBaoTransitSigner) KeyID() string { return s.keyID }

// PublicJWK returns a fresh copy of the public-only JWK (including "kid").
func (s *OpenBaoTransitSigner) PublicJWK() map[string]any {
	out := make(map[string]any, len(s.publicJWK))
	for k, v := range s.publicJWK {
		out[k] = v
	}
	return out
}

// Sign signs the JWS signing input inside the vault, returning the raw r||s signature.
func (s *OpenBaoTransitSigner) Sign(signingInput []byte) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"input":                base64.StdEncoding.EncodeToString(signingInput),
		"marshaling_algorithm": "jws",
		"hash_algorithm":       s.hash,
		"key_version":          s.keyVersion,
	})
	if err != nil {
		return nil, err
	}
	data, err := s.request(context.Background(), http.MethodPost, "/v1/transit/sign/"+s.keyName, body)
	if err != nil {
		return nil, err
	}
	signature, _ := data["signature"].(string)
	if signature == "" {
		return nil, fmt.Errorf("transit sign response carried no signature")
	}
	raw := signature[strings.LastIndex(signature, ":")+1:] // envelope: vault:v<n>:<base64url(r||s)>
	return base64.RawURLEncoding.DecodeString(raw)
}

// request calls the vault. The exported API carries no context, so callers pass context.Background();
// the client's 5s timeout bounds every call.
func (s *OpenBaoTransitSigner) request(ctx context.Context, method, path string, body []byte) (map[string]any, error) {
	headers := map[string]string{"X-Vault-Token": s.token}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}
	res, err := doRequest(ctx, s.client, method, s.base+path, headers, body, defaultMaxResponseBytes)
	if err != nil {
		var sdkErr *ClientAttestationError
		if errors.As(err, &sdkErr) && sdkErr.Status != 0 { // e.g. an oversize body: it answered
			return nil, err
		}
		return nil, fmt.Errorf("OpenBao unreachable at %s: %w", s.base, err)
	}
	if res.Status != http.StatusOK {
		return nil, &ClientAttestationError{
			Message: fmt.Sprintf("OpenBao returned HTTP %d for %s", res.Status, path),
			Status:  res.Status,
			Body:    truncateBody(res.Body),
		}
	}
	var parsed struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(res.Body, &parsed); err != nil {
		return nil, &ClientAttestationError{Message: fmt.Sprintf("unparseable OpenBao response: %v", err)}
	}
	if parsed.Data == nil {
		return nil, fmt.Errorf("OpenBao response carried no data")
	}
	return parsed.Data, nil
}

// ecJWKFromPEM converts a transit public_key PEM (SubjectPublicKeyInfo) into an EC public JWK plus its
// RFC 7638 thumbprint kid.
func ecJWKFromPEM(pemStr string) (map[string]any, string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, "", fmt.Errorf("transit key metadata carried no valid PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("unparseable transit public key: %w", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		return nil, "", fmt.Errorf("transit public key is not ECDSA")
	}
	key, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, "", fmt.Errorf("unable to import transit public key: %w", err)
	}
	jwkMap, err := canonicalPublicJWK(key)
	if err != nil {
		return nil, "", err
	}
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, "", fmt.Errorf("unable to compute transit key thumbprint: %w", err)
	}
	return jwkMap, base64.RawURLEncoding.EncodeToString(tp), nil
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}
