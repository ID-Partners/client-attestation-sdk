// Package clientattestation is a client-side builder SDK for OAuth
// Attestation-Based Client Authentication
// (draft-ietf-oauth-attestation-based-client-auth). It is a Go port of the
// Java and Python reference SDKs and produces artifacts accepted by the same
// AS-side verifier.
package clientattestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// SigningKeyPair is a signing key pair (public + private) carrying its JWS alg
// and RFC 7638 thumbprint kid. It is used both as the client instance key —
// which signs PoP / DPoP proofs and is bound into an attestation's cnf — and as
// a Client Attester's issuing key.
type SigningKeyPair struct {
	privateKey jwk.Key
	algorithm  string
	keyID      string
	publicJWK  map[string]any
}

// Generate creates a fresh key pair for the given JWS algorithm: ES256/384/512
// (EC P-256/384/521) or RS256/384/512 / PS256/384/512 (RSA 2048).
func Generate(algorithm string) (*SigningKeyPair, error) {
	var raw any
	var err error
	switch algorithm {
	case "ES256":
		raw, err = ecdsaGenerate("P-256")
	case "ES384":
		raw, err = ecdsaGenerate("P-384")
	case "ES512":
		raw, err = ecdsaGenerate("P-521")
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		raw, err = rsaGenerate(2048)
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", algorithm)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to generate a %s key: %w", algorithm, err)
	}
	return newSigningKeyPair(raw, algorithm)
}

// FromJWK wraps an existing JWK (which must contain the private component "d")
// for the given algorithm. The jwkJSON argument may be raw JSON bytes, a string,
// or a map[string]any.
//
// The key must suit the algorithm: an EC key on the algorithm's curve for
// ES256/384/512 (P-256/384/521), an RSA key of at least 2048 bits for
// RS256/384/512 and PS256/384/512. Its public members must belong to its private
// key. Only the key material is kept: the published JWK is re-encoded
// canonically (fixed-width EC coordinates, minimal RSA integers) and its kid is
// always the RFC 7638 thumbprint, whatever "kid" or other members the input had.
func FromJWK(jwkJSON any, algorithm string) (*SigningKeyPair, error) {
	var data []byte
	switch v := jwkJSON.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	case map[string]any:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal JWK map: %w", err)
		}
		data = b
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("unsupported JWK input type %T: %w", jwkJSON, err)
		}
		data = b
	}
	if !jwkHasPrivate(data) {
		return nil, fmt.Errorf("JWK does not contain a private key")
	}
	key, err := jwk.ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JWK: %w", err)
	}
	var raw any
	if err := key.Raw(&raw); err != nil {
		return nil, fmt.Errorf("unable to read the JWK's key material: %w", err)
	}
	return newSigningKeyPair(raw, algorithm)
}

// ecAlgorithmCurve is the curve each ECDSA JWS algorithm signs on.
var ecAlgorithmCurve = map[string]elliptic.Curve{
	"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521(),
}

// rsaAlgorithms are the RSA JWS algorithms the SDK signs with.
var rsaAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true, "PS256": true, "PS384": true, "PS512": true,
}

// minRSABits is the smallest RSA modulus the SDK signs with.
const minRSABits = 2048

// isSigningAlgorithm reports whether alg is one the SDK signs with: ES256/384/512, RS256/384/512 or
// PS256/384/512.
func isSigningAlgorithm(alg string) bool {
	_, ec := ecAlgorithmCurve[alg]
	return ec || rsaAlgorithms[alg]
}

// checkKeyForAlgorithm refuses a key the algorithm can't sign with (wrong type, wrong curve, RSA under
// 2048 bits) and a key whose public half doesn't belong to its private half: signing with one key while
// advertising another (as kid, cnf.jwk or the DPoP jwk) gives credentials no verifier will accept.
func checkKeyForAlgorithm(raw any, algorithm string) error {
	if !isSigningAlgorithm(algorithm) {
		return fmt.Errorf("unsupported signing algorithm: %s", algorithm)
	}
	digest := sha256.Sum256([]byte("client-attestation-sdk key pair check"))
	switch k := raw.(type) {
	case *ecdsa.PrivateKey:
		curve, ok := ecAlgorithmCurve[algorithm]
		if !ok {
			return fmt.Errorf("%s needs an RSA key, not an EC key", algorithm)
		}
		if k.Curve == nil || k.Curve.Params().Name != curve.Params().Name {
			return fmt.Errorf("%s needs an EC key on %s", algorithm, curve.Params().Name)
		}
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
		if err != nil || !ecdsa.VerifyASN1(&k.PublicKey, digest[:], sig) {
			return fmt.Errorf("the JWK's public key (x, y) does not match its private key (d)")
		}
	case *rsa.PrivateKey:
		if !rsaAlgorithms[algorithm] {
			return fmt.Errorf("%s needs an EC key, not an RSA key", algorithm)
		}
		if k.N == nil || k.N.BitLen() < minRSABits {
			return fmt.Errorf("RSA keys must be at least %d bits", minRSABits)
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		if err != nil || rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, digest[:], sig) != nil {
			return fmt.Errorf("the JWK's public key (n, e) does not match its private key")
		}
	default:
		return fmt.Errorf("%s needs an EC or RSA private key", algorithm)
	}
	return nil
}

// jwkHasPrivate reports whether the JWK JSON carries a private component ("d").
func jwkHasPrivate(data []byte) bool {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return false
	}
	_, ok := m["d"]
	return ok
}

// newSigningKeyPair wraps a raw private key (*ecdsa.PrivateKey or *rsa.PrivateKey). The JWK is rebuilt
// from the raw key, so it carries no caller-supplied members: jws.Sign copies a key's own "kid" into the
// header, which must always be the thumbprint.
func newSigningKeyPair(raw any, algorithm string) (*SigningKeyPair, error) {
	if err := checkKeyForAlgorithm(raw, algorithm); err != nil {
		return nil, err
	}
	private, err := jwk.FromRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("unable to import %s key: %w", algorithm, err)
	}
	pub, err := private.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("unable to derive public key: %w", err)
	}
	tp, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("unable to compute key thumbprint: %w", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(tp)

	publicParams, err := canonicalPublicJWK(pub)
	if err != nil {
		return nil, err
	}
	publicParams["kid"] = kid

	return &SigningKeyPair{
		privateKey: private,
		algorithm:  algorithm,
		keyID:      kid,
		publicJWK:  publicParams,
	}, nil
}

// canonicalPublicJWK returns the public JWK reduced to exactly the RFC 7638
// required members (EC: kty, crv, x, y; RSA: kty, e, n), matching what the Java
// (jose4j PUBLIC_ONLY) and Python (PyJWT to_jwk) ports emit. No "kid" is added
// here; callers add it when required.
func canonicalPublicJWK(pub jwk.Key) (map[string]any, error) {
	m, err := pub.AsMap(context.Background())
	if err != nil {
		return nil, fmt.Errorf("unable to convert public key to map: %w", err)
	}
	full := map[string]any{}
	for k, v := range m {
		full[k] = normalizeJWKValue(v)
	}
	kty := asString(full["kty"])
	full["kty"] = kty
	if crv, ok := full["crv"]; ok {
		full["crv"] = asString(crv)
	}
	out := map[string]any{}
	switch kty {
	case "EC":
		for _, k := range []string{"kty", "crv", "x", "y"} {
			if v, ok := full[k]; ok {
				out[k] = v
			}
		}
	case "OKP":
		for _, k := range []string{"kty", "crv", "x"} {
			if v, ok := full[k]; ok {
				out[k] = v
			}
		}
	case "RSA":
		for _, k := range []string{"kty", "e", "n"} {
			if v, ok := full[k]; ok {
				out[k] = v
			}
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
	return out, nil
}

// normalizeJWKValue turns jwx's byte-slice field values into their base64url
// (no-padding) string form and its typed-string values (jwa.KeyType,
// jwa.EllipticCurveAlgorithm) into plain strings, matching the JSON a JWK is
// expected to carry.
func normalizeJWKValue(v any) any {
	switch x := v.(type) {
	case []byte:
		return base64.RawURLEncoding.EncodeToString(x)
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return v
	}
}

// asString coerces a normalized JWK value (already run through normalizeJWKValue,
// or a raw jwx typed-string) to a plain Go string.
func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

// Algorithm returns the JWS "alg" for this key.
func (s *SigningKeyPair) Algorithm() string { return s.algorithm }

// KeyID returns the RFC 7638 thumbprint kid for this key.
func (s *SigningKeyPair) KeyID() string { return s.keyID }

// PublicJWK returns a fresh copy of the public-only JWK (including "kid") — an
// attestation cnf.jwk value or a DPoP header value.
func (s *SigningKeyPair) PublicJWK() map[string]any {
	out := make(map[string]any, len(s.publicJWK))
	for k, v := range s.publicJWK {
		out[k] = v
	}
	return out
}

// signCompact signs a claims map into a compact JWS with an explicit "typ"
// header, keyed by this SigningKeyPair. When embedJWK is set the public key
// travels in a "jwk" header (as DPoP requires); otherwise the key's thumbprint
// "kid" is set.
func (s *SigningKeyPair) signCompact(claims map[string]any, typ string, embedJWK bool) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("unable to marshal claims: %w", err)
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set("typ", typ); err != nil {
		return "", err
	}
	if embedJWK {
		pub := s.PublicJWK()
		delete(pub, "kid")
		jwkVal, err := publicJWKObject(pub)
		if err != nil {
			return "", err
		}
		if err := hdrs.Set(jws.JWKKey, jwkVal); err != nil {
			return "", err
		}
	} else {
		if err := hdrs.Set(jws.KeyIDKey, s.keyID); err != nil {
			return "", err
		}
	}

	alg := jwa.SignatureAlgorithm(s.algorithm)
	signed, err := jws.Sign(payload, jws.WithKey(alg, s.privateKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("JWS signing failed: %w", err)
	}
	return string(signed), nil
}

// publicJWKObject builds a jwk.Key from a public-JWK map so jwx serializes it as
// a proper JSON object (its canonical member order) inside the "jwk" header.
func publicJWKObject(m map[string]any) (jwk.Key, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal public JWK: %w", err)
	}
	key, err := jwk.ParseKey(b)
	if err != nil {
		return nil, fmt.Errorf("unable to parse public JWK: %w", err)
	}
	return key, nil
}

func requireText(value, field string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	return value, nil
}
