package clientattestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestGenerateCoversAllAlgorithmFamilies(t *testing.T) {
	cases := []struct {
		alg string
		kty string
		crv string
	}{
		{"ES256", "EC", "P-256"},
		{"ES384", "EC", "P-384"},
		{"ES512", "EC", "P-521"},
		{"RS256", "RSA", ""},
	}
	for _, c := range cases {
		kp, err := Generate(c.alg)
		if err != nil {
			t.Fatalf("Generate(%s): %v", c.alg, err)
		}
		if kp.Algorithm() != c.alg {
			t.Errorf("%s: Algorithm() = %q", c.alg, kp.Algorithm())
		}
		pub := kp.PublicJWK()
		if pub["kty"] != c.kty {
			t.Errorf("%s: kty = %v", c.alg, pub["kty"])
		}
		if c.crv != "" && pub["crv"] != c.crv {
			t.Errorf("%s: crv = %v", c.alg, pub["crv"])
		}
		if c.kty == "RSA" {
			if _, ok := pub["n"]; !ok {
				t.Errorf("%s: RSA public JWK missing n", c.alg)
			}
		}
		if pub["kid"] != kp.KeyID() {
			t.Errorf("%s: kid mismatch", c.alg)
		}
	}
}

func TestGenerateRejectsUnsupportedAlgorithm(t *testing.T) {
	if _, err := Generate("HS256"); err == nil {
		t.Error("expected an error for HS256")
	}
}

func TestEcdsaGenerateRejectsUnknownCurve(t *testing.T) {
	if _, err := ecdsaGenerate("P-111"); err == nil {
		t.Error("expected an error for an unknown curve")
	}
}

func TestFromJWKAcceptsBytesAndString(t *testing.T) {
	kp, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	privJSON, err := json.Marshal(kp.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	fromBytes, err := FromJWK(privJSON, "ES256")
	if err != nil {
		t.Fatalf("FromJWK([]byte): %v", err)
	}
	if fromBytes.KeyID() != kp.KeyID() {
		t.Errorf("[]byte: kid = %q, want %q", fromBytes.KeyID(), kp.KeyID())
	}
	fromString, err := FromJWK(string(privJSON), "ES256")
	if err != nil {
		t.Fatalf("FromJWK(string): %v", err)
	}
	if fromString.KeyID() != kp.KeyID() {
		t.Errorf("string: kid = %q, want %q", fromString.KeyID(), kp.KeyID())
	}
}

func TestFromJWKAcceptsOKPPrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := FromJWK(b, "EdDSA")
	if err != nil {
		t.Fatalf("FromJWK(OKP): %v", err)
	}
	pub := kp.PublicJWK()
	if pub["kty"] != "OKP" || pub["crv"] != "Ed25519" {
		t.Errorf("public JWK = %v", pub)
	}
	if _, hasD := pub["d"]; hasD {
		t.Error("public JWK leaks private component d")
	}
}

func TestFromJWKErrors(t *testing.T) {
	if _, err := FromJWK(make(chan int), "ES256"); err == nil {
		t.Error("unmarshalable input: expected an error")
	}
	if _, err := FromJWK(map[string]any{"d": make(chan int)}, "ES256"); err == nil {
		t.Error("unmarshalable map value: expected an error")
	}
	if _, err := FromJWK(42, "ES256"); err == nil {
		t.Error("non-object input: expected a missing-private-key error")
	}
	if _, err := FromJWK("not json", "ES256"); err == nil {
		t.Error("invalid JSON: expected an error")
	}
	if _, err := FromJWK(`{"kty":"EC","d":"AQ"}`, "ES256"); err == nil {
		t.Error("incomplete EC JWK: expected a parse error")
	}
	// An unknown curve parses but cannot be thumbprinted.
	if _, err := FromJWK(`{"kty":"EC","crv":"P-999","x":"AQ","y":"AQ","d":"AQ"}`, "ES256"); err == nil {
		t.Error("unknown curve: expected a thumbprint error")
	}
}

func TestNewSigningKeyPairRejectsSymmetricKey(t *testing.T) {
	key, err := jwk.FromRaw([]byte("secret-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSigningKeyPair(key, "HS256"); err == nil {
		t.Error("expected an error for an oct key (unsupported key type)")
	}
}

func TestJWKValueCoercions(t *testing.T) {
	if got := normalizeJWKValue("abc"); got != "abc" {
		t.Errorf("normalizeJWKValue(string) = %v", got)
	}
	if got := normalizeJWKValue(42); got != 42 {
		t.Errorf("normalizeJWKValue(default) = %v", got)
	}
	if got := normalizeJWKValue([]byte{1, 2, 3}); got != "AQID" {
		t.Errorf("normalizeJWKValue([]byte) = %v", got)
	}
	if got := normalizeJWKValue(jwa.EC); got != "EC" {
		t.Errorf("normalizeJWKValue(Stringer) = %v", got)
	}
	if got := asString("x"); got != "x" {
		t.Errorf("asString(string) = %q", got)
	}
	if got := asString(jwa.P256); got != "P-256" {
		t.Errorf("asString(Stringer) = %q", got)
	}
	if got := asString(42); got != "42" {
		t.Errorf("asString(default) = %q", got)
	}
}

func TestSignCompactErrors(t *testing.T) {
	kp, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kp.signCompact(map[string]any{"bad": make(chan int)}, "t", false); err == nil {
		t.Error("unmarshalable claims: expected an error")
	}

	// An EC key declared as RS256 must fail inside jws.Sign.
	privJSON, err := json.Marshal(kp.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	mismatched, err := FromJWK(privJSON, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mismatched.signCompact(map[string]any{"a": 1}, "t", false); err == nil {
		t.Error("alg/key mismatch: expected a signing error")
	}

	// A corrupt public JWK must fail when embedding the jwk header.
	bad := &SigningKeyPair{
		privateKey: kp.privateKey,
		algorithm:  "ES256",
		keyID:      kp.KeyID(),
		publicJWK:  map[string]any{"bad": make(chan int)},
	}
	if _, err := bad.signCompact(map[string]any{"a": 1}, "t", true); err == nil {
		t.Error("corrupt embedded jwk: expected an error")
	}
}

func TestPublicJWKObjectErrors(t *testing.T) {
	if _, err := publicJWKObject(map[string]any{"bad": make(chan int)}); err == nil {
		t.Error("unmarshalable map: expected an error")
	}
	if _, err := publicJWKObject(map[string]any{"foo": "bar"}); err == nil {
		t.Error("non-JWK object: expected a parse error")
	}
}
