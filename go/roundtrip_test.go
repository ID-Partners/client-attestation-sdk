package clientattestation

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

const (
	attesterIss   = "https://attester.example.com"
	testClientID  = "https://rp.example.com"
	testAudience  = "https://as.example.com"
	tokenEndpoint = "https://as.example.com/as/token.oauth2"
)

// publicKey returns the public jwk.Key for verification.
func publicKey(t *testing.T, k *SigningKeyPair) jwk.Key {
	t.Helper()
	b, err := json.Marshal(k.PublicJWK())
	if err != nil {
		t.Fatalf("marshal public jwk: %v", err)
	}
	key, err := jwk.ParseKey(b)
	if err != nil {
		t.Fatalf("parse public jwk: %v", err)
	}
	return key
}

// verify checks the ES256 signature with the given public key and returns the
// decoded protected header and claims.
func verify(t *testing.T, token string, pub jwk.Key) (map[string]any, map[string]any) {
	t.Helper()
	payload, err := jws.Verify([]byte(token), jws.WithKey(jwa.ES256, pub))
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	msg, err := jws.Parse([]byte(token))
	if err != nil {
		t.Fatalf("parse jws: %v", err)
	}
	hdrBytes, err := msg.Signatures()[0].ProtectedHeaders().AsMap(context.Background())
	if err != nil {
		t.Fatalf("protected headers: %v", err)
	}
	return hdrBytes, claims
}

func TestAttestationBindsInstanceKey(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := NewClientAttestationBuilder(attester, attesterIss).
		ClientID(testClientID).
		ConfirmationKey(instance).
		ExpiresIn(300).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	hdr, claims := verify(t, attestation, publicKey(t, attester))
	if hdr["typ"] != AttestationTyp {
		t.Fatalf("typ = %v, want %v", hdr["typ"], AttestationTyp)
	}
	if hdr["kid"] != attester.KeyID() {
		t.Fatalf("kid = %v, want %v", hdr["kid"], attester.KeyID())
	}
	if claims["iss"] != attesterIss {
		t.Fatalf("iss = %v, want %v", claims["iss"], attesterIss)
	}
	if claims["sub"] != testClientID {
		t.Fatalf("sub = %v, want %v", claims["sub"], testClientID)
	}
	cnf := claims["cnf"].(map[string]any)
	cnfJWK := cnf["jwk"].(map[string]any)
	if cnfJWK["x"] != instance.PublicJWK()["x"] {
		t.Fatalf("cnf.jwk.x = %v, want %v", cnfJWK["x"], instance.PublicJWK()["x"])
	}
	if cnfJWK["kid"] != instance.KeyID() {
		t.Fatalf("cnf.jwk.kid = %v, want %v", cnfJWK["kid"], instance.KeyID())
	}
	// iat/exp must be integer epoch seconds.
	assertIntegerClaim(t, claims, "iat")
	assertIntegerClaim(t, claims, "exp")
}

func TestPopCarriesAudJtiIatAndVerifiesWithInstanceKey(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	pop, err := NewPopBuilder(instance).ClientID(testClientID).Audience(testAudience).Build()
	if err != nil {
		t.Fatal(err)
	}
	hdr, claims := verify(t, pop, publicKey(t, instance))
	if hdr["typ"] != PopTyp {
		t.Fatalf("typ = %v, want %v", hdr["typ"], PopTyp)
	}
	if hdr["kid"] != instance.KeyID() {
		t.Fatalf("kid = %v, want %v", hdr["kid"], instance.KeyID())
	}
	if claims["aud"] != testAudience {
		t.Fatalf("aud = %v, want %v", claims["aud"], testAudience)
	}
	if claims["iss"] != testClientID {
		t.Fatalf("iss = %v, want %v", claims["iss"], testClientID)
	}
	if _, ok := claims["jti"]; !ok {
		t.Fatal("missing jti")
	}
	assertIntegerClaim(t, claims, "iat")
	if _, ok := claims["exp"]; ok {
		t.Fatal("PoP must not carry exp")
	}
}

func TestDpopEmbedsPublicJWKHeader(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	dpop, err := NewDpopProofBuilder(instance).Method("POST").URI(tokenEndpoint).Build()
	if err != nil {
		t.Fatal(err)
	}
	hdr, claims := verify(t, dpop, publicKey(t, instance))
	if hdr["typ"] != DpopTyp {
		t.Fatalf("typ = %v, want %v", hdr["typ"], DpopTyp)
	}
	jwkHdr, ok := hdr["jwk"]
	if !ok {
		t.Fatal("missing jwk header")
	}
	// The embedded jwk must NOT carry the private "d" and must NOT carry "kid".
	jwkMap := jwkHeaderAsMap(t, jwkHdr)
	if _, hasD := jwkMap["d"]; hasD {
		t.Fatal("dpop jwk header leaks private key (d)")
	}
	if _, hasKid := jwkMap["kid"]; hasKid {
		t.Fatal("dpop jwk header must not include kid")
	}
	if claims["htm"] != "POST" {
		t.Fatalf("htm = %v, want POST", claims["htm"])
	}
	if claims["htu"] != tokenEndpoint {
		t.Fatalf("htu = %v, want %v", claims["htu"], tokenEndpoint)
	}
	if _, ok := claims["jti"]; !ok {
		t.Fatal("missing jti")
	}
	assertIntegerClaim(t, claims, "iat")
}

func TestCredentialProducesBothHeaderSets(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := NewClientAttestationBuilder(attester, attesterIss).
		ClientID(testClientID).
		ConfirmationKey(instance).
		ExpiresIn(300).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := NewClientAttestationCredential(attestation, instance)
	if err != nil {
		t.Fatal(err)
	}
	popHeaders, err := cred.PopHeaders(testClientID, testAudience, "")
	if err != nil {
		t.Fatal(err)
	}
	dpopHeaders, err := cred.DpopHeaders("POST", tokenEndpoint, "")
	if err != nil {
		t.Fatal(err)
	}
	if popHeaders[AttestationHeader] != attestation {
		t.Fatal("pop headers: attestation mismatch")
	}
	if _, ok := popHeaders[PopHeader]; !ok {
		t.Fatal("missing PoP header")
	}
	if dpopHeaders[AttestationHeader] != attestation {
		t.Fatal("dpop headers: attestation mismatch")
	}
	if _, ok := dpopHeaders[DpopHeader]; !ok {
		t.Fatal("missing DPoP header")
	}
}

func TestFromJWKRejectsPublicOnly(t *testing.T) {
	pub := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": "R14dLtXfNw_SweH4s14G6evtKpEv1Bsr6DTbTp3jOHI",
		"y": "yiXPjLxyRju1sCq9IRkiZO-qSCOm3s1x-83lysV_m8g",
	}
	if _, err := FromJWK(pub, "ES256"); err == nil {
		t.Fatal("expected error for public-only JWK")
	}
}

// assertIntegerClaim confirms a numeric claim decoded from JSON is an integer
// epoch value (json.Unmarshal yields float64; the value must be whole).
func assertIntegerClaim(t *testing.T, claims map[string]any, name string) {
	t.Helper()
	v, ok := claims[name]
	if !ok {
		t.Fatalf("missing %s", name)
	}
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("%s is %T, want number", name, v)
	}
	if f != float64(int64(f)) {
		t.Fatalf("%s = %v, want integer epoch seconds", name, f)
	}
}

func jwkHeaderAsMap(t *testing.T, v any) map[string]any {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		return x
	case jwk.Key:
		m, err := x.AsMap(context.Background())
		if err != nil {
			t.Fatalf("jwk header AsMap: %v", err)
		}
		out := map[string]any{}
		for k, val := range m {
			out[k] = val
		}
		return out
	default:
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal jwk header: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("unmarshal jwk header: %v", err)
		}
		return m
	}
}
