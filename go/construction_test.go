package clientattestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// privateJWKMap is the full private JWK of a raw key, as a caller would load it from storage.
func privateJWKMap(t *testing.T, raw any) map[string]any {
	t.Helper()
	key, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAttestationRefusesPrivateOrSymmetricConfirmationJWK(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecPublic := privateJWKMap(t, &ecPriv.PublicKey)
	cases := map[string]map[string]any{
		"EC private":    privateJWKMap(t, ecPriv),
		"RSA private":   privateJWKMap(t, rsaPriv),
		"oct":           {"kty": "oct", "k": "c2VjcmV0"},
		"oct without k": {"kty": "oct"},
		"OKP":           {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
		"EC missing y":  {"kty": "EC", "crv": "P-256", "x": ecPublic["x"]},
		"EC bad curve":  {"kty": "EC", "crv": "secp256k1", "x": ecPublic["x"], "y": ecPublic["y"]},
	}
	for name, cnf := range cases {
		token, err := NewClientAttestationBuilder(attester, attesterIss).
			ClientID(testClientID).ConfirmationJWK(cnf).ExpiresIn(300).Build()
		if err == nil {
			_, claims := decodeSegments(t, token)
			t.Errorf("%s: signed an attestation with cnf %v", name, claims["cnf"])
		}
	}
}

func TestAttestationConfirmationJWKKeepsOnlyPublicMembers(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	cnf := instance.PublicJWK()
	cnf["use"] = "sig"
	cnf["x5u"] = "https://example.com/x5u"
	token, err := NewClientAttestationBuilder(attester, attesterIss).
		ClientID(testClientID).ConfirmationJWK(cnf).ExpiresIn(300).Build()
	if err != nil {
		t.Fatal(err)
	}
	_, claims := decodeSegments(t, token)
	got := claims["cnf"].(map[string]any)["jwk"].(map[string]any)
	if strings.Join(keysOf(got), ",") != "crv,kid,kty,x,y" || got["kid"] != instance.KeyID() {
		t.Errorf("cnf.jwk = %v", got)
	}
}

func TestAttestationRefusesExpiryNotAfterIssuedAt(t *testing.T) {
	attester, _ := Generate("ES256")
	instance, _ := Generate("ES256")
	builders := map[string]*ClientAttestationBuilder{
		"negative ttl": NewClientAttestationBuilder(attester, attesterIss).ExpiresIn(-100),
		"zero ttl":     NewClientAttestationBuilder(attester, attesterIss).ExpiresIn(0),
		"exp < iat":    NewClientAttestationBuilder(attester, attesterIss).IssuedAt(1700000000).ExpiresAt(1699999999),
	}
	for name, b := range builders {
		if _, err := b.ClientID(testClientID).ConfirmationKey(instance).Build(); err == nil || !strings.Contains(err.Error(), "after iat") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestFromJWKHeaderKidIsAlwaysTheThumbprint(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m := privateJWKMap(t, priv)
	m["kid"] = "label"
	key, err := FromJWK(m, "ES256")
	if err != nil {
		t.Fatal(err)
	}
	pop, err := NewPopBuilder(key).Audience("https://as.example.com").Build()
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := NewClientAttestationBuilder(key, attesterIss).ClientID(testClientID).ConfirmationKey(key).ExpiresIn(60).Build()
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{"pop": pop, "attestation": attestation} {
		if header, _ := decodeSegments(t, token); header["kid"] != key.KeyID() {
			t.Errorf("%s header kid = %v, want the thumbprint %s", name, header["kid"], key.KeyID())
		}
	}
	dpop, err := NewDpopProofBuilder(key).URI("https://as.example.com/token").Build()
	if err != nil {
		t.Fatal(err)
	}
	if header, _ := decodeSegments(t, dpop); header["kid"] != nil {
		t.Errorf("dpop header kid = %v, want none", header["kid"])
	}
}

func TestDpopJWKIsTheConfirmationJWKWithoutKid(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ec521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []struct {
		alg string
		raw any
	}{{"ES256", ec256}, {"ES384", ec384}, {"ES512", ec521}, {"RS256", rsaKey}, {"PS256", rsaKey}}
	for _, c := range cases {
		m := privateJWKMap(t, c.raw)
		m["kid"] = "caller-label"
		m["use"] = "sig"
		instance, err := FromJWK(m, c.alg)
		if err != nil {
			t.Fatalf("%s: %v", c.alg, err)
		}
		attestation, err := NewClientAttestationBuilder(attester, attesterIss).
			ClientID(testClientID).ConfirmationKey(instance).ExpiresIn(300).Build()
		if err != nil {
			t.Fatalf("%s: %v", c.alg, err)
		}
		_, claims := decodeSegments(t, attestation)
		cnfJWK := claims["cnf"].(map[string]any)["jwk"].(map[string]any)
		if cnfJWK["kid"] != instance.KeyID() {
			t.Errorf("%s: cnf.jwk kid = %v, want %s", c.alg, cnfJWK["kid"], instance.KeyID())
		}
		dpop, err := NewDpopProofBuilder(instance).Method("POST").URI("https://as.example.com/token").Build()
		if err != nil {
			t.Fatalf("%s: %v", c.alg, err)
		}
		header, _ := decodeSegments(t, dpop)
		if _, ok := header["kid"]; ok {
			t.Errorf("%s: dpop header has kid %v", c.alg, header["kid"])
		}
		dpopJWK := header["jwk"].(map[string]any)
		if _, ok := dpopJWK["kid"]; ok {
			t.Errorf("%s: dpop jwk has kid %v", c.alg, dpopJWK["kid"])
		}
		delete(cnfJWK, "kid")
		if !reflect.DeepEqual(cnfJWK, dpopJWK) {
			t.Errorf("%s: dpop jwk = %v, want cnf.jwk without kid %v", c.alg, dpopJWK, cnfJWK)
		}
	}
}

func TestFromJWKRefusesKeysTheAlgorithmCannotUse(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	swapped := privateJWKMap(t, p256)
	otherPub := privateJWKMap(t, other)
	swapped["x"], swapped["y"] = otherPub["x"], otherPub["y"]
	otherRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	swappedRSA := privateJWKMap(t, rsa2048)
	swappedRSA["n"] = privateJWKMap(t, otherRSA)["n"]
	cases := []struct {
		name string
		jwk  map[string]any
		alg  string
	}{
		{"P-384 as ES256", privateJWKMap(t, p384), "ES256"},
		{"P-256 as ES384", privateJWKMap(t, p256), "ES384"},
		{"EC as RS256", privateJWKMap(t, p256), "RS256"},
		{"RSA as ES256", privateJWKMap(t, rsa2048), "ES256"},
		{"RSA-1024 as RS256", privateJWKMap(t, rsa1024), "RS256"},
		{"RSA-1024 as PS256", privateJWKMap(t, rsa1024), "PS256"},
		{"EC x/y of another key", swapped, "ES256"},
		{"RSA n of another key", swappedRSA, "RS256"},
		{"alg none", privateJWKMap(t, p256), "none"},
		{"alg HS256", privateJWKMap(t, p256), "HS256"},
	}
	for _, c := range cases {
		if key, err := FromJWK(c.jwk, c.alg); err == nil {
			t.Errorf("%s: accepted (kid %s)", c.name, key.KeyID())
		}
	}
}

func TestFromJWKPublishesCanonicalPublicJWK(t *testing.T) {
	enc := base64.RawURLEncoding
	// An EC key whose x has a leading zero byte, written short (31 bytes).
	var priv *ecdsa.PrivateKey
	for {
		priv, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if len(priv.X.Bytes()) < 32 {
			break
		}
	}
	short := map[string]any{"kty": "EC", "crv": "P-256",
		"x": enc.EncodeToString(priv.X.Bytes()),
		"y": enc.EncodeToString(priv.Y.FillBytes(make([]byte, 32))),
		"d": enc.EncodeToString(priv.D.FillBytes(make([]byte, 32)))}
	fromShort, err := FromJWK(short, "ES256")
	if err != nil {
		t.Fatal(err)
	}
	fromFull, err := FromJWK(privateJWKMap(t, priv), "ES256")
	if err != nil {
		t.Fatal(err)
	}
	x, _ := enc.DecodeString(fromShort.PublicJWK()["x"].(string))
	if len(x) != 32 || fromShort.KeyID() != fromFull.KeyID() {
		t.Errorf("short x: published %d-byte x, kid %s, want 32 bytes and kid %s", len(x), fromShort.KeyID(), fromFull.KeyID())
	}
	// An RSA key whose n carries a leading zero byte.
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	padded := privateJWKMap(t, r)
	padded["n"] = enc.EncodeToString(append([]byte{0}, r.N.Bytes()...))
	fromPadded, err := FromJWK(padded, "RS256")
	if err != nil {
		t.Fatal(err)
	}
	fromMinimal, err := FromJWK(privateJWKMap(t, r), "RS256")
	if err != nil {
		t.Fatal(err)
	}
	if fromPadded.PublicJWK()["n"] != enc.EncodeToString(r.N.Bytes()) || fromPadded.KeyID() != fromMinimal.KeyID() {
		t.Errorf("padded n: kid %s, want %s", fromPadded.KeyID(), fromMinimal.KeyID())
	}
}

// fixedSigner is a JwsSigner returning a fixed signature under a fixed algorithm.
type fixedSigner struct {
	alg string
	sig []byte
}

func (s fixedSigner) Algorithm() string           { return s.alg }
func (s fixedSigner) KeyID() string               { return "fixed-kid" }
func (s fixedSigner) PublicJWK() map[string]any   { return map[string]any{} }
func (s fixedSigner) Sign([]byte) ([]byte, error) { return s.sig, nil }

func TestExternalSignerMustProduceARealSignature(t *testing.T) {
	instance, _ := Generate("ES256")
	cases := map[string]fixedSigner{
		"alg none, empty signature": {"none", nil},
		"alg HS256":                 {"HS256", make([]byte, 32)},
		"empty ES256 signature":     {"ES256", nil},
		"DER ES256 signature":       {"ES256", append([]byte{0x30, 0x44, 0x02, 0x20}, make([]byte, 66)...)},
		"truncated ES384 signature": {"ES384", make([]byte, 64)},
		"empty RS256 signature":     {"RS256", []byte{}},
	}
	for name, signer := range cases {
		token, err := NewClientAttestationBuilderWithSigner(signer, attesterIss).
			ClientID(testClientID).ConfirmationKey(instance).ExpiresIn(60).Build()
		if err == nil {
			t.Errorf("%s: built %s", name, token)
		}
	}
	if _, err := NewClientAttestationBuilderWithSigner(fixedSigner{"ES256", make([]byte, 64)}, attesterIss).
		ClientID(testClientID).ConfirmationKey(instance).ExpiresIn(60).Build(); err != nil {
		t.Errorf("a 64-byte ES256 signature: %v", err)
	}
}

func TestOpenBaoRefusesPublicKeyOnAnotherCurve(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	body, _ := json.Marshal(map[string]any{"data": map[string]any{
		"type": "ecdsa-p256", "latest_version": 1,
		"keys": map[string]any{"1": map[string]any{"public_key": pemStr}}}})
	srv := jsonBaoServer(string(body), `{}`)
	defer srv.Close()
	if signer, err := NewOpenBaoTransitSigner(srv.URL, "tok", "k"); err == nil {
		t.Errorf("accepted a P-384 public key for an ecdsa-p256 key: %v", signer.PublicJWK())
	}
}

func TestMintRequestSignRefusesReservedTyp(t *testing.T) {
	key, _ := Generate("ES256")
	req := &MintRequest{InstanceKey: key}
	claims := map[string]any{"aud": "https://as.example.com", "jti": "j", "iat": 1}
	for _, typ := range []string{PopTyp, DpopTyp, AttestationTyp, "application/" + PopTyp, "OAuth-Client-Attestation-PoP+JWT"} {
		if _, err := req.Sign(claims, typ); err == nil {
			t.Errorf("signed typ %q", typ)
		}
		if _, err := req.InstanceProof(typ, "https://as.example.com"); err == nil {
			t.Errorf("instance proof signed typ %q", typ)
		}
	}
	if _, err := req.Sign(claims, InstanceProofTyp); err != nil {
		t.Errorf("profile typ: %v", err)
	}
}
