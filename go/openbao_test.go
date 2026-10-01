package clientattestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

const fakeKeyName = "attestation-es256"

// newFakeBao starts an in-process fake of the OpenBao transit API, holding a real P-256 key so produced
// signatures genuinely verify.
func newFakeBao(t *testing.T, token string) (*httptest.Server, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"errors":["permission denied"]}`)
			return
		}
		if r.Method == http.MethodGet {
			der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
			pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"type": "ecdsa-p256", "latest_version": 1,
				"keys": map[string]any{"1": map[string]any{"public_key": pemStr}}}})
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["marshaling_algorithm"] != "jws" {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"errors":["expected marshaling_algorithm=jws"]}`)
			return
		}
		input, _ := base64.StdEncoding.DecodeString(body["input"].(string))
		digest := sha256.Sum256(input)
		rInt, sInt, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		raw := make([]byte, 64)
		rInt.FillBytes(raw[:32])
		sInt.FillBytes(raw[32:])
		envelope := "vault:v1:" + base64.RawURLEncoding.EncodeToString(raw)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signature": envelope, "key_version": 1}})
	}))
	return srv, priv
}

func TestOpenBaoDerivesPublicJWK(t *testing.T) {
	srv, _ := newFakeBao(t, "tok")
	defer srv.Close()
	signer, err := NewOpenBaoTransitSigner(srv.URL, "tok", fakeKeyName)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	pub := signer.PublicJWK()
	if signer.Algorithm() != "ES256" {
		t.Errorf("algorithm = %q", signer.Algorithm())
	}
	if pub["kty"] != "EC" || pub["crv"] != "P-256" {
		t.Errorf("jwk = %v", pub)
	}
	if pub["kid"] != signer.KeyID() || pub["alg"] != "ES256" {
		t.Errorf("kid/alg = %v", pub)
	}
}

func TestOpenBaoSignedAttestationVerifies(t *testing.T) {
	srv, _ := newFakeBao(t, "tok")
	defer srv.Close()
	signer, err := NewOpenBaoTransitSigner(srv.URL, "tok", fakeKeyName)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatalf("generate instance: %v", err)
	}
	attestation, err := NewClientAttestationBuilderWithSigner(signer, "https://attester.example.com").
		ClientID("https://rp.example.com").
		ConfirmationKey(instance).
		ExpiresIn(300).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	pubJSON, _ := json.Marshal(signer.PublicJWK())
	pubKey, err := jwk.ParseKey(pubJSON)
	if err != nil {
		t.Fatalf("parse public jwk: %v", err)
	}
	payload, err := jws.Verify([]byte(attestation), jws.WithKey(jwa.ES256, pubKey))
	if err != nil {
		t.Fatalf("vault-signed attestation did not verify: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims["iss"] != "https://attester.example.com" || claims["sub"] != "https://rp.example.com" {
		t.Errorf("claims = %v", claims)
	}
	msg, _ := jws.Parse([]byte(attestation))
	hdr := msg.Signatures()[0].ProtectedHeaders()
	if hdr.Type() != "oauth-client-attestation+jwt" {
		t.Errorf("typ = %q", hdr.Type())
	}
	if hdr.KeyID() != signer.KeyID() {
		t.Errorf("kid = %q", hdr.KeyID())
	}
}

func TestOpenBaoWrongTokenFailsClosed(t *testing.T) {
	srv, _ := newFakeBao(t, "tok")
	defer srv.Close()
	if _, err := NewOpenBaoTransitSigner(srv.URL, "wrong-token", fakeKeyName); err == nil {
		t.Error("a wrong token must fail closed")
	}
}

func TestOpenBaoVaultDownFailsClosed(t *testing.T) {
	srv, _ := newFakeBao(t, "tok")
	signer, err := NewOpenBaoTransitSigner(srv.URL, "tok", fakeKeyName)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	srv.Close()
	// Point the signer at a port nothing listens on, so the call is refused at once rather than
	// waiting out the client's 5s timeout.
	signer.base = closedPortURL(t)
	start := time.Now()
	if _, err := signer.Sign([]byte("header.payload")); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("an unreachable vault must fail closed, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("vault-down failure took %v; it should be refused immediately", elapsed)
	}
}

// closedPortURL returns an http URL on a loopback port that was just bound and released, so a
// connection to it is refused immediately.
func closedPortURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return "http://" + addr
}
