package clientattestation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubSigner is a minimal JwsSigner for exercising signExternal without a vault.
type stubSigner struct {
	signErr error
}

func (s stubSigner) Algorithm() string         { return "ES256" }
func (s stubSigner) KeyID() string             { return "stub-kid" }
func (s stubSigner) PublicJWK() map[string]any { return map[string]any{} }
func (s stubSigner) Sign([]byte) ([]byte, error) {
	if s.signErr != nil {
		return nil, s.signErr
	}
	return []byte("sig"), nil
}

func TestSignExternalErrors(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	// Unmarshalable claims (via the workload) must surface as a marshal error.
	_, err = NewClientAttestationBuilderWithSigner(stubSigner{}, attesterIss).
		ClientID(testClientID).
		ConfirmationKey(instance).
		ExpiresIn(300).
		Workload(map[string]any{"bad": make(chan int)}).
		Build()
	if err == nil || !strings.Contains(err.Error(), "marshal") {
		t.Errorf("unmarshalable claims: err = %v", err)
	}
	// A failing external signer must fail the build.
	_, err = NewClientAttestationBuilderWithSigner(stubSigner{signErr: errors.New("hsm down")}, attesterIss).
		ClientID(testClientID).
		ConfirmationKey(instance).
		ExpiresIn(300).
		Build()
	if err == nil || !strings.Contains(err.Error(), "hsm down") {
		t.Errorf("signer failure: err = %v", err)
	}
}

// jsonBaoServer serves fixed bodies for the transit key-read (GET) and sign (POST) endpoints.
func jsonBaoServer(getBody, postBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, getBody)
			return
		}
		io.WriteString(w, postBody)
	}))
}

func validECKeyReadBody(t *testing.T) string {
	t.Helper()
	priv, err := ecdsaGenerate("P-256")
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	body, err := json.Marshal(map[string]any{"data": map[string]any{
		"type": "ecdsa-p256", "latest_version": 1,
		"keys": map[string]any{"1": map[string]any{"public_key": pemStr}}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestOpenBaoUnsupportedKeyType(t *testing.T) {
	srv := jsonBaoServer(`{"data":{"type":"rsa-2048"}}`, `{}`)
	defer srv.Close()
	if _, err := NewOpenBaoTransitSigner(srv.URL, "tok", "k"); err == nil ||
		!strings.Contains(err.Error(), "unsupported type") {
		t.Errorf("expected an unsupported-type error, got %v", err)
	}
}

func TestOpenBaoBadPEMFailsClosed(t *testing.T) {
	srv := jsonBaoServer(`{"data":{"type":"ecdsa-p256","latest_version":1,`+
		`"keys":{"1":{"public_key":"not a pem"}}}}`, `{}`)
	defer srv.Close()
	if _, err := NewOpenBaoTransitSigner(srv.URL, "tok", "k"); err == nil ||
		!strings.Contains(err.Error(), "PEM") {
		t.Errorf("expected a PEM error, got %v", err)
	}
}

func TestOpenBaoSignResponseWithoutSignature(t *testing.T) {
	srv := jsonBaoServer(validECKeyReadBody(t), `{"data":{"key_version":1}}`)
	defer srv.Close()
	signer, err := NewOpenBaoTransitSigner(srv.URL, "tok", "k")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign([]byte("h.p")); err == nil ||
		!strings.Contains(err.Error(), "no signature") {
		t.Errorf("expected a no-signature error, got %v", err)
	}
}

func TestOpenBaoUnparseableResponse(t *testing.T) {
	srv := jsonBaoServer(`not json`, `{}`)
	defer srv.Close()
	if _, err := NewOpenBaoTransitSigner(srv.URL, "tok", "k"); err == nil ||
		!strings.Contains(err.Error(), "unparseable") {
		t.Errorf("expected an unparseable-response error, got %v", err)
	}
}

func TestOpenBaoResponseWithoutData(t *testing.T) {
	srv := jsonBaoServer(`{}`, `{}`)
	defer srv.Close()
	if _, err := NewOpenBaoTransitSigner(srv.URL, "tok", "k"); err == nil ||
		!strings.Contains(err.Error(), "no data") {
		t.Errorf("expected a no-data error, got %v", err)
	}
}

func TestOpenBaoInvalidBaseURL(t *testing.T) {
	if _, err := NewOpenBaoTransitSigner("://bad", "tok", "k"); err == nil {
		t.Error("expected an error for an invalid base URL")
	}
}

func TestOpenBaoTruncatedResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		io.WriteString(w, "short")
	}))
	defer srv.Close()
	if _, err := NewOpenBaoTransitSigner(srv.URL, "tok", "k"); err == nil {
		t.Error("expected an error for a truncated response body")
	}
}

func TestECJWKFromPEMErrors(t *testing.T) {
	if _, _, err := ecJWKFromPEM(""); err == nil {
		t.Error("empty input: expected an error")
	}
	junk := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")}))
	if _, _, err := ecJWKFromPEM(junk); err == nil ||
		!strings.Contains(err.Error(), "unparseable") {
		t.Errorf("junk DER: expected an unparseable error, got %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, _, err := ecJWKFromPEM(rsaPEM); err == nil ||
		!strings.Contains(err.Error(), "not ECDSA") {
		t.Errorf("RSA key: expected a not-ECDSA error, got %v", err)
	}
}

func TestToFloat(t *testing.T) {
	if got := toFloat(float64(2.5)); got != 2.5 {
		t.Errorf("toFloat(float64) = %v", got)
	}
	if got := toFloat(json.Number("3")); got != 3 {
		t.Errorf("toFloat(json.Number) = %v", got)
	}
	if got := toFloat("nope"); got != 0 {
		t.Errorf("toFloat(default) = %v", got)
	}
}
