package clientattestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capturedHeaders records the proof-of-possession headers the fake token endpoint last saw, so tests
// can inspect what mode the client actually sent.
type capturedHeaders struct {
	pop  string
	dpop string
}

// fakeAttester mirrors what the real attester does: discovery, a challenge (fixed at "chal-123"), a
// mint that echoes an attestation with sub=demo-client, and a token endpoint that requires the
// attestation header plus at least one proof-of-possession header (PoP or DPoP).
func fakeAttester(t *testing.T) (*httptest.Server, *capturedHeaders) {
	t.Helper()
	captured := &capturedHeaders{}
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/client-attester", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"attestation_endpoint": srv.URL + "/federation/attestation",
			"challenge_endpoint":   srv.URL + "/federation/attestation-challenge",
			"token_endpoint":       srv.URL + "/as/token.oauth2",
			"evidence_audience":    "https://attester.example.com",
			"pop_audience":         "https://pf.issuer.example",
		})
	})

	mux.HandleFunc("/federation/attestation-challenge", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"attestation_challenge": "chal-123", "expires_in": 300})
	})

	mux.HandleFunc("/federation/attestation", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("mint body not JSON: %v", err)
		}
		for _, key := range []string{"instance_key", "svid", "proof"} {
			if _, ok := body[key]; !ok {
				t.Errorf("mint body missing %q", key)
			}
		}
		if _, ok := body["client_id"]; ok {
			t.Error("mint body must not carry client_id (evidence-first)")
		}
		sub := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"demo-client"}`))
		writeJSON(w, 200, map[string]any{"attestation": "h." + sub + ".sig", "expires_in": 300})
	})

	mux.HandleFunc("/as/token.oauth2", func(w http.ResponseWriter, r *http.Request) {
		pop := r.Header.Get(PopHeader)
		dpop := r.Header.Get(DpopHeader)
		if r.Header.Get(AttestationHeader) == "" || (pop == "" && dpop == "") {
			writeJSON(w, 401, map[string]any{"error": "invalid_client"})
			return
		}
		captured.pop = pop
		captured.dpop = dpop
		raw, _ := io.ReadAll(r.Body)
		form := string(raw)
		if !strings.Contains(form, "grant_type=client_credentials") {
			t.Errorf("token form missing grant_type=client_credentials: %q", form)
		}
		if strings.Contains(form, "client_secret") || strings.Contains(form, "client_id") {
			t.Errorf("token form must not carry client_secret/client_id: %q", form)
		}
		writeJSON(w, 200, map[string]any{"access_token": "AT-xyz", "expires_in": 3600, "token_type": "Bearer"})
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, captured
}

// decodeJWTClaims decodes a compact JWT's payload without verifying its signature — good enough for
// tests that only need to inspect claims sent over the wire.
func decodeJWTClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		t.Fatalf("not a valid compact JWT: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("invalid base64url payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("invalid JSON payload: %v", err)
	}
	return claims
}

func writeJSON(w http.ResponseWriter, code int, obj any) {
	body, _ := json.Marshal(obj)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func TestFullFlowReturnsAndCachesAToken(t *testing.T) {
	srv, _ := fakeAttester(t)
	ca, err := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: "fake-svid"}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	token, err := ca.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if token != "AT-xyz" {
		t.Fatalf("token = %q, want AT-xyz", token)
	}

	header, err := ca.AuthorizationHeader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if header != "Bearer AT-xyz" {
		t.Fatalf("authorization header = %q, want Bearer AT-xyz", header)
	}

	// Cached: a second call returns the same token without re-minting.
	if again, _ := ca.Token(ctx); again != "AT-xyz" {
		t.Fatalf("cached token = %q, want AT-xyz", again)
	}
}

// TestDefaultModePopJWTCarriesChallenge covers the dropped-challenge bug: the PoP JWT sent at the
// token endpoint must carry the "challenge" the fake attester's challenge endpoint issued
// (fixed at "chal-123"), not just the mint-time instance-key proof.
func TestDefaultModePopJWTCarriesChallenge(t *testing.T) {
	srv, captured := fakeAttester(t)
	ca, err := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: "fake-svid"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if captured.pop == "" {
		t.Fatal("expected a PoP header to have been sent")
	}
	if captured.dpop != "" {
		t.Fatal("default mode must not send a DPoP header")
	}
	claims := decodeJWTClaims(t, captured.pop)
	if claims["challenge"] != "chal-123" {
		t.Fatalf("pop challenge = %v, want chal-123 (the fixture's fake challenge)", claims["challenge"])
	}
}

// TestDpopCombinedModeSendsDpopHeaderWithChallengeNonce covers the new dpop_combined PoP method:
// selecting it via WithPopMethod must route the proof under the DPoP header (not PoP), carrying the
// challenge as DPoP's "nonce".
func TestDpopCombinedModeSendsDpopHeaderWithChallengeNonce(t *testing.T) {
	srv, captured := fakeAttester(t)
	ca, err := NewClientAttestation(srv.URL,
		WithEvidence(StaticSvidSource{SVID: "fake-svid"}),
		WithPopMethod(PopMethodDpopCombined),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if captured.dpop == "" {
		t.Fatal("expected a DPoP header to have been sent")
	}
	if captured.pop != "" {
		t.Fatal("dpop_combined mode must not send the PoP header")
	}
	claims := decodeJWTClaims(t, captured.dpop)
	if claims["nonce"] != "chal-123" {
		t.Fatalf("dpop nonce = %v, want chal-123 (the fixture's fake challenge)", claims["nonce"])
	}
}

func TestRoundTripperAttachesBearer(t *testing.T) {
	srv, _ := fakeAttester(t)
	ca, err := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: "fake-svid"}))
	if err != nil {
		t.Fatal(err)
	}

	var gotAuth string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	t.Cleanup(api.Close)

	client := &http.Client{Transport: ca.RoundTripper()}
	resp, err := client.Get(api.URL + "/thing")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer AT-xyz" {
		t.Fatalf("outbound Authorization = %q, want Bearer AT-xyz", gotAuth)
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"pf.example.com", "https://pf.example.com"},
		{"https://pf.example.com/", "https://pf.example.com"},
		{"http://pf.pf:9080", "http://pf.pf:9080"},
	}
	for _, tc := range cases {
		got, err := normalizeBaseURL(tc.in)
		if err != nil {
			t.Fatalf("normalizeBaseURL(%q) errored: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeBaseURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if _, err := normalizeBaseURL("   "); err == nil {
		t.Fatal("normalizeBaseURL(blank) should error")
	}
}

func TestJwtSubReadsTheClientID(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"demo-client"}`))
	sub, err := jwtSub("h." + payload + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	if sub != "demo-client" {
		t.Fatalf("jwtSub = %q, want demo-client", sub)
	}
}

func TestAutoDetectPrecedence(t *testing.T) {
	// Explicit env token wins over everything.
	t.Setenv(EnvSVID, "the-token")
	source, err := AutoDetectEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := source.(StaticSvidSource); !ok {
		t.Fatalf("source = %T, want StaticSvidSource", source)
	}
	if got, _ := source.Fetch("aud"); got != "the-token" {
		t.Fatalf("fetch = %q, want the-token", got)
	}

	// Next: a token file.
	t.Setenv(EnvSVID, "")
	tokenFile := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvTokenFile, tokenFile)
	source, err = AutoDetectEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := source.Fetch("aud"); got != "file-token" {
		t.Fatalf("fetch = %q, want file-token", got)
	}
}

func TestAutoDetectRaisesWhenNothingFound(t *testing.T) {
	t.Setenv(EnvSVID, "")
	t.Setenv(EnvTokenFile, "")
	t.Setenv(EnvSpiffeSocket, "")

	origTokenFile, origSocket, origProbe := defaultTokenFile, defaultSpiffeSocket, gcpMetadataProbe
	t.Cleanup(func() {
		defaultTokenFile, defaultSpiffeSocket, gcpMetadataProbe = origTokenFile, origSocket, origProbe
	})
	defaultTokenFile = "/nonexistent/attester-token"
	defaultSpiffeSocket = "/nonexistent/spire.sock"
	gcpMetadataProbe = func() bool { return false }

	_, err := AutoDetectEvidence()
	if err == nil {
		t.Fatal("expected EvidenceNotFound")
	}
	if _, ok := err.(*EvidenceNotFound); !ok {
		t.Fatalf("err = %T, want *EvidenceNotFound", err)
	}
}
