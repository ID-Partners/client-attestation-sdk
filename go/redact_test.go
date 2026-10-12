package clientattestation

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// secretJWT stands in for any credential: it starts with eyJ like every JWT, and carries a marker that
// must not appear in an error, a String form or a log line.
const secretJWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.SECRET-MARKER"

// attesterWith serves discovery, a mint answered by mint and a token endpoint answered by token.
func attesterWith(t *testing.T, mint, token http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/client-attester", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"attestation_endpoint": srv.URL + "/mint", "token_endpoint": srv.URL + "/token", "evidence_audience": shortAudience})
	})
	if mint == nil {
		mint = func(w http.ResponseWriter, r *http.Request) {
			sub := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"c"}`))
			writeJSON(w, 200, map[string]any{"attestation": "h." + sub + ".s"})
		}
	}
	mux.HandleFunc("/mint", mint)
	mux.HandleFunc("/token", token)
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func rawResponse(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// assertNoSecret fails if the marker is anywhere in err's chain: its message, or the Body of any
// *ClientAttestationError or *IssuanceError in it.
func assertNoSecret(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error")
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if strings.Contains(e.Error(), "SECRET-MARKER") {
			t.Fatalf("error message carries the credential: %v", e)
		}
		var sdkErr *ClientAttestationError
		if errors.As(e, &sdkErr) && strings.Contains(sdkErr.Body, "SECRET-MARKER") {
			t.Fatalf("error Body carries the credential: %q", sdkErr.Body)
		}
		var issErr *IssuanceError
		if errors.As(e, &issErr) && strings.Contains(issErr.Body, "SECRET-MARKER") {
			t.Fatalf("error Body carries the credential: %q", issErr.Body)
		}
	}
}

func TestUnusable2xxTokenResponseKeepsNoBody(t *testing.T) {
	for name, body := range map[string]string{
		"trailing data":   `{"access_token":"` + secretJWT + `","token_type":"Bearer"} trailing`,
		"form encoded":    `access_token=` + secretJWT + `&token_type=Bearer`,
		"no access_token": `{"accessToken":"` + secretJWT + `","token_type":"Bearer"}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := attesterWith(t, nil, rawResponse(200, body))
			ca, _ := NewClientAttestation(srv.URL, WithEvidenceAudience(shortAudience), WithEvidence(StaticSvidSource{SVID: "s"}))
			_, err := ca.Token(context.Background())
			assertNoSecret(t, err)
		})
	}
}

func TestUnusable2xxMintResponseKeepsNoBody(t *testing.T) {
	for name, body := range map[string]string{
		"trailing data": `{"attestation":"` + secretJWT + `"} trailing`,
		"wrong member":  `{"client_attestation":"` + secretJWT + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := attesterWith(t, rawResponse(200, body), rawResponse(200, `{"access_token":"AT"}`))
			ca, _ := NewClientAttestation(srv.URL, WithEvidenceAudience(shortAudience), WithEvidence(StaticSvidSource{SVID: "s"}))
			_, err := ca.Token(context.Background())
			assertNoSecret(t, err)
		})
	}
}

func TestIssuanceErrorBodyIsCapped(t *testing.T) {
	long := `{"error":"denied","error_description":"` + strings.Repeat("d", 1000) + `"}`
	srv := httptest.NewServer(rawResponse(403, long))
	defer srv.Close()
	ic, _ := NewAttestationIssuanceClient(srv.URL, "c", "aud", StaticSvidSource{SVID: "s"})
	_, err := ic.Bootstrap(nil, "")
	var issErr *IssuanceError
	if !errors.As(err, &issErr) || issErr.Body != long[:maxErrorBodyBytes] {
		t.Fatalf("want a capped *IssuanceError, got %v", err)
	}
	if len(err.Error()) > len("attestation issuance failed: HTTP 403: ")+maxErrorBodyBytes {
		t.Fatalf("message not capped: %d bytes", len(err.Error()))
	}
}

func TestUnusable2xxIssuanceResponseKeepsNoBody(t *testing.T) {
	srv := httptest.NewServer(rawResponse(200, `{"attestation":"`+secretJWT+`"} trailing`))
	defer srv.Close()
	ic, _ := NewAttestationIssuanceClient(srv.URL, "c", "aud", StaticSvidSource{SVID: "s"})
	_, err := ic.Bootstrap(nil, "")
	assertNoSecret(t, err)
}

// printedForms is every way a value commonly reaches a log: fmt's verbs and slog's two handlers.
func printedForms(v any) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%v\n%+v\n%#v\n%s\n", v, v, v, v)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "v", v)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "v", v)
	return buf.String()
}

func TestDefaultStringFormsRedactCredentials(t *testing.T) {
	key, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := NewClientAttestationCredential(secretJWT, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := attesterWith(t, nil, rawResponse(200, `{"access_token":"`+secretJWT+`","token_type":"Bearer","expires_in":60}`))
	ca, _ := NewClientAttestation(srv.URL, WithEvidenceAudience(shortAudience), WithEvidence(StaticSvidSource{SVID: "s"}))
	if _, err := ca.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	ca.rememberNonce("https://rs.example", "NONCE-SECRET-MARKER")
	for name, v := range map[string]any{
		"ClientAttestation":           ca,
		"OpenBaoTransitSigner":        &OpenBaoTransitSigner{base: "https://bao", token: "VAULT-SECRET-MARKER", keyName: "k"},
		"ClientAttestationCredential": cred,
		"MintRequest":                 MintRequest{InstanceKey: key, Evidence: secretJWT, Challenge: "CHALLENGE-SECRET-MARKER", ClientID: "c"},
		"*MintRequest":                &MintRequest{InstanceKey: key, Evidence: secretJWT, Challenge: "CHALLENGE-SECRET-MARKER"},
		"MintResult":                  MintResult{Attestation: secretJWT, ExpiresIn: 60},
		"*MintResult":                 &MintResult{Attestation: secretJWT, ExpiresIn: 60},
		"IssuedAttestation":           &IssuedAttestation{Attestation: secretJWT, ExpiresIn: 60, InstanceKey: key},
		"StaticSvidSource":            StaticSvidSource{SVID: secretJWT},
	} {
		t.Run(name, func(t *testing.T) {
			if out := printedForms(v); strings.Contains(out, "SECRET-MARKER") {
				t.Fatalf("printed form carries a credential:\n%s", out)
			}
		})
	}
	if got := fmt.Sprint(MintRequest{ClientID: "c", Evidence: "abc"}); got != `MintRequest{ClientID: "c", Evidence: <redacted:3 bytes>, Challenge: ""}` {
		t.Fatalf("String() = %s", got)
	}
}
