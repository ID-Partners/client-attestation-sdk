package clientattestation

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// configurableAttester serves a discovery document built by doc (given the server URL) and a challenge
// endpoint answered by challenge; mint and token endpoints always succeed.
func configurableAttester(t *testing.T, doc func(base string) map[string]any, challenge http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/client-attester", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, doc(srv.URL))
	})
	if challenge != nil {
		mux.HandleFunc("/challenge", challenge)
	}
	mux.HandleFunc("/mint", func(w http.ResponseWriter, r *http.Request) {
		sub := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"demo-client"}`))
		writeJSON(w, 200, map[string]any{"attestation": "h." + sub + ".sig"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"access_token": "AT", "expires_in": 60})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func standardDoc(base string) map[string]any {
	return map[string]any{
		"attestation_endpoint": base + "/mint",
		"challenge_endpoint":   base + "/challenge",
		"token_endpoint":       base + "/token",
		"evidence_audience":    shortAudience,
	}
}

func tokenFrom(t *testing.T, srv *httptest.Server, opts ...Option) error {
	t.Helper()
	ca, err := NewClientAttestation(srv.URL, append([]Option{WithEvidenceAudience(shortAudience), WithEvidence(StaticSvidSource{SVID: "s"})}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ca.Token(context.Background())
	return err
}

func TestChallengeFailureFailsClosed(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"status":  func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 503, map[string]any{"error": "down"}) },
		"json":    func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("not json")) },
		"missing": func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"other": 1}) },
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			srv := configurableAttester(t, standardDoc, handler)
			err := tokenFrom(t, srv)
			var caErr *ClientAttestationError
			if !errors.As(err, &caErr) || !strings.Contains(caErr.Message, "attestation challenge") {
				t.Fatalf("err = %v, want a challenge ClientAttestationError", err)
			}
			if err := tokenFrom(t, srv, WithRequireChallenge(false)); err != nil {
				t.Fatalf("WithRequireChallenge(false) should proceed: %v", err)
			}
		})
	}
}

func TestChallengeNetworkFailureFailsClosed(t *testing.T) {
	srv := configurableAttester(t, func(base string) map[string]any {
		d := standardDoc(base)
		d["challenge_endpoint"] = "http://127.0.0.1:1/challenge"
		return d
	}, nil)
	err := tokenFrom(t, srv)
	var caErr *ClientAttestationError
	if !errors.As(err, &caErr) || !strings.Contains(caErr.Message, "127.0.0.1:1") {
		t.Fatalf("err = %v", err)
	}
	if err := tokenFrom(t, srv, WithRequireChallenge(false)); err != nil {
		t.Fatal(err)
	}
}

func TestNoChallengeEndpointNoError(t *testing.T) {
	srv := configurableAttester(t, func(base string) map[string]any {
		d := standardDoc(base)
		delete(d, "challenge_endpoint")
		return d
	}, nil)
	if err := tokenFrom(t, srv); err != nil {
		t.Fatal(err)
	}
}

func TestMissingAttestationEndpointIsAnError(t *testing.T) {
	srv := configurableAttester(t, func(base string) map[string]any {
		d := standardDoc(base)
		delete(d, "attestation_endpoint")
		return d
	}, nil)
	if err := tokenFrom(t, srv); err == nil || !strings.Contains(err.Error(), "attestation_endpoint") {
		t.Fatalf("err = %v", err)
	}
}

func TestInsecureHostRefused(t *testing.T) {
	for _, host := range []string{"http://pf.example.com", "http://10.0.0.1:9031"} {
		_, err := NewClientAttestation(host)
		var caErr *ClientAttestationError
		if !errors.As(err, &caErr) || !strings.Contains(caErr.Message, host) {
			t.Fatalf("NewClientAttestation(%q) err = %v, want ClientAttestationError naming it", host, err)
		}
		if _, err := NewClientAttestation(host, WithAllowInsecure()); err != nil {
			t.Fatalf("WithAllowInsecure: %v", err)
		}
	}
	for _, host := range []string{"pf.example.com", "https://pf.example.com", "http://localhost:9031",
		"http://127.0.0.1", "http://[::1]:8080"} {
		if _, err := NewClientAttestation(host); err != nil {
			t.Fatalf("NewClientAttestation(%q): %v", host, err)
		}
	}
	if err := (&ClientAttestation{}).checkSecure("http://[bad"); err == nil {
		t.Fatal("unparseable URL must be refused")
	}
}

func TestInsecureDiscoveryEndpointsRefused(t *testing.T) {
	for _, field := range []string{"attestation_endpoint", "challenge_endpoint", "token_endpoint"} {
		t.Run(field, func(t *testing.T) {
			bad := "http://evil.example/" + field
			srv := configurableAttester(t, func(base string) map[string]any {
				d := standardDoc(base)
				d[field] = bad
				return d
			}, func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, 200, map[string]any{"attestation_challenge": "c"})
			})
			err := tokenFrom(t, srv)
			if err == nil || !strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), "insecure") {
				t.Fatalf("err = %v, want refusal naming %s", err, bad)
			}
			// Even with the challenge optional, an insecure endpoint is still refused.
			if err := tokenFrom(t, srv, WithRequireChallenge(false)); err == nil {
				t.Fatal("expected refusal")
			}
		})
	}
}

func TestExplicitEvidenceEnvPointingNowhereIsAnError(t *testing.T) {
	t.Setenv(EnvSVID, "")
	missing := filepath.Join(t.TempDir(), "nope")

	t.Setenv(EnvTokenFile, missing)
	_, err := AutoDetectEvidence()
	var nf *EvidenceNotFound
	if !errors.As(err, &nf) || !strings.Contains(err.Error(), EnvTokenFile) {
		t.Fatalf("err = %v, want EvidenceNotFound naming %s", err, EnvTokenFile)
	}

	t.Setenv(EnvTokenFile, "")
	origTokenFile := defaultTokenFile
	t.Cleanup(func() { defaultTokenFile = origTokenFile })
	defaultTokenFile = "/nonexistent/attester-token"
	t.Setenv(EnvSpiffeSocket, "unix://"+missing)
	_, err = AutoDetectEvidence()
	if !errors.As(err, &nf) || !strings.Contains(err.Error(), EnvSpiffeSocket) {
		t.Fatalf("err = %v, want EvidenceNotFound naming %s", err, EnvSpiffeSocket)
	}

	// A socket that does exist is used as given.
	sock := filepath.Join(t.TempDir(), "sock")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvSpiffeSocket, sock)
	source, err := AutoDetectEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := source.(SpireWorkloadAPISvidSource); !ok || s.SocketPath != sock {
		t.Fatalf("source = %#v", source)
	}
}
