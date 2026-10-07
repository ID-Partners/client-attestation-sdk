package clientattestation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Credentials the logging fake hands out. Every one carries a marker the leak check looks for, and the
// ones a real server would send as JWTs start with eyJ.
const (
	logSecretSvid      = "eyJsvid.SECRET-svid.sig"
	logSecretChallenge = "SECRET-challenge-value"
	logSecretToken     = "eyJhbGciOiJFUzI1NiJ9.SECRET-access-token.sig"
)

// syncBuffer is a bytes.Buffer safe for concurrent writes from a slog handler.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// debugLogger captures every event at the most verbose level as JSON lines.
func debugLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// events parses the captured JSON lines.
func events(t *testing.T, buf *syncBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		out = append(out, m)
	}
	return out
}

func findEvent(evs []map[string]any, name string) map[string]any {
	for _, e := range evs {
		if e["msg"] == name {
			return e
		}
	}
	return nil
}

func requireEvents(t *testing.T, buf *syncBuffer, names ...string) []map[string]any {
	t.Helper()
	evs := events(t, buf)
	for _, name := range names {
		if findEvent(evs, name) == nil {
			t.Errorf("no %s event in:\n%s", name, buf.String())
		}
	}
	return evs
}

// assertNoSecrets fails if the log holds anything that looks like a credential or key material.
func assertNoSecrets(t *testing.T, buf *syncBuffer) {
	t.Helper()
	out := buf.String()
	for _, bad := range []string{"eyJ", "SECRET", `"d":`, "fake-svid", "chal-123", "AT-1", "?ignored"} {
		if strings.Contains(out, bad) {
			t.Errorf("log output contains %q:\n%s", bad, out)
		}
	}
}

// loggingAttester is a fake attester + AS that hands out JWT-shaped credentials. With demandNonce it
// answers the first DPoP token request with 400 use_dpop_nonce.
func loggingAttester(t *testing.T, tokenType, demandNonce string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/client-attester", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"attestation_endpoint": srv.URL + "/federation/attestation",
			"challenge_endpoint":   srv.URL + "/federation/attestation-challenge",
			"token_endpoint":       srv.URL + "/as/token.oauth2?SECRET=1",
			"evidence_audience":    "https://attester.example.com",
		})
	})
	mux.HandleFunc("/federation/attestation-challenge", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"attestation_challenge": logSecretChallenge})
	})
	mux.HandleFunc("/federation/attestation", func(w http.ResponseWriter, r *http.Request) {
		sub := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"demo-client"}`))
		writeJSON(w, 200, map[string]any{"attestation": "eyJhbGciOiJFUzI1NiJ9." + sub + ".c2ln"})
	})
	mux.HandleFunc("/as/token.oauth2", func(w http.ResponseWriter, r *http.Request) {
		if demandNonce != "" && r.Header.Get(DpopHeader) != "" {
			proof := decodeJWTClaims(t, r.Header.Get(DpopHeader))
			if proof["nonce"] != demandNonce {
				w.Header().Set(DpopNonceHeader, demandNonce)
				writeJSON(w, 400, map[string]any{"error": "use_dpop_nonce"})
				return
			}
		}
		writeJSON(w, 200, map[string]any{"access_token": logSecretToken, "expires_in": 3600, "token_type": tokenType})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestLoggingFullFlowNeverLogsSecrets(t *testing.T) {
	for _, tc := range []struct {
		name, popMethod, tokenType, nonce string
	}{
		{"pop-jwt", PopMethodAttestationPopJWT, "Bearer", ""},
		{"dpop-with-nonce-retry", PopMethodDpopCombined, "DPoP", "SECRET-as-nonce"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := loggingAttester(t, tc.tokenType, tc.nonce)
			logger, buf := debugLogger()
			ca, err := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: logSecretSvid}),
				WithPopMethod(tc.popMethod), WithLogger(logger))
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if _, err := ca.Token(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := ca.Token(ctx); err != nil { // served from cache
				t.Fatal(err)
			}
			if _, err := ca.TokenWithOptions(ctx, WithForceRefresh()); err != nil { // discovery cached
				t.Fatal(err)
			}
			if _, err := ca.RequestHeaders(ctx, "GET", "https://api.example.com/x?SECRET=1"); err != nil {
				t.Fatal(err)
			}

			names := []string{"token.refreshing", "discovery.fetched", "discovery.cached", "evidence.obtained",
				"challenge.fetched", "attestation.minted", "token.obtained", "token.cache_hit"}
			if tc.nonce != "" {
				names = append(names, "dpop.nonce_retry")
			}
			evs := requireEvents(t, buf, names...)
			obtained := findEvent(evs, "token.obtained")
			if obtained["token_type"] != tc.tokenType || obtained["client_id"] != "demo-client" ||
				obtained["pop_method"] != tc.popMethod || obtained["expires_in"] != float64(3600) ||
				obtained["level"] != "INFO" {
				t.Errorf("token.obtained = %v", obtained)
			}
			if e := findEvent(evs, "attestation.minted"); e["alg"] != "ES256" || e["host"] != strings.TrimPrefix(srv.URL, "http://") {
				t.Errorf("attestation.minted = %v", e)
			}
			if e := findEvent(evs, "evidence.obtained"); e["source"] != "StaticSvidSource" {
				t.Errorf("evidence.obtained = %v", e)
			}
			if tc.nonce != "" {
				if e := findEvent(evs, "dpop.nonce_retry"); e["at"] != "token_endpoint" || e["status"] != float64(400) {
					t.Errorf("dpop.nonce_retry = %v", e)
				}
			}
			reasons := map[any]bool{}
			for _, e := range evs {
				if e["msg"] == "token.refreshing" {
					reasons[e["reason"]] = true
				}
			}
			if !reasons["initial"] || !reasons["forced"] {
				t.Errorf("token.refreshing reasons = %v", reasons)
			}
			assertNoSecrets(t, buf)
		})
	}
}

func TestLoggingResourceNonceRetry(t *testing.T) {
	as := newDpopAS(t, "DPoP")
	rs := newDpopResource(t, as)
	logger, buf := debugLogger()
	ca, err := NewClientAttestation(as.srv.URL, WithEvidence(StaticSvidSource{SVID: "fake-svid"}),
		WithPopMethod(PopMethodDpopCombined), WithLogger(logger))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: ca.RoundTripper()}).Get(rs.srv.URL + "/data?SECRET=1")
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	evs := requireEvents(t, buf, "dpop.nonce_retry", "token.obtained")
	if e := findEvent(evs, "dpop.nonce_retry"); e["at"] != "resource" || e["status"] != float64(401) {
		t.Errorf("dpop.nonce_retry = %v", e)
	}
	assertNoSecrets(t, buf)
}

func TestLoggingHTTPFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 503, map[string]any{"error": "down"})
		}))
		defer srv.Close()
		logger, buf := debugLogger()
		ca, _ := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: "x"}), WithLogger(logger))
		if _, err := ca.Token(ctx); err == nil {
			t.Fatal("expected an error")
		}
		e := findEvent(requireEvents(t, buf, "http.failed"), "http.failed")
		if e["step"] != "discover" || e["reason"] != "status" || e["status"] != float64(503) ||
			e["method"] != "GET" || e["path"] != wellKnownPath || e["level"] != "WARN" {
			t.Errorf("http.failed = %v", e)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		defer srv.Close()
		logger, buf := debugLogger()
		ca, _ := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: "x"}), WithLogger(logger))
		_, _ = ca.Token(ctx)
		if e := findEvent(events(t, buf), "http.failed"); e == nil || e["reason"] != "malformed" {
			t.Errorf("http.failed = %v", e)
		}
	})

	t.Run("redirect", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example/x", http.StatusFound)
		}))
		defer srv.Close()
		logger, buf := debugLogger()
		ca, _ := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: "x"}), WithLogger(logger))
		_, _ = ca.Token(ctx)
		if e := findEvent(events(t, buf), "http.failed"); e == nil || e["reason"] != "redirect" || e["status"] != float64(302) {
			t.Errorf("http.failed = %v", e)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
		defer srv.Close()
		defer close(release)
		logger, buf := debugLogger()
		ca, _ := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: "x"}), WithLogger(logger),
			WithTimeout(50*time.Millisecond))
		_, _ = ca.Token(ctx)
		if e := findEvent(events(t, buf), "http.failed"); e == nil || e["reason"] != "timeout" {
			t.Errorf("http.failed = %v", e)
		}
	})

	t.Run("token endpoint and skipped challenge", func(t *testing.T) {
		var srv *httptest.Server
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/client-attester", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{
				"attestation_endpoint": srv.URL + "/mint", "challenge_endpoint": srv.URL + "/challenge",
				"token_endpoint": srv.URL + "/token", "evidence_audience": "aud",
			})
		})
		mux.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 500, nil) })
		mux.HandleFunc("/mint", func(w http.ResponseWriter, r *http.Request) {
			sub := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"c"}`))
			writeJSON(w, 200, map[string]any{"attestation": "h." + sub + ".s"})
		})
		mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 400, map[string]any{"error": "invalid_client"})
		})
		srv = httptest.NewServer(mux)
		defer srv.Close()
		logger, buf := debugLogger()
		ca, _ := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: "x"}), WithLogger(logger),
			WithRequireChallenge(false))
		_, _ = ca.Token(ctx)
		evs := requireEvents(t, buf, "challenge.skipped")
		var tokenFailure map[string]any
		for _, e := range evs {
			if e["msg"] == "http.failed" && e["step"] == "token" {
				tokenFailure = e
			}
		}
		if tokenFailure == nil || tokenFailure["reason"] != "status" || tokenFailure["status"] != float64(400) {
			t.Errorf("token http.failed = %v\n%s", tokenFailure, buf.String())
		}
	})

	t.Run("token endpoint unreachable", func(t *testing.T) {
		var srv *httptest.Server
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/client-attester", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{
				"attestation_endpoint": srv.URL + "/mint", "token_endpoint": "http://127.0.0.1:1/token",
				"evidence_audience": "aud",
			})
		})
		mux.HandleFunc("/mint", func(w http.ResponseWriter, r *http.Request) {
			sub := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"c"}`))
			writeJSON(w, 200, map[string]any{"attestation": "h." + sub + ".s"})
		})
		srv = httptest.NewServer(mux)
		defer srv.Close()
		logger, buf := debugLogger()
		ca, _ := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: "x"}), WithLogger(logger))
		_, _ = ca.Token(ctx)
		e := findEvent(events(t, buf), "http.failed")
		if e == nil || e["step"] != "token" || e["reason"] != "network" || e["host"] != "127.0.0.1:1" {
			t.Errorf("http.failed = %v", e)
		}
	})
}

func TestTransportReasonClassifiesTooLarge(t *testing.T) {
	reason, status := transportReason(&ClientAttestationError{Message: "response from GET x exceeds 10 bytes", Status: 200})
	if reason != "too_large" || status != 200 {
		t.Fatalf("got %s %d", reason, status)
	}
	if reason, _ := transportReason(context.DeadlineExceeded); reason != "timeout" {
		t.Fatalf("got %s", reason)
	}
	if reason, _ := transportReason(errors.New("boom")); reason != "network" {
		t.Fatalf("got %s", reason)
	}
	if reason, _ := transportReason(&ClientAttestationError{Message: "other"}); reason != "network" {
		t.Fatalf("got %s", reason)
	}
}

func TestLoggingIsSilentByDefault(t *testing.T) {
	// A default token source has a discarding logger: nothing reaches slog's default handler either.
	var buf syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	srv := loggingAttester(t, "Bearer", "")
	ca, err := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: logSecretSvid}), WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "" {
		t.Fatalf("default logger wrote: %s", buf.String())
	}
}
