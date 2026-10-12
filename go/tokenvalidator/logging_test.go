package tokenvalidator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

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

func debugLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func logEvents(t *testing.T, buf *syncBuffer) []map[string]any {
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

func eventsNamed(evs []map[string]any, name string) []map[string]any {
	var out []map[string]any
	for _, e := range evs {
		if e["msg"] == name {
			out = append(out, e)
		}
	}
	return out
}

func assertNoSecrets(t *testing.T, buf *syncBuffer) {
	t.Helper()
	for _, bad := range []string{"eyJ", "SECRET", `"d":`} {
		if strings.Contains(buf.String(), bad) {
			t.Errorf("log output contains %q:\n%s", bad, buf.String())
		}
	}
}

func TestLoggingValidatorNeverLogsTokens(t *testing.T) {
	v := loadVectors(t)
	jwksHits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(v.JWKS)
	}))
	defer srv.Close()

	logger, buf := debugLogger()
	val, err := New(&Config{
		Issuer: v.Issuer, Audiences: []string{v.Audience}, JWKSURI: srv.URL + "/jwks?SECRET=1",
		RequiredScopes: v.RequiredScopes, AcceptedAlgorithms: v.AcceptedAlgorithms,
		Introspection: &IntrospectionConfig{Endpoint: "https://as.example/introspect?SECRET=1",
			ClientID: "rs", ClientSecret: "SECRET-client-secret"},
	}, WithLogger(logger), WithHTTPPost(func(string, string, map[string]string) (map[string]any, error) {
		return map[string]any{"active": true, "scope": strings.Join(v.RequiredScopes, " "), "aud": v.Audience}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	var shared []vectorCase
	for _, c := range v.Cases {
		if c.shared() {
			shared = append(shared, c)
			val.Validate(c.Token, nil)
		}
	}
	// An unknown kid inside the cooldown is throttled, not fetched.
	val.Validate(tokenNamed(v, "valid"), nil) // cached key: no fetch, no event
	val.jwks.refresh("unknown-kid", "ES256", false)
	if _, err := val.ValidateActive(tokenNamed(v, "valid"), nil); err != nil {
		t.Fatal(err)
	}

	evs := logEvents(t, buf)
	verdicts := eventsNamed(evs, "token.validated")
	if len(verdicts) != len(shared)+2 {
		t.Fatalf("got %d verdicts, want %d:\n%s", len(verdicts), len(shared)+2, buf.String())
	}
	for i, c := range shared {
		want := c.Expect
		e := verdicts[i]
		wantLevel := "INFO"
		if want == "valid" {
			wantLevel = "DEBUG"
		}
		if e["result"] != want || e["mode"] != "jwt" || e["level"] != wantLevel {
			t.Errorf("%s: verdict %v", c.Name, e)
		}
	}
	if last := verdicts[len(verdicts)-1]; last["mode"] != "introspection" || last["result"] != "valid" {
		t.Errorf("introspection verdict %v", last)
	}
	fetched := eventsNamed(evs, "jwks.fetched")
	if len(fetched) != 1 || fetched[0]["keys"] != float64(1) || fetched[0]["host"] != strings.TrimPrefix(srv.URL, "http://") {
		t.Errorf("jwks.fetched = %v", fetched)
	}
	if len(eventsNamed(evs, "jwks.refetch_throttled")) == 0 {
		t.Errorf("no jwks.refetch_throttled:\n%s", buf.String())
	}
	assertNoSecrets(t, buf)
}

func TestLoggingJWKSFetchFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		get    HTTPGetFunc
		reason string
		status float64
	}{
		{"status", func(string) ([]byte, error) { return nil, &statusError{what: "GET x", status: 503} }, "status", 503},
		{"malformed", func(string) ([]byte, error) { return []byte("not json"), nil }, "malformed", 0},
		{"too_large", func(string) ([]byte, error) { return make([]byte, MaxJWKSBytes+1), nil }, "too_large", 0},
		{"network", func(string) ([]byte, error) { return nil, errors.New("connection refused") }, "network", 0},
		{"redirect", func(string) ([]byte, error) { return nil, errors.New("jwks: redirects are not followed") }, "redirect", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := debugLogger()
			p, _ := uriProvider(t, tc.get)
			p.logger = logger
			p.resolve("k", "")
			e := eventsNamed(logEvents(t, buf), "jwks.fetch_failed")
			if len(e) != 1 || e[0]["reason"] != tc.reason || e[0]["level"] != "WARN" || e[0]["host"] != "as.test" {
				t.Fatalf("jwks.fetch_failed = %v", e)
			}
			if got, _ := e[0]["status"].(float64); got != tc.status {
				t.Fatalf("status = %v, want %v", e[0]["status"], tc.status)
			}
		})
	}
}

func TestLoggingIntrospectionFailure(t *testing.T) {
	v := loadVectors(t)
	logger, buf := debugLogger()
	val, err := New(&Config{
		Issuer: v.Issuer, Audiences: []string{v.Audience}, JWKS: v.JWKS,
		Introspection: &IntrospectionConfig{Endpoint: "https://as.example/introspect?SECRET=1", ClientID: "rs", ClientSecret: "SECRET"},
	}, WithLogger(logger), WithHTTPPost(func(string, string, map[string]string) (map[string]any, error) {
		return nil, &statusError{what: "introspection", status: 401}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := val.ValidateActive(tokenNamed(v, "valid"), nil); err == nil {
		t.Fatal("expected an error")
	}
	evs := logEvents(t, buf)
	e := eventsNamed(evs, "http.failed")
	if len(e) != 1 || e[0]["step"] != "introspection" || e[0]["status"] != float64(401) || e[0]["reason"] != "status" ||
		e[0]["host"] != "as.example" || e[0]["path"] != "/introspect" || e[0]["method"] != "POST" {
		t.Fatalf("http.failed = %v", e)
	}
	// a failed call is an error, not a verdict, so no token.validated is logged (as in every port)
	if verdict := eventsNamed(evs, "token.validated"); len(verdict) != 0 {
		t.Fatalf("verdict = %v", verdict)
	}
	assertNoSecrets(t, buf)
}

// The default introspection POST classifies an oversized body as too_large and a body that isn't a strict
// JSON object as malformed, as the JWKS fetch does, and keeps the error messages.
func TestLoggingIntrospectionFailureReasons(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write(make([]byte, MaxIntrospectionBytes+1))
		case "/text":
			_, _ = w.Write([]byte("not json"))
		case "/array":
			_, _ = w.Write([]byte(`[true]`))
		case "/dup":
			_, _ = w.Write([]byte(`{"active": true, "active": false}`))
		case "/status":
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	v := loadVectors(t)
	viaServer := func(path string) HTTPPostFunc {
		return func(_, body string, headers map[string]string) (map[string]any, error) {
			return defaultHTTPPost(srv.URL+path, body, headers)
		}
	}
	hook := func(data map[string]any, err error) HTTPPostFunc {
		return func(string, string, map[string]string) (map[string]any, error) { return data, err }
	}
	for _, tc := range []struct {
		name, reason, message string
		status                float64
		post                  HTTPPostFunc
	}{
		{"too_large", "too_large", "larger than", 0, viaServer("/big")},
		{"not_json", "malformed", "is not JSON", 0, viaServer("/text")},
		{"not_object", "malformed", "is not a JSON object", 0, viaServer("/array")},
		{"duplicate_member", "malformed", "not a strict JSON object", 0, viaServer("/dup")},
		{"status", "status", "status 503", 503, viaServer("/status")},
		{"hook_nil_object", "malformed", "not a JSON object", 0, hook(nil, nil)},
		{"hook_timeout", "timeout", "i/o timeout", 0, hook(nil, timeoutErr{})},
		{"hook_deadline", "timeout", "deadline", 0, hook(nil, context.DeadlineExceeded)},
		{"hook_network", "network", "connection refused", 0, hook(nil, errors.New("connection refused"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := debugLogger()
			val, err := New(&Config{
				Issuer: v.Issuer, Audiences: []string{v.Audience}, JWKS: v.JWKS,
				Introspection: &IntrospectionConfig{Endpoint: "https://as.example/introspect", ClientID: "rs", ClientSecret: "SECRET"},
			}, WithLogger(logger), WithHTTPPost(tc.post))
			if err != nil {
				t.Fatal(err)
			}
			_, err = val.ValidateActive(tokenNamed(v, "valid"), nil)
			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.message)
			}
			e := eventsNamed(logEvents(t, buf), "http.failed")
			if len(e) != 1 || e[0]["step"] != "introspection" || e[0]["reason"] != tc.reason || e[0]["level"] != "WARN" {
				t.Fatalf("http.failed = %v, want reason %s", e, tc.reason)
			}
			if got, _ := e[0]["status"].(float64); got != tc.status {
				t.Fatalf("status = %v, want %v", e[0]["status"], tc.status)
			}
			assertNoSecrets(t, buf)
		})
	}
}

func TestFailureReasonClassifies(t *testing.T) {
	var syntaxErr error
	var x any
	syntaxErr = json.Unmarshal([]byte("{"), &x)
	cases := map[string]error{
		"malformed": syntaxErr,
		"too_large": &tooLargeError{msg: "big"},
		"timeout":   timeoutErr{},
	}
	for want, err := range cases {
		if got, _ := failureReason(err); got != want {
			t.Errorf("%v: got %s, want %s", err, got, want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestDefaultHTTPGetTypedErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = w.Write(make([]byte, MaxJWKSBytes+1))
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()
	if _, err := defaultHTTPGet(srv.URL + "/fail"); err == nil {
		t.Fatal("want error")
	} else if reason, status := failureReason(err); reason != "status" || status != 500 || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("got %s %d %v", reason, status, err)
	}
	if _, err := defaultHTTPGet(srv.URL + "/big"); err == nil {
		t.Fatal("want error")
	} else if reason, _ := failureReason(err); reason != "too_large" {
		t.Fatalf("got %s", reason)
	}
}

func TestValidatorLoggingIsSilentByDefault(t *testing.T) {
	var buf syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)
	v := loadVectors(t)
	val := newValidator(t, v)
	val.Validate(tokenNamed(v, "valid"), nil)
	val.Validate(tokenNamed(v, "expired"), nil)
	if buf.String() != "" {
		t.Fatalf("default logger wrote: %s", buf.String())
	}
}
