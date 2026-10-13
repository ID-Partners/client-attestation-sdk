package tokenvalidator

// The decisions validation/SEMANTICS.md pins for every port, beyond what the shared token vectors reach:
// the shared introspection vectors, the default introspection transport's cap and strict parsing,
// injected transports that return nothing, the config's unset-versus-empty rules and the strict reader's
// edges.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntrospectionVectorsMatchExpected(t *testing.T) {
	v := loadVectors(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "validation", "introspection.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			Name           string         `json:"name"`
			Expect         string         `json:"expect"`
			Response       map[string]any `json:"response"`
			TransportError bool           `json:"transport_error"`
			NoEndpoint     bool           `json:"no_endpoint"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, c := range file.Cases {
		cfg := &Config{Issuer: v.Issuer, Audiences: []string{v.Audience}, JWKS: v.JWKS, RequiredScopes: v.RequiredScopes}
		if !c.NoEndpoint {
			cfg.Introspection = &IntrospectionConfig{Endpoint: "https://as.test/introspect", ClientID: "rs", ClientSecret: "secret"}
		}
		val, err := New(cfg, WithHTTPPost(func(string, string, map[string]string) (map[string]any, error) {
			if c.TransportError {
				return nil, &statusError{what: "introspection", status: 503}
			}
			return c.Response, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		got := "raises"
		if r, err := val.ValidateActive("opaque", nil); err == nil {
			got = r.Error
		}
		if got != c.Expect {
			t.Errorf("%s: expected %s, got %s", c.Name, c.Expect, got)
		}
	}
}

func introspectionServer(t *testing.T, status int, body string) *AccessTokenValidator {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience},
		Introspection: &IntrospectionConfig{Endpoint: srv.URL, ClientID: "rs", ClientSecret: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	return val
}

func TestDefaultIntrospectionRefusesWhatEveryPortRefuses(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"active": true, "active": false}`, "duplicate member name"},
		{`[true]`, "not a JSON object"},
		{`{"active": true,}`, "not a strict JSON object"},
		{`{"active": true} {}`, "data after the JSON object"},
		{`{"active": true, "x": "` + strings.Repeat("a", MaxIntrospectionBytes) + `"}`, "larger than"},
	} {
		_, err := introspectionServer(t, 200, tc.body).ValidateActive("t", nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%.40s: err = %v, want %q", tc.body, err, tc.want)
		}
	}
	if _, err := introspectionServer(t, 503, `{}`).ValidateActive("t", nil); err == nil {
		t.Error("a 503 must be an error, not a verdict")
	}
}

func TestDefaultIntrospectionReplacesInvalidUTF8(t *testing.T) {
	r, err := introspectionServer(t, 200, "{\"active\": true, \"sub\": \"agent-\xff\"}").ValidateActive("t", nil)
	if err != nil || !r.Valid || r.Subject != "agent-�" {
		t.Fatalf("r = %+v, err = %v", r, err)
	}
}

func TestInjectedTransportReturningNothingIsAnError(t *testing.T) {
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience},
		Introspection: &IntrospectionConfig{Endpoint: "https://as.test/introspect", ClientID: "rs", ClientSecret: "secret"}},
		WithHTTPPost(func(string, string, map[string]string) (map[string]any, error) { return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := val.ValidateActive("t", nil); err == nil || !strings.Contains(err.Error(), "not a JSON object") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnsetVersusEmptyConfig(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	token := signClaims(t, key, map[string]any{"exp": int64(1_000_000)})
	at := func(sec int64) Option { return WithClock(func() time.Time { return time.Unix(sec, 0) }) }
	check := func(cfg *Config, now int64, want string) {
		t.Helper()
		cfg.Issuer, cfg.Audiences, cfg.JWKS = testIssuer, []string{testAudience}, jwks
		val, err := New(cfg, at(now))
		if err != nil {
			t.Fatal(err)
		}
		got := val.Validate(token, nil).Error
		if got != want {
			t.Errorf("%+v at %d: got %s, want %s", cfg, now, got, want)
		}
	}
	check(&Config{}, 1_000_059, ErrValid)                   // unset leeway: the default 60
	check(&Config{ZeroLeeway: true}, 1_000_000, ErrValid)   // leeway 0: exp itself is fine
	check(&Config{ZeroLeeway: true}, 1_000_001, ErrExpired) // ... and a second later is not
	check(&Config{AcceptedAlgorithms: []string{}}, 1_000_000, ErrUnsupportedAlgorithm)
	check(&Config{AcceptedTokenTypes: []string{}}, 1_000_000, ErrValid) // no typ header: nothing to refuse
	check(&Config{AcceptedAlgorithms: []string{"ES256", "none", "HS256"}}, 1_000_000, ErrValid)

	if _, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, ZeroLeeway: true, LeewaySeconds: 5}); err == nil {
		t.Error("ZeroLeeway with a non-zero LeewaySeconds must be refused")
	}
}

func TestSignatureWithAnAlgorithmJWXLacks(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatal(err)
	}
	delete(set.Keys[0], "alg")
	noAlg, _ := json.Marshal(set)
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: noAlg,
		AcceptedAlgorithms: []string{"ES256", "XX999"}})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(signClaims(t, key, map[string]any{"exp": int64(4102444800)}), ".")
	header := b64json(t, map[string]any{"alg": "XX999", "kid": "k1"})
	if r := val.Validate(header+"."+parts[1]+"."+parts[2], nil); r.Error != ErrInvalidSignature {
		t.Errorf("got %s", r.Error)
	}
}

func b64json(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestStrictReaderEdges(t *testing.T) {
	obj, err := parseObject([]byte(`{"a": "x\"y{[", "b": [1, {"c": null}], "d": [], "e": 1e400}`), "payload")
	if err != nil {
		t.Fatal(err)
	}
	if obj["a"] != `x"y{[` || !math.IsInf(obj["e"].(float64), 1) || len(obj["d"].([]any)) != 0 {
		t.Errorf("obj = %v", obj)
	}
	for _, bad := range []string{`{"a": [1,]}`, `{"a": [{"x": 1, "x": 2}]}`, `{"a": [` + strings.Repeat("[", 70) + `]}`, `{"a": "`} {
		if _, err := parseObject([]byte(bad), "payload"); err == nil {
			t.Errorf("%.30s: expected an error", bad)
		}
	}
	if _, _, err := numericDate(map[string]any{"exp": -math.Pow(2, 53)}, "exp"); err == nil {
		t.Error("-(2^53) is out of range")
	}
	if n, ok, err := numericDate(map[string]any{"exp": -4.9}, "exp"); !ok || err != nil || n != -4 {
		t.Errorf("numericDate(-4.9) = %d, %v, %v", n, ok, err)
	}
}
