package tokenvalidator

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A plain-http jwks_uri lets anyone on the path serve their own keys, and a plain-http introspection
// endpoint hands them the resource server's client secret: New refuses both unless the host is loopback
// or AllowInsecure is set.
func TestNewRefusesInsecureEndpoints(t *testing.T) {
	insecure := []string{
		"http://issuer.example.com/jwks",
		"http://127.0.0.2/jwks",
		"http://localhost.attacker.example/jwks",
		"http://localhost@attacker.example/jwks",
		"issuer.example.com/jwks",
	}
	for _, u := range insecure {
		if _, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKSURI: u}); err == nil ||
			!strings.Contains(err.Error(), "JWKSURI") {
			t.Errorf("JWKSURI %q: want a refusal, got %v", u, err)
		}
		cfg := &Config{Issuer: testIssuer, Audiences: []string{testAudience},
			Introspection: &IntrospectionConfig{Endpoint: u, ClientID: "rs", ClientSecret: "s3cret"}}
		if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "introspection") {
			t.Errorf("introspection endpoint %q: want a refusal, got %v", u, err)
		}
		cfg.JWKSURI, cfg.AllowInsecure = u, true
		if _, err := New(cfg); err != nil {
			t.Errorf("%q with AllowInsecure: %v", u, err)
		}
	}
}

func TestNewAcceptsHTTPSAndLoopback(t *testing.T) {
	for _, u := range []string{
		"https://issuer.example.com/jwks",
		"HTTPS://issuer.example.com/jwks",
		"http://localhost:8080/jwks",
		"http://LOCALHOST/jwks",
		"http://127.0.0.1:9000/jwks",
		"http://[::1]:8080/jwks",
	} {
		cfg := &Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKSURI: u,
			Introspection: &IntrospectionConfig{Endpoint: u}}
		if _, err := New(cfg); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
}

// A negative leeway would expire every token early and accept none issued "now"; it is a mistake, not a
// policy, so New refuses it.
func TestNewRefusesNegativeLeeway(t *testing.T) {
	_, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: []byte(`{"keys":[]}`),
		LeewaySeconds: -1})
	if err == nil || !strings.Contains(err.Error(), "LeewaySeconds") {
		t.Fatalf("want a refusal, got %v", err)
	}
}

// New keeps its own copy of the Config: reusing the struct for another validator, or changing it later, must
// not change what a live validator accepts.
func TestNewCopiesTheConfig(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	exp := time.Now().Unix() + 300
	sign := func(claims map[string]any) string {
		payload, _ := json.Marshal(claims)
		return signPayload(t, key, payload)
	}
	good := signClaims(t, key, map[string]any{"exp": exp, "scope": "read"})
	noIssuer := sign(map[string]any{"aud": testAudience, "exp": exp, "scope": "read"})
	otherAudience := sign(map[string]any{"iss": testIssuer, "aud": "https://other.test", "exp": exp, "scope": "read"})
	otherType := signClaimsTyp(t, key, map[string]any{"exp": exp, "scope": "read"}, "id_token+jwt")

	var posted string
	newValidator := func() (*Config, *AccessTokenValidator) {
		cfg := &Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks,
			RequiredScopes: []string{"read"}, AcceptedAlgorithms: []string{"ES256"},
			AcceptedTokenTypes: []string{"at+jwt"},
			Introspection:      &IntrospectionConfig{Endpoint: "https://as.test/introspect"}}
		val, err := New(cfg, WithHTTPPost(func(endpoint, _ string, _ map[string]string) (map[string]any, error) {
			posted = endpoint
			return map[string]any{"active": true, "scope": "read"}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		return cfg, val
	}
	for _, c := range []struct {
		name   string
		mutate func(*Config)
		token  string
		want   string
	}{
		{"Issuer", func(c *Config) { c.Issuer = "" }, noIssuer, ErrInvalidIssuer},
		{"Audiences", func(c *Config) { c.Audiences[0] = "https://other.test" }, otherAudience, ErrInvalidAudience},
		{"RequiredScopes", func(c *Config) { c.RequiredScopes[0] = "admin" }, good, ErrValid},
		{"AcceptedAlgorithms", func(c *Config) { c.AcceptedAlgorithms[0] = "PS256" }, good, ErrValid},
		{"AcceptedTokenTypes", func(c *Config) { c.AcceptedTokenTypes[0] = "id_token+jwt" }, otherType,
			ErrInvalidTokenType},
	} {
		cfg, val := newValidator()
		c.mutate(cfg)
		if r := val.Validate(c.token, nil); r.Error != c.want {
			t.Errorf("%s changed after New: want %q, got %q", c.name, c.want, r.Error)
		}
	}

	cfg, val := newValidator()
	cfg.Introspection.Endpoint = "http://attacker.example/introspect"
	if _, err := val.ValidateActive("opaque", nil); err != nil || posted != "https://as.test/introspect" {
		t.Errorf("introspection went to %q (%v)", posted, err)
	}
}
