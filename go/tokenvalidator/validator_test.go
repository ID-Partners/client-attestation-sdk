package tokenvalidator

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type vectorFile struct {
	Issuer             string          `json:"issuer"`
	Audience           string          `json:"audience"`
	RequiredScopes     []string        `json:"required_scopes"`
	AcceptedAlgorithms []string        `json:"accepted_algorithms"`
	JWKS               json.RawMessage `json:"jwks"`
	Cases              []vectorCase    `json:"cases"`
}

type vectorCase struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	Expect string `json:"expect"`
	// Config overrides the shared config; a key that is present wins even when empty (null for
	// accepted_token_types turns the typ check off).
	Config map[string]json.RawMessage `json:"config"`
	Now    *int64                     `json:"now"`
}

// shared reports whether a case runs under the shared config and the real clock.
func (c vectorCase) shared() bool { return c.Config == nil && c.Now == nil }

// validatorFor is the validator a case asks for: the shared config plus its overrides and clock.
func validatorFor(t *testing.T, v vectorFile, c vectorCase) *AccessTokenValidator {
	t.Helper()
	cfg := &Config{
		Issuer: v.Issuer, Audiences: []string{v.Audience}, JWKS: v.JWKS,
		RequiredScopes: v.RequiredScopes, AcceptedAlgorithms: v.AcceptedAlgorithms,
	}
	if raw, ok := c.Config["accepted_algorithms"]; ok {
		cfg.AcceptedAlgorithms = []string{}
		if err := json.Unmarshal(raw, &cfg.AcceptedAlgorithms); err != nil {
			t.Fatal(err)
		}
	}
	if raw, ok := c.Config["accepted_token_types"]; ok {
		if string(raw) == "null" {
			cfg.DisableTokenTypeCheck = true
		} else {
			cfg.AcceptedTokenTypes = []string{}
			if err := json.Unmarshal(raw, &cfg.AcceptedTokenTypes); err != nil {
				t.Fatal(err)
			}
		}
	}
	if raw, ok := c.Config["leeway_seconds"]; ok {
		if err := json.Unmarshal(raw, &cfg.LeewaySeconds); err != nil {
			t.Fatal(err)
		}
		cfg.ZeroLeeway = cfg.LeewaySeconds == 0
	}
	var opts []Option
	if c.Now != nil {
		at := time.Unix(*c.Now, 0)
		opts = append(opts, WithClock(func() time.Time { return at }))
	}
	val, err := New(cfg, opts...)
	if err != nil {
		t.Fatalf("%s: new validator: %v", c.Name, err)
	}
	return val
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "validation", "tokens.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func newValidator(t *testing.T, v vectorFile) *AccessTokenValidator {
	t.Helper()
	val, err := New(&Config{
		Issuer: v.Issuer, Audiences: []string{v.Audience}, JWKS: v.JWKS,
		RequiredScopes: v.RequiredScopes, AcceptedAlgorithms: v.AcceptedAlgorithms,
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	return val
}

func tokenNamed(v vectorFile, name string) string {
	for _, c := range v.Cases {
		if c.Name == name {
			return c.Token
		}
	}
	return ""
}

func TestVectorsMatchExpected(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Cases {
		r := validatorFor(t, v, c).Validate(c.Token, nil)
		got := "valid"
		if !r.Valid {
			got = r.Error
		}
		if got != c.Expect {
			t.Errorf("%s: expected %s, got %s", c.Name, c.Expect, got)
		}
	}
}

func TestValidExposesSubjectAndScopes(t *testing.T) {
	v := loadVectors(t)
	r := newValidator(t, v).Validate(tokenNamed(v, "valid"), nil)
	if !r.Valid {
		t.Fatalf("expected valid, got %s", r.Error)
	}
	if r.Subject != "agent-1" {
		t.Errorf("subject = %q", r.Subject)
	}
	if !contains(r.Scopes, "read") || !contains(r.Scopes, "write") {
		t.Errorf("scopes = %v", r.Scopes)
	}
	if !contains(r.Audience, v.Audience) {
		t.Errorf("audience = %v", r.Audience)
	}
}

func TestRequiredScopeOverride(t *testing.T) {
	v := loadVectors(t)
	r := newValidator(t, v).Validate(tokenNamed(v, "valid"), []string{"read", "admin"})
	if r.Valid || r.Error != ErrInsufficientScope {
		t.Errorf("expected insufficient_scope, got valid=%v error=%s", r.Valid, r.Error)
	}
}

func TestIntrospectionActive(t *testing.T) {
	v := loadVectors(t)
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"active":true,"scope":"read write","sub":"agent-1","aud":"`+v.Audience+`"}`)
	}))
	defer srv.Close()

	val, _ := New(&Config{
		Issuer: v.Issuer, Audiences: []string{v.Audience}, JWKS: v.JWKS, RequiredScopes: []string{"read"},
		Introspection: &IntrospectionConfig{Endpoint: srv.URL, ClientID: "rs-1", ClientSecret: "s3cret"},
	})
	r, err := val.ValidateActive("opaque-token", nil)
	if err != nil || !r.Valid {
		t.Fatalf("expected valid, got %s: %s", r.Error, r.ErrorDescription)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if !strings.Contains(gotBody, "token=opaque-token") {
		t.Errorf("body = %q", gotBody)
	}
}

func TestIntrospectionInactive(t *testing.T) {
	v := loadVectors(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"active":false}`)
	}))
	defer srv.Close()

	val, _ := New(&Config{
		Issuer: v.Issuer, Audiences: []string{v.Audience}, JWKS: v.JWKS,
		Introspection: &IntrospectionConfig{Endpoint: srv.URL, ClientID: "rs-1", ClientSecret: "s3cret"},
	})
	r, err := val.ValidateActive("revoked", nil)
	if err != nil || r.Valid || r.Error != ErrInactive {
		t.Errorf("expected inactive, got valid=%v error=%s", r.Valid, r.Error)
	}
}
