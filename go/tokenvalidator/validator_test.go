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
)

type vectorFile struct {
	Issuer             string          `json:"issuer"`
	Audience           string          `json:"audience"`
	RequiredScopes     []string        `json:"required_scopes"`
	AcceptedAlgorithms []string        `json:"accepted_algorithms"`
	JWKS               json.RawMessage `json:"jwks"`
	Cases              []struct {
		Name   string `json:"name"`
		Token  string `json:"token"`
		Expect string `json:"expect"`
	} `json:"cases"`
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
	val := newValidator(t, v)
	for _, c := range v.Cases {
		r := val.Validate(c.Token, nil)
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
	r := val.ValidateActive("opaque-token", nil)
	if !r.Valid {
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
	r := val.ValidateActive("revoked", nil)
	if r.Valid || r.Error != ErrInactive {
		t.Errorf("expected inactive, got valid=%v error=%s", r.Valid, r.Error)
	}
}
