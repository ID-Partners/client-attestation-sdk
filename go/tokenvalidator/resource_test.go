package tokenvalidator

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resourceFixture(t *testing.T) *ProtectedResource {
	t.Helper()
	v := loadVectors(t)
	validator, err := New(&Config{
		Issuer: v.Issuer, Audiences: []string{v.Audience}, JWKS: v.JWKS,
		RequiredScopes: v.RequiredScopes, AcceptedAlgorithms: v.AcceptedAlgorithms,
	})
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	pr, err := NewProtectedResource(v.Audience, []string{v.Issuer}, validator, []string{"read", "write"})
	if err != nil {
		t.Fatalf("new protected resource: %v", err)
	}
	return pr
}

func TestBearerToken(t *testing.T) {
	// validation/bearer.json is shared: the Java, Python and TypeScript tests read the same cases.
	raw, err := os.ReadFile(filepath.Join("..", "..", "validation", "bearer.json"))
	if err != nil {
		t.Fatalf("read bearer cases: %v", err)
	}
	var file struct {
		Cases []struct {
			Header string  `json:"header"`
			Token  *string `json:"token"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse bearer cases: %v", err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no bearer cases")
	}
	for _, c := range file.Cases {
		want := ""
		if c.Token != nil {
			want = *c.Token
		}
		if got := BearerToken(c.Header); got != want {
			t.Errorf("BearerToken(%q) = %q, want %q", c.Header, got, want)
		}
	}
}

func TestResourceMetadata(t *testing.T) {
	pr := resourceFixture(t)
	md := pr.Metadata()
	if md.Resource != "https://api.example.com" {
		t.Errorf("resource = %q", md.Resource)
	}
	if len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != "https://issuer.example.com" {
		t.Errorf("authorization_servers = %v", md.AuthorizationServers)
	}
	if len(md.BearerMethodsSupported) != 1 || md.BearerMethodsSupported[0] != "header" {
		t.Errorf("bearer_methods_supported = %v", md.BearerMethodsSupported)
	}
	if pr.MetadataPath() != "/.well-known/oauth-protected-resource" {
		t.Errorf("MetadataPath = %q", pr.MetadataPath())
	}
	if pr.MetadataURL() != "https://api.example.com/.well-known/oauth-protected-resource" {
		t.Errorf("MetadataURL = %q", pr.MetadataURL())
	}
	b, _ := json.Marshal(md)
	if !strings.Contains(string(b), `"bearer_methods_supported":["header"]`) {
		t.Errorf("metadata JSON = %s", b)
	}
}

func TestMetadataPathWithResourcePath(t *testing.T) {
	v := loadVectors(t)
	validator, _ := New(&Config{Issuer: v.Issuer, Audiences: []string{"https://mcp.example.com/mcp"}, JWKS: v.JWKS})
	pr, err := NewProtectedResource("https://mcp.example.com/mcp", []string{v.Issuer}, validator, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pr.MetadataPath() != "/.well-known/oauth-protected-resource/mcp" {
		t.Errorf("MetadataPath = %q", pr.MetadataPath())
	}
}

func TestProtectedResourceRefusesAValidatorForAnotherAudience(t *testing.T) {
	v := loadVectors(t)
	validator, err := New(&Config{Issuer: v.Issuer, Audiences: []string{v.Audience}, JWKS: v.JWKS})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProtectedResource("https://other.example.com", []string{v.Issuer}, validator, nil); err == nil {
		t.Error("expected an error for a resource the validator does not accept")
	}
}

func TestAuthenticateValid(t *testing.T) {
	v := loadVectors(t)
	d := resourceFixture(t).Authenticate("Bearer "+tokenNamed(v, "valid"), nil)
	if !d.Authorized || d.Status != 200 {
		t.Fatalf("valid: authorized=%v status=%d", d.Authorized, d.Status)
	}
	if d.Result.Subject != "agent-1" {
		t.Errorf("subject = %q", d.Result.Subject)
	}
}

func TestAuthenticateMissingToken(t *testing.T) {
	d := resourceFixture(t).Authenticate("", nil)
	if d.Authorized || d.Status != 401 {
		t.Fatalf("missing: authorized=%v status=%d", d.Authorized, d.Status)
	}
	if !strings.Contains(d.WWWAuthenticate, `resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"`) {
		t.Errorf("WWW-Authenticate = %q", d.WWWAuthenticate)
	}
}

func TestAuthenticateExpired(t *testing.T) {
	v := loadVectors(t)
	d := resourceFixture(t).Authenticate("Bearer "+tokenNamed(v, "expired"), nil)
	if d.Status != 401 || d.Error != "invalid_token" {
		t.Errorf("expired: status=%d error=%q", d.Status, d.Error)
	}
}

func TestAuthenticateWrongAudience(t *testing.T) {
	v := loadVectors(t)
	d := resourceFixture(t).Authenticate("Bearer "+tokenNamed(v, "wrong_audience"), nil)
	if d.Status != 401 || d.Result.Error != ErrInvalidAudience {
		t.Errorf("wrong audience: status=%d error=%q", d.Status, d.Result.Error)
	}
}

func TestAuthenticateInsufficientScope(t *testing.T) {
	v := loadVectors(t)
	d := resourceFixture(t).Authenticate("Bearer "+tokenNamed(v, "valid"), []string{"read", "admin"})
	if d.Status != 403 || d.Error != "insufficient_scope" {
		t.Errorf("scope: status=%d error=%q", d.Status, d.Error)
	}
	if !strings.Contains(d.WWWAuthenticate, `error="insufficient_scope"`) {
		t.Errorf("WWW-Authenticate = %q", d.WWWAuthenticate)
	}
}

func TestResourceChecksItsOwnAudienceWithASharedValidator(t *testing.T) {
	v := loadVectors(t)
	other := "https://other.example.com"
	validator, err := New(&Config{Issuer: v.Issuer, Audiences: []string{v.Audience, other}, JWKS: v.JWKS})
	if err != nil {
		t.Fatal(err)
	}
	token := tokenNamed(v, "valid")
	if !validator.Validate(token, nil).Valid {
		t.Fatal("shared validator must accept the token")
	}
	pr, err := NewProtectedResource(other, []string{v.Issuer}, validator, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := pr.Authenticate("Bearer "+token, nil)
	if d.Authorized || d.Status != 401 || d.Result.Error != ErrInvalidAudience || d.Error != "invalid_token" {
		t.Fatalf("wrong resource: %+v", d)
	}
	pr, err = NewProtectedResource(v.Audience, []string{v.Issuer}, validator, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !pr.Authenticate("Bearer "+token, nil).Authorized {
		t.Fatal("intended resource must accept the token")
	}
}

func TestBearerGuardRefusesConfirmationWithoutProof(t *testing.T) {
	for _, cnf := range []any{map[string]any{"jkt": "bound-key"}, map[string]any{"x5t#S256": "certificate"}, map[string]any{}, "malformed"} {
		key, jwks := newTestKey(t, "key")
		validator, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks})
		if err != nil {
			t.Fatal(err)
		}
		resource, err := NewProtectedResource(testAudience, []string{testIssuer}, validator, nil)
		if err != nil {
			t.Fatal(err)
		}
		claims := map[string]any{"exp": time.Now().Unix() + 300, "cnf": cnf}
		token := signClaims(t, key, claims)
		if !validator.Validate(token, nil).Valid {
			t.Fatal("JWT validation remains available to proof-verifying callers")
		}
		d := resource.Authenticate("Bearer "+token, nil)
		if d.Authorized || d.Status != 401 || d.Result.Error != ErrInvalidToken || d.Error != "invalid_token" {
			t.Fatalf("confirmation accepted without proof: %+v", d)
		}
		claims["cnf"] = nil
		if !resource.Authenticate("Bearer "+signClaims(t, key, claims), nil).Authorized {
			t.Fatal("null confirmation must remain a Bearer token")
		}
	}
}

func TestAuthenticateActiveBindsThisResourceAndRefusesConfirmation(t *testing.T) {
	guard := func(response map[string]any) *ProtectedResource {
		_, jwks := newTestKey(t, "key")
		post := func(string, string, map[string]string) (map[string]any, error) {
			if response == nil {
				return nil, errors.New("introspection: HTTP 503")
			}
			return response, nil
		}
		validator, err := New(&Config{
			Issuer: testIssuer, Audiences: []string{testAudience, "https://other.test"}, JWKS: jwks,
			Introspection: &IntrospectionConfig{Endpoint: testIssuer + "/introspect", ClientID: "rs", ClientSecret: "secret"},
		}, WithHTTPPost(post))
		if err != nil {
			t.Fatal(err)
		}
		resource, err := NewProtectedResource(testAudience, []string{testIssuer}, validator, nil)
		if err != nil {
			t.Fatal(err)
		}
		return resource
	}
	active := func(extra map[string]any) map[string]any {
		m := map[string]any{"active": true, "sub": "agent-1", "aud": testAudience}
		for k, v := range extra {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}
	if d, err := guard(active(nil)).AuthenticateActive("Bearer opaque", nil); err != nil || !d.Authorized {
		t.Fatalf("active token for this resource refused: %+v %v", d, err)
	}
	for _, tc := range []struct {
		response map[string]any
		want     string
	}{
		{active(map[string]any{"aud": "https://other.test"}), ErrInvalidAudience},
		{active(map[string]any{"aud": nil}), ErrInvalidAudience},
		{active(map[string]any{"cnf": map[string]any{"jkt": "bound-key"}}), ErrInvalidToken},
		{map[string]any{"active": false}, ErrInactive},
	} {
		d, err := guard(tc.response).AuthenticateActive("Bearer opaque", nil)
		if err != nil || d.Authorized || d.Status != 401 || d.Result.Error != tc.want {
			t.Fatalf("%v: got %+v %v, want 401 %s", tc.response, d, err, tc.want)
		}
	}
	if d, err := guard(active(nil)).AuthenticateActive("", nil); err != nil || d.Status != 401 {
		t.Fatalf("missing header: %+v %v", d, err)
	}
	if _, err := guard(nil).AuthenticateActive("Bearer opaque", nil); err == nil {
		t.Fatal("a failed introspection call must be an error, not a verdict")
	}
}
