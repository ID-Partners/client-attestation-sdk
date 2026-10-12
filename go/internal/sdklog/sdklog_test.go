package sdklog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogDropsEmptyAndScrubsJWTs(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	//nolint:staticcheck // a nil ctx is tolerated on purpose
	Log(nil, l, slog.LevelDebug, "e", "empty", "", "nil", nil, "jwt", "eyJabc.def.ghi", "host", "pf.example.com",
		"n", 3, "zero", NonZero(0))
	out := buf.String()
	for _, bad := range []string{"empty=", "nil=", "zero=", "eyJ"} {
		if strings.Contains(out, bad) {
			t.Errorf("output %q contains %q", out, bad)
		}
	}
	for _, want := range []string{"jwt=\"<redacted:14 bytes>\"", "host=pf.example.com", "n=3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q lacks %q", out, want)
		}
	}
	buf.Reset()
	Log(context.Background(), l.WithGroup("g"), slog.LevelDebug-1, "below the level")
	Log(context.Background(), nil, slog.LevelError, "nil logger")
	if buf.Len() != 0 {
		t.Errorf("unexpected output %q", buf.String())
	}
}

func TestOrDiscard(t *testing.T) {
	if OrDiscard(nil).Enabled(context.Background(), slog.LevelError) {
		t.Fatal("the default logger must discard")
	}
	l := slog.Default()
	if OrDiscard(l) != l {
		t.Fatal("a configured logger is kept")
	}
}

func TestHostAndPath(t *testing.T) {
	cases := []struct{ url, host, path string }{
		{"https://pf.example.com:443/as/token.oauth2?secret=1#f", "pf.example.com", "/as/token.oauth2"},
		{"http://pf.example.com:80/x", "pf.example.com", "/x"},
		{"https://pf.example.com:9031/x?y", "pf.example.com:9031", "/x"},
		{"https://user:pw@pf.example.com/x", "pf.example.com", "/x"},
		{"://bad", "", ""},
	}
	for _, c := range cases {
		if got := Host(c.url); got != c.host {
			t.Errorf("Host(%q) = %q, want %q", c.url, got, c.host)
		}
		if got := Path(c.url); got != c.path {
			t.Errorf("Path(%q) = %q, want %q", c.url, got, c.path)
		}
	}
}

// Synthetic, built here so no scanner mistakes them for real ones.
func vaultTokens() []string {
	var out []string
	for _, prefix := range []string{"hvs.", "hvb.", "hvr.", "s.", "b.", "r."} {
		for _, suffix := range []string{"", "-_x9"} {
			out = append(out, prefix+strings.Repeat("TESTONLY", 3)+suffix)
		}
	}
	return out
}

func TestLogRedactsCredentialKeys(t *testing.T) {
	keys := []string{"auth_req_id", "code", "handle", "token", "secret", "password", "assertion",
		"client_assertion", "vault_token", "x-vault-token", "X-Vault-Token", "Authorization", "dpop",
		"private_key", "refresh_token", "session_token", "api-token", "client_secret", "db_password"}
	for _, key := range keys {
		var buf bytes.Buffer
		l := slog.New(slog.NewTextHandler(&buf, nil))
		Log(context.Background(), l, slog.LevelInfo, "e", key, "opaque-value-123", "n", 7)
		out := buf.String()
		if strings.Contains(out, "opaque-value-123") || !strings.Contains(out, "<redacted:16 bytes>") ||
			!strings.Contains(out, "n=7") {
			t.Errorf("key %q: output %q", key, out)
		}
	}
	var buf bytes.Buffer
	Log(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)), slog.LevelInfo, "e", "code", 123456)
	if strings.Contains(buf.String(), "123456") {
		t.Errorf("a non-string value under a credential key was logged: %q", buf.String())
	}
}

func TestScrubRedactsCredentialValues(t *testing.T) {
	values := []string{"Bearer 2YotnFZFEjr1zCsicMWpAA", "DPoP 2YotnFZFEjr1zCsicMWpAA", "bearer opaque",
		"Basic YWxhZGRpbjpvcGVuc2VzYW1l", " Bearer 2YotnFZFEjr1zCsicMWpAA",
		"Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA"}
	for _, tok := range vaultTokens() {
		values = append(values, tok, "X-Vault-Token: "+tok)
	}
	for _, v := range values {
		if got := Scrub(v); !strings.HasPrefix(got, "<redacted:") {
			t.Errorf("Scrub(%q) = %q", v, got)
		}
	}
}

func TestLogKeepsOrdinaryAttributes(t *testing.T) {
	// A backstop, not a filter: the vocabulary in docs/logging.md passes through untouched.
	kv := []any{"host", "pf.example.com:9031", "path", "/as/token.oauth2", "method", "POST", "status", 400,
		"step", "token", "reason", "timeout", "token_type", "Bearer", "pop_method", "dpop_combined",
		"client_id", "urn:agent:x", "alg", "ES256", "source", "StaticSvidSource", "at", "token_endpoint",
		"keys", 3, "result", "invalid_audience", "mode", "introspection", "error", "authorization_pending",
		"expires_in", 120, "detail", "s.example.com", "other", "hvs.short", "label", "bob.smith",
		"host2", "vault.s.abcdefghijklmnopqrstuvwxyz.internal", "word", "DPoP", "scheme", "Bearer"}
	var buf bytes.Buffer
	Log(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)), slog.LevelInfo, "token.obtained", kv...)
	out := buf.String()
	if strings.Contains(out, "redacted") {
		t.Fatalf("an ordinary attribute was redacted: %q", out)
	}
	for i := 0; i < len(kv); i += 2 {
		if want := fmt.Sprintf("%s=%v", kv[i], kv[i+1]); !strings.Contains(out, want) {
			t.Errorf("output %q lacks %q", out, want)
		}
	}
}

func TestLogRedactionSharedCases(t *testing.T) {
	// validation/redaction.json is shared: the Java, Python and TypeScript tests read the same cases.
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "validation", "redaction.json"))
	if err != nil {
		t.Fatalf("read redaction cases: %v", err)
	}
	var file struct {
		Cases []struct {
			Key      string `json:"key"`
			Value    any    `json:"value"`
			Redacted bool   `json:"redacted"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse redaction cases: %v", err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no redaction cases")
	}
	for _, c := range file.Cases {
		var buf bytes.Buffer
		Log(context.Background(), slog.New(slog.NewJSONHandler(&buf, nil)), slog.LevelInfo, "e", c.Key, c.Value)
		var rec map[string]any
		if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
			t.Fatalf("case %q=%v: output %q: %v", c.Key, c.Value, buf.String(), err)
		}
		got := rec[c.Key]
		s, isString := got.(string)
		redacted := isString && strings.HasPrefix(s, "<redacted:")
		if redacted != c.Redacted || (!c.Redacted && fmt.Sprint(got) != fmt.Sprint(c.Value)) {
			t.Errorf("case %q=%q: logged %q, want redacted=%v", c.Key, c.Value, got, c.Redacted)
		}
	}
}
