package sdklog

import (
	"bytes"
	"context"
	"log/slog"
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
