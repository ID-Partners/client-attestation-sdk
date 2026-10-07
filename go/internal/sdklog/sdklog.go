// Package sdklog is the SDK's shared logging plumbing: the silent default logger, the event emitter that
// drops empty attributes and refuses anything that looks like a JWT, and the URL helpers that log only a
// host and a path. The event vocabulary is documented in docs/logging.md.
package sdklog

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

// Discard is the default logger: it never writes anything.
func Discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// OrDiscard returns l, or the discarding logger when l is nil.
func OrDiscard(l *slog.Logger) *slog.Logger {
	if l == nil {
		return Discard()
	}
	return l
}

// Log emits one event. kv is alternating key/value pairs. A pair whose value is nil or "" is left out,
// and a string value that looks like a JWT is replaced by "<redacted:N bytes>" as a backstop: callers
// never pass credentials, and this makes sure a mistake cannot put one in a log.
func Log(ctx context.Context, l *slog.Logger, level slog.Level, event string, kv ...any) {
	if l == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !l.Enabled(ctx, level) {
		return
	}
	attrs := make([]slog.Attr, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key, _ := kv[i].(string)
		value := kv[i+1]
		if key == "" || value == nil {
			continue
		}
		if s, ok := value.(string); ok {
			if s == "" {
				continue
			}
			value = Scrub(s)
		}
		attrs = append(attrs, slog.Any(key, value))
	}
	l.LogAttrs(ctx, level, event, attrs...)
}

// Scrub returns s, or "<redacted:N bytes>" when s looks like it carries a JWT (contains "eyJ", the
// base64url of `{"`).
func Scrub(s string) string {
	if strings.Contains(s, "eyJ") {
		return fmt.Sprintf("<redacted:%d bytes>", len(s))
	}
	return s
}

// NonZero returns v, or nil (so Log leaves the attribute out) when v is zero.
func NonZero(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// Host is the host (and port, when it is not the scheme's default) of a URL; "" when it does not parse.
func Host(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	port := u.Port()
	if port == "" || (strings.EqualFold(u.Scheme, "https") && port == "443") || (strings.EqualFold(u.Scheme, "http") && port == "80") {
		return u.Hostname()
	}
	return u.Host
}

// Path is the path of a URL, never its query string or fragment.
func Path(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.EscapedPath()
}
