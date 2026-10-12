// Package sdklog is the SDK's shared logging plumbing: the silent default logger, the event emitter that
// drops empty attributes and refuses anything that looks like a credential, and the URL helpers that log
// only a host and a path. The event vocabulary is documented in docs/logging.md.
package sdklog

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
)

// The backstop (docs/logging.md, the same rule in every port): an attribute is redacted when its key names
// a credential, or its value carries one this SDK handles. Keys are matched in lower case.
var (
	secretKeys = map[string]bool{
		"svid": true, "proof": true, "assertion": true, "client_assertion": true, "subject_token": true,
		"actor_token": true, "client_secret": true, "attestation": true, "access_token": true,
		"refresh_token": true, "id_token": true, "authorization": true, "dpop": true,
		"oauth-client-attestation": true, "oauth-client-attestation-pop": true, "auth_req_id": true,
		"code": true, "handle": true, "token": true, "secret": true, "password": true, "private_key": true,
		"vault_token": true, "x-vault-token": true,
	}
	secretKeySuffixes = []string{"_token", "-token", "_secret", "-secret", "_password"}
	// Vault/OpenBao tokens: hvs./hvb./hvr. and the older s./b./r. forms, standing alone.
	vaultToken = regexp.MustCompile(`(?:^|[^A-Za-z0-9._-])(?:hv[sbr]\.[A-Za-z0-9_-]{20,}|[sbr]\.[A-Za-z0-9_-]{24,}(?:$|[^A-Za-z0-9._-]))`)
	// An Authorization header value anywhere in the string: a scheme this SDK sends, standing alone, then
	// whitespace and the first character of a credential ("Bearer x", " Bearer x", "Authorization: Bearer x").
	// A bare scheme name ("Bearer", "token_type=Bearer", "dpop_combined") is not one.
	authScheme = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_-])(?:bearer|dpop|basic)[ \t]+[A-Za-z0-9._~+/-]`)
)

// SecretKey reports whether an attribute key names a credential, so its value is redacted whatever it
// looks like (an opaque token, an auth_req_id, a ceremony handle).
func SecretKey(key string) bool {
	k := strings.ToLower(key)
	if secretKeys[k] {
		return true
	}
	for _, suffix := range secretKeySuffixes {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}

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
// and a value under a credential key (SecretKey), or a string value that looks like a credential (Scrub),
// is replaced by "<redacted:N bytes>" as a backstop: callers never pass credentials, and this makes sure a
// mistake cannot put one in a log.
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
		s, isString := value.(string)
		if isString && s == "" {
			continue
		}
		if SecretKey(key) {
			value = redacted(fmt.Sprint(value))
		} else if isString {
			value = Scrub(s)
		}
		attrs = append(attrs, slog.Any(key, value))
	}
	l.LogAttrs(ctx, level, event, attrs...)
}

// Scrub returns s, or "<redacted:N bytes>" when s looks like it carries a credential: a JWT (contains
// "eyJ", the base64url of `{"`), a Vault/OpenBao token, or an Authorization header value.
func Scrub(s string) string {
	if strings.Contains(s, "eyJ") || vaultToken.MatchString(s) || authScheme.MatchString(s) {
		return redacted(s)
	}
	return s
}

func redacted(s string) string {
	return fmt.Sprintf("<redacted:%d bytes>", len(s))
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
