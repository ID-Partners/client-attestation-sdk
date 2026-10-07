package clientattestation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/id-partners/client-attestation-sdk/go/internal/sdklog"
)

// WithLogger sends the token source's events (discovery, minting, the token endpoint, DPoP nonce
// retries, HTTP failures) to logger. The default discards everything; a nil logger also discards. Event
// names and attributes are shared by every port: see docs/logging.md. No token, attestation, proof,
// SVID, challenge value, key material or header value is ever logged.
func WithLogger(logger *slog.Logger) Option {
	return func(c *ClientAttestation) { c.logger = logger }
}

// log emits one event on the configured logger (a no-op when none is configured).
func (c *ClientAttestation) log(ctx context.Context, level slog.Level, event string, kv ...any) {
	sdklog.Log(ctx, c.logger, level, event, kv...)
}

// logHTTPFailure emits http.failed for a call the flow made. status is 0 when the server never answered.
func (c *ClientAttestation) logHTTPFailure(ctx context.Context, step, method, target string, status int, reason string) {
	c.log(ctx, slog.LevelWarn, "http.failed",
		"step", step, "method", method, "host", sdklog.Host(target), "path", sdklog.Path(target),
		"status", sdklog.NonZero(int64(status)), "reason", reason)
}

// typeName is a value's bare type name ("StaticSvidSource"), as the other ports log it.
func typeName(v any) string {
	name := strings.TrimLeft(fmt.Sprintf("%T", v), "*")
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// transportReason classifies an error from doRequest: timeout, redirect, too_large or network.
func transportReason(err error) (reason string, status int) {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", 0
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout", 0
	}
	var caErr *ClientAttestationError
	if errors.As(err, &caErr) {
		switch {
		case strings.HasPrefix(caErr.Message, "refusing to follow HTTP redirect"):
			return "redirect", caErr.Status
		case strings.Contains(caErr.Message, " exceeds "):
			return "too_large", caErr.Status
		}
		return "network", caErr.Status
	}
	return "network", 0
}
