package tokenvalidator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/id-partners/client-attestation-sdk/go/internal/sdklog"
)

// WithLogger sends the validator's events (verdicts, JWKS fetches, introspection failures) to logger.
// The default discards everything; a nil logger also discards. Event names and attributes are shared by
// every port: see docs/logging.md. No token or credential is ever logged — a verdict carries only its
// stable error code.
func WithLogger(logger *slog.Logger) Option {
	return func(v *AccessTokenValidator) { v.logger = logger }
}

// statusError is a non-2xx answer from the JWKS or introspection endpoint.
type statusError struct {
	what   string
	status int
}

func (e *statusError) Error() string { return fmt.Sprintf("%s: status %d", e.what, e.status) }

// tooLargeError is a response body over the cap.
type tooLargeError struct{ msg string }

func (e *tooLargeError) Error() string { return e.msg }

// failureReason classifies a fetch error: timeout, redirect, too_large, status, malformed or network.
func failureReason(err error) (reason string, status int) {
	var se *statusError
	if errors.As(err, &se) {
		return "status", se.status
	}
	var tl *tooLargeError
	if errors.As(err, &tl) {
		return "too_large", 0
	}
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		return "malformed", 0
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", 0
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout", 0
	}
	if strings.Contains(err.Error(), "redirects are not followed") {
		return "redirect", 0
	}
	return "network", 0
}

// logVerdict emits token.validated: debug for a valid token, info for a rejection.
func (v *AccessTokenValidator) logVerdict(result Result, mode string) Result {
	level := slog.LevelInfo
	if result.Valid {
		level = slog.LevelDebug
	}
	sdklog.Log(context.Background(), v.logger, level, "token.validated", "result", result.Error, "mode", mode)
	return result
}
