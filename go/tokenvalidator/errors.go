// Package tokenvalidator provides resource-server access-token validation:
// JWT signature + scope/audience checks in a fixed, cross-language order, plus
// optional RFC 7662 introspection.
//
// The validation order and the stable error codes below are part of a
// cross-language contract shared with the Python and TypeScript ports so that
// every port reports the same verdict for the same token.
package tokenvalidator

// Stable validation outcome codes, shared across the Python / TypeScript / Go
// ports so their verdicts can be compared directly.
const (
	ErrValid                = "valid"
	ErrExpired              = "expired"
	ErrNotYetValid          = "not_yet_valid"
	ErrInvalidSignature     = "invalid_signature"
	ErrInvalidIssuer        = "invalid_issuer"
	ErrInvalidAudience      = "invalid_audience"
	ErrInsufficientScope    = "insufficient_scope"
	ErrInvalidToken         = "invalid_token"
	ErrUnsupportedAlgorithm = "unsupported_algorithm"
	ErrKeyNotFound          = "key_not_found"
	ErrInactive             = "inactive"
	ErrMissingExpiry        = "missing_expiry"
	ErrIssuedInFuture       = "issued_in_future"
	ErrInvalidTokenType     = "invalid_token_type"
)
