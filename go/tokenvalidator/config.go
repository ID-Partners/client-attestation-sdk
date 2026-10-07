package tokenvalidator

import (
	"encoding/json"
	"errors"
	"strings"
)

// DefaultAlgorithms returns the accepted-algorithm set used when a Config leaves
// AcceptedAlgorithms nil: ECDSA / RSA-PKCS1 / RSA-PSS at 256/384/512. Each call
// returns a new slice, so changing it has no effect on validation.
func DefaultAlgorithms() []string { return append([]string(nil), defaultAlgorithms...) }

// DefaultTokenTypes returns the accepted "typ" header set used when a Config
// leaves AcceptedTokenTypes nil: RFC 9068 section 2.1 at+jwt (the application/
// prefix is optional). Each call returns a new slice.
func DefaultTokenTypes() []string { return append([]string(nil), defaultTokenTypes...) }

// The defaults the validator uses. Unexported, so no other package can widen
// what a validator with a default Config accepts.
var (
	defaultAlgorithms = []string{
		"ES256", "ES384", "ES512",
		"RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
	}
	defaultTokenTypes = []string{"at+jwt"}
)

// DefaultLeewaySeconds is the clock skew allowance applied to exp/nbf/iat when a
// Config leaves LeewaySeconds at zero and ZeroLeeway unset.
const DefaultLeewaySeconds = 60

// IntrospectionConfig holds an RFC 7662 introspection endpoint and the client
// credentials the resource server uses to authenticate to the authorization
// server.
type IntrospectionConfig struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	// AuthMethod is "client_secret_basic" (default) or "client_secret_post".
	AuthMethod string
}

// Config describes what a resource server accepts: the trusted issuer, its own
// audience identifier(s), the signing keys (static JWKS or a JWKSURI to fetch),
// required scopes, accepted algorithms, clock leeway, and optional
// introspection.
//
// Issuer and Audiences are required: New refuses a Config without them,
// because a validator that skips either accepts tokens minted for someone else.
type Config struct {
	// Issuer is the expected "iss" claim. Required.
	Issuer string
	// Audiences are this resource server's accepted audience identifiers.
	// At least one is required.
	Audiences []string
	// JWKS is a static JSON Web Key Set (raw JSON: {"keys":[...]}). Mutually
	// exclusive with JWKSURI.
	JWKS json.RawMessage
	// JWKSURI is fetched (and cached, refreshed on an unknown kid) when JWKS is
	// not provided.
	JWKSURI string
	// RequiredScopes must all be granted unless Validate is called with an
	// explicit override.
	RequiredScopes []string
	// AcceptedAlgorithms is the set of accepted "alg" header values. nil means
	// DefaultAlgorithms; a non-nil empty slice accepts nothing. "none" and the
	// HS* algorithms are refused even when listed.
	AcceptedAlgorithms []string
	// LeewaySeconds is the clock skew allowance for exp/nbf/iat. Zero means
	// DefaultLeewaySeconds, because an int can't tell "unset" from 0: set
	// ZeroLeeway for no allowance at all.
	LeewaySeconds int
	// ZeroLeeway allows no clock skew at all. LeewaySeconds must then be 0.
	ZeroLeeway bool
	// AcceptedTokenTypes is checked against the JWT "typ" header when the token
	// carries one, so an ID token can't stand in for an access token. nil
	// means DefaultTokenTypes; a non-nil empty slice accepts no typ (a token
	// without one is still accepted).
	AcceptedTokenTypes []string
	// DisableTokenTypeCheck turns the "typ" check off, for an issuer that
	// stamps something other than at+jwt.
	DisableTokenTypeCheck bool
	// Introspection, when set, enables ValidateActive via RFC 7662.
	Introspection *IntrospectionConfig
}

// check refuses a contradictory config.
func (c *Config) check() error {
	if c.ZeroLeeway && c.LeewaySeconds != 0 {
		return errors.New("tokenvalidator: ZeroLeeway is set but LeewaySeconds is not 0")
	}
	return nil
}

// acceptedAlgorithms returns the configured accepted algorithms, or the
// defaults when the field is nil (an empty slice accepts nothing).
func (c *Config) acceptedAlgorithms() []string {
	if c.AcceptedAlgorithms == nil {
		return defaultAlgorithms
	}
	return c.AcceptedAlgorithms
}

// leeway returns the configured leeway: 0 with ZeroLeeway, else the default
// when LeewaySeconds is zero.
func (c *Config) leeway() int {
	if c.ZeroLeeway {
		return 0
	}
	if c.LeewaySeconds == 0 {
		return DefaultLeewaySeconds
	}
	return c.LeewaySeconds
}

// acceptsTokenType reports whether a "typ" header value is acceptable.
func (c *Config) acceptsTokenType(typ string) bool {
	if c.DisableTokenTypeCheck {
		return true
	}
	types := c.AcceptedTokenTypes
	if types == nil {
		types = defaultTokenTypes
	}
	for _, t := range types {
		if normaliseType(t) == normaliseType(typ) {
			return true
		}
	}
	return false
}

// normaliseType compares JOSE "typ" values the way RFC 7515 section 4.1.9
// says to: case-insensitively, with an optional "application/" prefix.
func normaliseType(value string) string {
	return strings.TrimPrefix(strings.ToLower(value), "application/")
}
