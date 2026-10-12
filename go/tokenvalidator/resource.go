package tokenvalidator

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ProtectedResource adds the OAuth 2.0/2.1 resource-server transport conventions on top of an
// AccessTokenValidator: RFC 9728 Protected Resource Metadata (/.well-known/oauth-protected-resource),
// RFC 6750 bearer extraction + WWW-Authenticate challenges, and a request guard that binds the token
// audience to this resource (RFC 8707). It is the resource-server side of any OAuth-protected HTTP service
// — an MCP server, an A2A agent, or a plain REST API. Protocol-neutral: nothing here is MCP-only.

const wellKnownProtectedResource = "/.well-known/oauth-protected-resource"

var bearerPattern = regexp.MustCompile(`(?i)^\s*Bearer\s+(.+?)\s*$`)

// BearerToken extracts the token from an "Authorization: Bearer <token>" header value, or "" if the header
// is absent, blank, or not a Bearer credential.
func BearerToken(authorizationHeader string) string {
	m := bearerPattern.FindStringSubmatch(authorizationHeader)
	if m == nil {
		return ""
	}
	return m[1]
}

// ProtectedResourceMetadata is the RFC 9728 protected-resource metadata document.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
}

// AuthDecision is the outcome of guarding a request. Authorized is true on success; otherwise Status is
// 401 or 403 and WWWAuthenticate carries the header value to return.
type AuthDecision struct {
	Authorized       bool
	Result           Result
	Status           int
	WWWAuthenticate  string
	Error            string
	ErrorDescription string
}

// ProtectedResource is an OAuth-protected resource server. The validator must accept resource as an
// audience so incoming tokens are bound to this resource (RFC 8707), which MCP servers MUST enforce.
type ProtectedResource struct {
	Resource             string
	AuthorizationServers []string
	ScopesSupported      []string
	validator            *AccessTokenValidator
}

// NewProtectedResource builds a ProtectedResource around a configured validator. It refuses a validator
// that does not accept resource as an audience.
func NewProtectedResource(resource string, authorizationServers []string, validator *AccessTokenValidator, scopesSupported []string) (*ProtectedResource, error) {
	if !contains(validator.config.Audiences, resource) {
		return nil, fmt.Errorf("tokenvalidator: the validator does not accept this resource (%s) as an audience", resource)
	}
	return &ProtectedResource{
		Resource:             resource,
		AuthorizationServers: authorizationServers,
		ScopesSupported:      scopesSupported,
		validator:            validator,
	}, nil
}

// Metadata returns the RFC 9728 protected-resource metadata. Serve it at MetadataPath.
func (p *ProtectedResource) Metadata() ProtectedResourceMetadata {
	return ProtectedResourceMetadata{
		Resource:               p.Resource,
		AuthorizationServers:   p.AuthorizationServers,
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        p.ScopesSupported,
	}
}

// MetadataPath is the path to serve the metadata at, per RFC 9728 §3.
func (p *ProtectedResource) MetadataPath() string {
	u, err := url.Parse(p.Resource)
	if err != nil || u.Path == "" || u.Path == "/" {
		return wellKnownProtectedResource
	}
	return wellKnownProtectedResource + u.Path
}

// MetadataURL is the absolute URL of the metadata document.
func (p *ProtectedResource) MetadataURL() string {
	u, err := url.Parse(p.Resource)
	if err != nil {
		return p.MetadataPath()
	}
	return u.Scheme + "://" + u.Host + p.MetadataPath()
}

// Challenge builds the "WWW-Authenticate: Bearer ..." header value (RFC 6750 + RFC 9728 §5.1).
func (p *ProtectedResource) Challenge(errCode, errDescription string) string {
	var params []string
	if errCode != "" {
		params = append(params, `error="`+quoteAuthParam(errCode)+`"`)
		if errDescription != "" {
			params = append(params, `error_description="`+quoteAuthParam(errDescription)+`"`)
		}
	}
	params = append(params, `resource_metadata="`+quoteAuthParam(p.MetadataURL())+`"`)
	return "Bearer " + strings.Join(params, ", ")
}

// Authenticate guards a request: extract the bearer token, validate it (audience must be this resource,
// plus any requiredScopes), and return an AuthDecision. Missing/invalid/expired/wrong-audience → 401;
// insufficient scope → 403.
func (p *ProtectedResource) Authenticate(authorizationHeader string, requiredScopes []string) AuthDecision {
	decision, _ := p.guard(authorizationHeader, func(token string) (Result, error) {
		return p.validator.Validate(token, requiredScopes), nil
	})
	return decision
}

// AuthenticateActive is Authenticate for tokens checked by RFC 7662 introspection (ValidateActive), such
// as opaque tokens, with the same rules: the response's aud must name this resource, so a response without
// one is refused (401), and a sender-constrained token (cnf) is refused (401). A failed introspection call
// is not a verdict: it returns ValidateActive's error, with a zero AuthDecision, and the caller answers it
// (503, say).
func (p *ProtectedResource) AuthenticateActive(authorizationHeader string, requiredScopes []string) (AuthDecision, error) {
	return p.guard(authorizationHeader, func(token string) (Result, error) {
		return p.validator.ValidateActive(token, requiredScopes)
	})
}

func (p *ProtectedResource) guard(authorizationHeader string, validate func(string) (Result, error)) (AuthDecision, error) {
	token := BearerToken(authorizationHeader)
	if token == "" {
		return AuthDecision{Status: 401, WWWAuthenticate: p.Challenge("", ""), ErrorDescription: "authentication required"}, nil
	}
	result, err := validate(token)
	if err != nil {
		return AuthDecision{}, err
	}
	if result.Valid && !contains(result.Audience, p.Resource) {
		result = failure(ErrInvalidAudience, "token audience is not this resource")
	}
	if result.Valid && result.Claims["cnf"] != nil {
		result = failure(ErrInvalidToken, "sender-constrained token requires proof verification")
	}
	if result.Valid {
		return AuthDecision{Authorized: true, Result: result, Status: 200}, nil
	}
	status, oauthErr := resourceHTTPError(result.Error)
	return AuthDecision{
		Result:           result,
		Status:           status,
		Error:            oauthErr,
		ErrorDescription: result.ErrorDescription,
		WWWAuthenticate:  p.Challenge(oauthErr, result.ErrorDescription),
	}, nil
}

func resourceHTTPError(errCode string) (int, string) {
	if errCode == ErrInsufficientScope {
		return 403, "insufficient_scope"
	}
	return 401, "invalid_token"
}

// quoteAuthParam makes v safe inside a quoted auth-param: control characters (0x00-0x1F, 0x7F — CR and
// LF included, so no header splitting) are dropped, and backslash and double quote are escaped.
func quoteAuthParam(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
	v = strings.ReplaceAll(v, `\`, `\\`)
	return strings.ReplaceAll(v, `"`, `\"`)
}
