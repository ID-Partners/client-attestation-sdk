package tokenvalidator

// Result is the outcome of validating an access token: either a valid token
// (with its subject, granted scopes, audience and claims) or a failure carrying
// a stable Error code (see the Err* constants).
type Result struct {
	Valid            bool
	Error            string
	ErrorDescription string
	Subject          string
	Scopes           []string
	Audience         []string
	Claims           map[string]any
	// ExpiresAt is the "exp" claim in epoch seconds, or 0 when absent.
	ExpiresAt int64
}

// failure builds an invalid Result with a stable error code and description.
func failure(code, description string) Result {
	return Result{Valid: false, Error: code, ErrorDescription: description}
}

// success builds a valid Result from the token claims, granted scopes and
// audience. Subject is taken from "sub" and ExpiresAt from "exp".
func success(claims map[string]any, scopes, audience []string) Result {
	return Result{
		Valid:     true,
		Error:     ErrValid,
		Subject:   stringClaim(claims, "sub"),
		Scopes:    scopes,
		Audience:  audience,
		Claims:    claims,
		ExpiresAt: intClaim(claims, "exp"),
	}
}
