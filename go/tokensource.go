package clientattestation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"
)

// DraftRevision is the draft-ietf-oauth-attestation-based-client-auth revision this SDK implements.
const DraftRevision = "10"

// wellKnownPath is the attester discovery document path.
const wellKnownPath = "/.well-known/client-attester"

// DefaultExpirySkew is how long before actual expiry a cached token is refreshed, so a token is never
// used at the edge.
const DefaultExpirySkew = 30 * time.Second

// ClientAttestation gets and caches an access token from a PingFederate host using client attestation.
//
// It runs the whole flow in one call: discover -> get the workload's platform identity (evidence) ->
// get a challenge -> mint the attestation -> call the token endpoint with the attestation headers ->
// cache the access token. The workload sends no client secret and no client_id; its only credential is
// the attestation, built from the identity its runtime already gives it (auto-detected; see evidence.go).
type ClientAttestation struct {
	baseURL              string
	evidence             SvidSource
	authorizationDetails []map[string]any
	operator             map[string]any
	challengeAtToken     bool
	algorithm            string
	popMethod            string
	skew                 time.Duration
	timeout              time.Duration
	httpClient           *http.Client
	requireChallenge     bool
	allowInsecure        bool

	// lock is a 1-buffered channel semaphore guarding the cache and the network flow (single-flight).
	// Unlike a sync.Mutex, a waiter can give up when its ctx is cancelled.
	lockOnce    sync.Once
	lock        chan struct{}
	cachedToken string
	tokenType   string          // "Bearer" or "DPoP", parsed from the token response
	boundKey    *SigningKeyPair // instance key that minted the attestation behind cachedToken
	expiresAt   time.Time
	discovery   *discoveryDoc

	// nonceMu guards nonces: the last DPoP-Nonce each origin returned.
	nonceMu sync.Mutex
	nonces  map[string]string
}

// Token types the SDK distinguishes (token_type in the token response, compared case-insensitively).
const (
	TokenTypeBearer = "Bearer"
	TokenTypeDPoP   = "DPoP"
)

// Option configures a ClientAttestation.
type Option func(*ClientAttestation)

// WithEvidence overrides evidence auto-detection with an explicit SvidSource.
func WithEvidence(source SvidSource) Option {
	return func(c *ClientAttestation) { c.evidence = source }
}

// WithAuthorizationDetails sets the optional RFC 9396 access request sent at mint time; the attester
// grants at most what the workload is entitled to.
func WithAuthorizationDetails(details []map[string]any) Option {
	return func(c *ClientAttestation) { c.authorizationDetails = details }
}

// WithOperator names the client's operator — who answers for this workload. It is sent in the mint
// request body as "operator", so the attester (not the client) is what states it; an attester that does
// not know the member ignores it, and one that does can refuse to name an operator it cannot corroborate.
// When set it is also sent as the token-endpoint form parameter "operator" (compact JSON, sorted keys),
// so an AS can populate RFC 8693 may_act from it without parsing the attestation; an AS that does not
// know the parameter ignores it. A nil or empty map sends nothing.
func WithOperator(operator map[string]any) Option {
	return func(c *ClientAttestation) { c.operator = operator }
}

// WithChallengeAtToken controls whether the attester-issued challenge also rides in the token-endpoint
// proof (the PoP's "challenge" claim, or the DPoP "nonce"), on top of the mint-time instance proof it
// always protects. The default true binds token issuance to the same challenge as the mint, so a
// captured attestation cannot be redeemed for a token without it — but it requires an attester whose
// challenge store tolerates being checked at both points. Some attesters treat a challenge as consumed
// the moment the mint's instance proof uses it, and then reject a token request that presents the same
// value as "unknown or expired" — pass false against one of those (the challenge still protects the
// mint; only the token-endpoint copy is dropped).
func WithChallengeAtToken(enabled bool) Option {
	return func(c *ClientAttestation) { c.challengeAtToken = enabled }
}

// WithAlgorithm sets the instance-key signature algorithm (default ES256).
func WithAlgorithm(algorithm string) Option {
	return func(c *ClientAttestation) {
		if algorithm != "" {
			c.algorithm = algorithm
		}
	}
}

// WithPopMethod sets the proof-of-possession method sent alongside the attestation:
// PopMethodAttestationPopJWT (default) sends a dedicated OAuth-Client-Attestation-PoP JWT under the
// PoP header; PopMethodDpopCombined sends a DPoP proof under the DPoP header instead.
func WithPopMethod(method string) Option {
	return func(c *ClientAttestation) {
		if method != "" {
			c.popMethod = method
		}
	}
}

// WithExpirySkew refreshes the cached token this long before it expires (default 30s).
func WithExpirySkew(skew time.Duration) Option {
	return func(c *ClientAttestation) { c.skew = skew }
}

// WithTimeout sets the per-request HTTP timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *ClientAttestation) { c.timeout = timeout }
}

// WithHTTPClient supplies a custom *http.Client. It is never mutated: when it has no CheckRedirect the
// SDK uses a shallow copy that refuses redirects, and when it has no Timeout the copy gets the
// WithTimeout value (default 20s). A non-zero Timeout is honored as-is.
func WithHTTPClient(client *http.Client) Option {
	return func(c *ClientAttestation) { c.httpClient = client }
}

// WithRequireChallenge controls what happens when the discovery document advertises a
// challenge_endpoint but fetching a challenge fails (network, status, bad JSON, no
// attestation_challenge). With true (the default) the flow fails closed with a *ClientAttestationError;
// with false it proceeds without a challenge. No advertised challenge_endpoint never fails.
func WithRequireChallenge(require bool) Option {
	return func(c *ClientAttestation) { c.requireChallenge = require }
}

// WithAllowInsecure permits plain-http pfHost and discovery endpoints on non-loopback hosts. Without it
// every such URL must be https (localhost, 127.0.0.1 and ::1 are always allowed).
func WithAllowInsecure() Option {
	return func(c *ClientAttestation) { c.allowInsecure = true }
}

// NewClientAttestation builds a token source aimed at pfHost — "pf.example.com", or a full base URL
// "https://pf.example.com". Plain hostnames default to https. An http:// host is refused unless it is
// loopback or WithAllowInsecure() is given.
func NewClientAttestation(pfHost string, opts ...Option) (*ClientAttestation, error) {
	base, err := normalizeBaseURL(pfHost)
	if err != nil {
		return nil, err
	}
	c := &ClientAttestation{
		baseURL:          base,
		algorithm:        "ES256",
		popMethod:        PopMethodAttestationPopJWT,
		skew:             DefaultExpirySkew,
		timeout:          20 * time.Second,
		requireChallenge: true,
		challengeAtToken: true,
	}
	for _, opt := range opts {
		opt(c)
	}
	if err := c.checkSecure(c.baseURL); err != nil {
		return nil, err
	}
	c.httpClient = safeClient(c.httpClient, c.timeout)
	return c, nil
}

// TokenOption tunes a single TokenWithOptions call.
type TokenOption func(*tokenOptions)

type tokenOptions struct {
	forceRefresh bool
}

// WithForceRefresh bypasses the cached token: the full flow runs and the fresh token replaces the cache.
func WithForceRefresh() TokenOption {
	return func(o *tokenOptions) { o.forceRefresh = true }
}

// acquire takes the single-flight lock, giving up with ctx.Err() if ctx is done first.
func (c *ClientAttestation) acquire(ctx context.Context) error {
	c.lockOnce.Do(func() { c.lock = make(chan struct{}, 1) })
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *ClientAttestation) release() { <-c.lock }

// Token returns a valid access token, minting a new one only when the cached one is near expiry.
// Waiting for a concurrent refresh honors ctx cancellation.
func (c *ClientAttestation) Token(ctx context.Context) (string, error) {
	return c.TokenWithOptions(ctx)
}

// TokenWithOptions is Token with per-call options, e.g. WithForceRefresh().
func (c *ClientAttestation) TokenWithOptions(ctx context.Context, opts ...TokenOption) (string, error) {
	state, err := c.tokenState(ctx, opts...)
	if err != nil {
		return "", err
	}
	return state.token, nil
}

// boundToken is a snapshot of the cached token, its type and the instance key it is bound to.
type boundToken struct {
	token     string
	tokenType string
	key       *SigningKeyPair
}

func (b boundToken) isDPoP() bool { return b.tokenType == TokenTypeDPoP }

// tokenState returns the cached token (minting a new one when needed) together with its type and bound
// key, all read under the same lock so they always belong together.
func (c *ClientAttestation) tokenState(ctx context.Context, opts ...TokenOption) (boundToken, error) {
	var o tokenOptions
	for _, opt := range opts {
		opt(&o)
	}
	if err := c.acquire(ctx); err != nil {
		return boundToken{}, err
	}
	defer c.release()
	// Re-checked under the lock: a waiter that queued behind a refresh is served the fresh token.
	if !o.forceRefresh && c.cachedToken != "" && time.Now().Before(c.expiresAt) {
		return boundToken{c.cachedToken, c.tokenType, c.boundKey}, nil
	}
	response, instanceKey, err := c.runFlow(ctx)
	if err != nil {
		return boundToken{}, err
	}
	c.cachedToken = response.AccessToken
	c.boundKey = instanceKey
	c.tokenType = TokenTypeBearer
	if strings.EqualFold(strings.TrimSpace(response.TokenType), TokenTypeDPoP) {
		c.tokenType = TokenTypeDPoP
	}
	if response.ExpiresIn > 0 {
		c.expiresAt = time.Now().Add(time.Duration(response.ExpiresIn)*time.Second - c.skew)
	} else {
		c.expiresAt = time.Time{}
	}
	return boundToken{c.cachedToken, c.tokenType, c.boundKey}, nil
}

// RequestHeaders returns the headers to send to a resource for one request, obtaining or refreshing the
// token like Token does:
//
//   - Bearer token: {"Authorization": "Bearer <t>"}
//   - DPoP-bound token: {"Authorization": "DPoP <t>", "DPoP": <proof>}, the proof signed by the instance
//     key the token is bound to, with htm = method, htu = url (no query/fragment), a fresh jti and iat,
//     ath = hash of the token, and nonce = the last DPoP-Nonce that url's origin returned, if any.
//
// Build headers per request: a DPoP proof is single-use. RoundTripper does this for you, including the
// one retry on a use_dpop_nonce challenge.
func (c *ClientAttestation) RequestHeaders(ctx context.Context, method, url string) (map[string]string, error) {
	headers, _, err := c.requestHeaders(ctx, method, url)
	return headers, err
}

func (c *ClientAttestation) requestHeaders(ctx context.Context, method, target string, opts ...TokenOption) (map[string]string, bool, error) {
	state, err := c.tokenState(ctx, opts...)
	if err != nil {
		return nil, false, err
	}
	if !state.isDPoP() {
		return map[string]string{"Authorization": "Bearer " + state.token}, false, nil
	}
	if state.key == nil {
		return nil, true, &ClientAttestationError{Message: "DPoP-bound token has no bound instance key"}
	}
	proof, err := NewDpopProofBuilder(state.key).
		Method(method).
		URI(target).
		AccessToken(state.token).
		Nonce(c.nonceFor(target)).
		Build()
	if err != nil {
		return nil, true, err
	}
	return map[string]string{"Authorization": "DPoP " + state.token, DpopHeader: proof}, true, nil
}

// AuthorizationHeader returns the Authorization header value: "Bearer <token>", or "DPoP <token>" when
// the AS issued a DPoP-bound token. A DPoP-bound token also needs a per-request DPoP proof, which this
// value alone does not carry — use RequestHeaders (or RoundTripper) for those.
func (c *ClientAttestation) AuthorizationHeader(ctx context.Context) (string, error) {
	return c.AuthorizationHeaderWithOptions(ctx)
}

// AuthorizationHeaderWithOptions is AuthorizationHeader with per-call options, e.g. WithForceRefresh().
func (c *ClientAttestation) AuthorizationHeaderWithOptions(ctx context.Context, opts ...TokenOption) (string, error) {
	state, err := c.tokenState(ctx, opts...)
	if err != nil {
		return "", err
	}
	if state.isDPoP() {
		return TokenTypeDPoP + " " + state.token, nil
	}
	return "Bearer " + state.token, nil
}

// RoundTripper returns an http.RoundTripper that attaches (and refreshes) the access token on every
// outbound request using RequestHeaders, delegating to http.DefaultTransport. For a Bearer token that is
// just the Authorization header. For a DPoP-bound token it also adds a fresh DPoP proof, and on a
// use_dpop_nonce challenge (401 WWW-Authenticate: DPoP error="use_dpop_nonce", or a 400 JSON error, with
// a DPoP-Nonce header) it remembers the nonce for the origin and resends once with a new proof. A request
// body is rewound with req.GetBody; with no GetBody and a non-empty body the challenge is returned as-is.
// Use RoundTripperOver to supply a base.
func (c *ClientAttestation) RoundTripper() http.RoundTripper {
	return &authRoundTripper{source: c}
}

// RoundTripperOver is like RoundTripper but delegates to the given base transport.
func (c *ClientAttestation) RoundTripperOver(base http.RoundTripper) http.RoundTripper {
	return &authRoundTripper{source: c, base: base}
}

// Discovery returns the attester's /.well-known/client-attester document (fetched once, then cached).
func (c *ClientAttestation) Discovery(ctx context.Context) (*discoveryDoc, error) {
	if err := c.acquire(ctx); err != nil {
		return nil, err
	}
	defer c.release()
	return c.getDiscovery(ctx)
}

// ── the flow ────────────────────────────────────────────────────────────────────────────────────────

type discoveryDoc struct {
	EvidenceAudience    string `json:"evidence_audience"`
	AttestationEndpoint string `json:"attestation_endpoint"`
	ChallengeEndpoint   string `json:"challenge_endpoint"`
	TokenEndpoint       string `json:"token_endpoint"`
	PopAudience         string `json:"pop_audience"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// getDiscovery fetches and caches the discovery document. Caller holds c.lock.
func (c *ClientAttestation) getDiscovery(ctx context.Context) (*discoveryDoc, error) {
	if c.discovery != nil {
		return c.discovery, nil
	}
	var doc discoveryDoc
	if err := c.getJSON(ctx, http.MethodGet, c.baseURL+wellKnownPath, nil, &doc); err != nil {
		return nil, err
	}
	c.discovery = &doc
	return c.discovery, nil
}

// runFlow runs the full attestation exchange and returns the token endpoint response together with the
// instance key the attestation (and so the token) is bound to. Caller holds c.lock.
func (c *ClientAttestation) runFlow(ctx context.Context) (*tokenResponse, *SigningKeyPair, error) {
	doc, err := c.getDiscovery(ctx)
	if err != nil {
		return nil, nil, err
	}
	if doc.EvidenceAudience == "" {
		return nil, nil, &ClientAttestationError{Message: "attester discovery document has no evidence_audience"}
	}
	if doc.AttestationEndpoint == "" {
		return nil, nil, &ClientAttestationError{Message: "attester discovery document has no attestation_endpoint"}
	}

	source := c.evidence
	if source == nil {
		source, err = AutoDetectEvidence()
		if err != nil {
			return nil, nil, err
		}
	}
	svid, err := source.Fetch(doc.EvidenceAudience)
	if err != nil {
		return nil, nil, err
	}

	instanceKey, err := Generate(c.algorithm)
	if err != nil {
		return nil, nil, err
	}
	challenge, err := c.fetchChallenge(ctx, doc)
	if err != nil {
		return nil, nil, err
	}
	attestation, err := c.mint(ctx, doc, instanceKey, svid, challenge)
	if err != nil {
		return nil, nil, err
	}

	// token_endpoint is advertised by current attesters; fall back to the standard PF path so an older
	// discovery document still works from the host alone.
	tokenEndpoint := doc.TokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = c.baseURL + "/as/token.oauth2"
	}
	if err := c.checkSecure(tokenEndpoint); err != nil {
		return nil, nil, err
	}
	clientID, err := jwtSub(attestation)
	if err != nil {
		return nil, nil, err
	}
	// See WithChallengeAtToken: some attesters consume the challenge the moment the mint's instance
	// proof uses it, and reject a token request that presents the same value a second time. Against one
	// of those, only the mint gets the challenge.
	tokenChallenge := ""
	if c.challengeAtToken {
		tokenChallenge = challenge
	}

	if c.popMethod == PopMethodDpopCombined {
		// The attester challenge normally rides as the DPoP nonce; if the AS demands its own nonce
		// (400 use_dpop_nonce + DPoP-Nonce), retry once with the server's value.
		proof := func(nonce string) (string, error) {
			return NewDpopProofBuilder(instanceKey).Method(http.MethodPost).URI(tokenEndpoint).Nonce(nonce).Build()
		}
		initialNonce := tokenChallenge
		if initialNonce == "" {
			initialNonce = c.nonceFor(tokenEndpoint)
		}
		dpop, err := proof(initialNonce)
		if err != nil {
			return nil, nil, err
		}
		res, err := c.sendTokenRequest(ctx, tokenEndpoint, attestation, DpopHeader, dpop)
		if err != nil {
			return nil, nil, err
		}
		if nonce, ok := nonceChallenge(res.Status, res.Header, res.Body); ok {
			if dpop, err = proof(nonce); err != nil {
				return nil, nil, err
			}
			if res, err = c.sendTokenRequest(ctx, tokenEndpoint, attestation, DpopHeader, dpop); err != nil {
				return nil, nil, err
			}
		}
		response, err := parseTokenResponse(res)
		return response, instanceKey, err
	}

	// The PoP audience must be PF's configured issuer, which the attester advertises as pop_audience.
	// Falling back to the token endpoint URL only works when the dialed URL matches PF's issuer (no proxy
	// in between) — so prefer the advertised value.
	popAudience := doc.PopAudience
	if popAudience == "" {
		popAudience = tokenEndpoint
	}
	pop, err := NewPopBuilder(instanceKey).ClientID(clientID).Audience(popAudience).Challenge(tokenChallenge).Build()
	if err != nil {
		return nil, nil, err
	}
	res, err := c.sendTokenRequest(ctx, tokenEndpoint, attestation, PopHeader, pop)
	if err != nil {
		return nil, nil, err
	}
	response, err := parseTokenResponse(res)
	return response, instanceKey, err
}

// fetchChallenge asks the challenge endpoint for a challenge if one is advertised. No advertised
// endpoint means no challenge and no error. When one IS advertised, any failure to get a challenge
// fails the flow closed — unless WithRequireChallenge(false), which proceeds without one.
func (c *ClientAttestation) fetchChallenge(ctx context.Context, doc *discoveryDoc) (string, error) {
	if doc.ChallengeEndpoint == "" {
		return "", nil
	}
	if err := c.checkSecure(doc.ChallengeEndpoint); err != nil {
		return "", err
	}
	var body struct {
		AttestationChallenge string `json:"attestation_challenge"`
	}
	err := c.getJSON(ctx, http.MethodPost, doc.ChallengeEndpoint, nil, &body)
	if err == nil && body.AttestationChallenge == "" {
		err = &ClientAttestationError{Message: "challenge endpoint response has no attestation_challenge"}
	}
	if err != nil {
		if !c.requireChallenge {
			return "", nil
		}
		var caErr *ClientAttestationError
		if errors.As(err, &caErr) {
			return "", &ClientAttestationError{
				Message: "could not obtain an attestation challenge from " + doc.ChallengeEndpoint + ": " + caErr.Message,
				Status:  caErr.Status,
				Body:    caErr.Body,
			}
		}
		return "", &ClientAttestationError{
			Message: fmt.Sprintf("could not obtain an attestation challenge from %s: %v", doc.ChallengeEndpoint, err),
		}
	}
	return body.AttestationChallenge, nil
}

// mint builds the instance proof and exchanges evidence for a minted attestation. Evidence-first: the
// body carries no client_id; the attester maps the identity to a client.
func (c *ClientAttestation) mint(ctx context.Context, doc *discoveryDoc, instanceKey *SigningKeyPair, svid, challenge string) (string, error) {
	proofClaims := map[string]any{
		"aud": doc.EvidenceAudience,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
	}
	if challenge != "" {
		proofClaims["challenge"] = challenge
	}
	proof, err := instanceKey.signCompact(proofClaims, InstanceProofTyp, false)
	if err != nil {
		return "", err
	}

	body := map[string]any{
		"instance_key": instanceKey.PublicJWK(),
		"svid":         svid,
		"proof":        proof,
	}
	if len(c.authorizationDetails) > 0 {
		body["authorization_details"] = c.authorizationDetails
	}
	if len(c.operator) > 0 {
		// Asked for at mint time so the ATTESTER is what states the operator, rather than the client
		// asserting it about itself at the token endpoint.
		body["operator"] = c.operator
	}
	var response struct {
		Attestation string `json:"attestation"`
	}
	if err := c.checkSecure(doc.AttestationEndpoint); err != nil {
		return "", err
	}
	if err := c.getJSON(ctx, http.MethodPost, doc.AttestationEndpoint, body, &response); err != nil {
		return "", err
	}
	if response.Attestation == "" {
		return "", &ClientAttestationError{Message: "attester response contained no attestation"}
	}
	return response.Attestation, nil
}

// sendTokenRequest posts the client_credentials grant with the attestation header plus a
// proof-of-possession header — popHeaderName is PopHeader for dedicated PoP-JWT mode or DpopHeader
// for DPoP combined mode — and returns the raw response.
func (c *ClientAttestation) sendTokenRequest(ctx context.Context, endpoint, attestation, popHeaderName, pop string) (*httpResult, error) {
	values := url.Values{"grant_type": {"client_credentials"}}
	if len(c.operator) > 0 {
		// Extension parameter, sent only when configured. The attestation is the authoritative carrier
		// (the attester signed it); this repeats it on the wire for an AS that wants it without parsing
		// the attestation.
		op, err := compactSortedJSON(c.operator)
		if err != nil {
			return nil, err
		}
		values.Set("operator", op)
	}
	form := values.Encode()
	return doRequest(ctx, c.httpClient, http.MethodPost, endpoint, map[string]string{
		"Content-Type":    "application/x-www-form-urlencoded",
		"Accept":          "application/json",
		AttestationHeader: attestation,
		popHeaderName:     pop,
	}, []byte(form), defaultMaxResponseBytes)
}

// compactSortedJSON renders v as compact JSON with object keys sorted (encoding/json sorts map keys),
// without HTML escaping and with every non-ASCII character escaped as \uXXXX (a surrogate pair above
// U+FFFF) — the same bytes as Python's json.dumps(v, separators=(",", ":"), sort_keys=True) and the
// TypeScript and Java ports.
func compactSortedJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", &ClientAttestationError{Message: fmt.Sprintf("operator is not JSON-serialisable: %v", err)}
	}
	var out strings.Builder
	for _, r := range strings.TrimRight(buf.String(), "\n") {
		switch {
		case r < 0x80:
			out.WriteRune(r)
		case r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&out, "\\u%04x\\u%04x", hi, lo)
		default:
			fmt.Fprintf(&out, "\\u%04x", r)
		}
	}
	return out.String(), nil
}

// parseTokenResponse turns a token endpoint response into a tokenResponse, or a *ClientAttestationError.
func parseTokenResponse(res *httpResult) (*tokenResponse, error) {
	raw := res.Body
	// The token endpoint's error body (RFC 6749 §5.2 JSON) is carried in full — callers read Body.
	if !res.ok() {
		return nil, &ClientAttestationError{
			Message: fmt.Sprintf("token endpoint returned HTTP %d", res.Status),
			Status:  res.Status,
			Body:    string(raw),
		}
	}
	var parsed tokenResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, &ClientAttestationError{Message: "unparseable token endpoint response", Body: string(raw)}
	}
	if parsed.AccessToken == "" {
		return nil, &ClientAttestationError{Message: "token endpoint returned no access_token", Body: string(raw)}
	}
	return &parsed, nil
}

// getJSON performs an HTTP request with an optional JSON body and decodes a JSON response into out.
func (c *ClientAttestation) getJSON(ctx context.Context, method, target string, jsonBody any, out any) error {
	headers := map[string]string{"Accept": "application/json"}
	var data []byte
	if jsonBody != nil {
		var err error
		if data, err = json.Marshal(jsonBody); err != nil {
			return err
		}
		headers["Content-Type"] = "application/json"
	}
	res, err := doRequest(ctx, c.httpClient, method, target, headers, data, defaultMaxResponseBytes)
	if err != nil {
		return err
	}
	if len(res.Body) == 0 {
		out = nil // an empty 2xx body leaves out untouched
	}
	return decodeJSONOK(res, method+" "+target, out)
}

// ClientAttestationError is returned when a step in the flow fails. Status and Body are set for HTTP
// failures.
type ClientAttestationError struct {
	Message string
	Status  int
	Body    string
}

func (e *ClientAttestationError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("%s (HTTP %d): %s", e.Message, e.Status, e.Body)
	}
	return e.Message
}

// normalizeBaseURL turns a bare host into an https base URL and strips a trailing slash. A host that
// already carries a scheme is kept as-is (so in-cluster http://… works).
func normalizeBaseURL(pfHost string) (string, error) {
	host := strings.TrimRight(strings.TrimSpace(pfHost), "/")
	if host == "" {
		return "", fmt.Errorf("pfHost is required")
	}
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	return host, nil
}

// checkSecure refuses a non-https URL unless its host is loopback (localhost, 127.0.0.1, ::1) or
// WithAllowInsecure() was given.
func (c *ClientAttestation) checkSecure(target string) error {
	if c.allowInsecure {
		return nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return &ClientAttestationError{Message: fmt.Sprintf("invalid URL %q: %v", target, err)}
	}
	if strings.EqualFold(u.Scheme, "https") || isLoopbackHost(u.Hostname()) {
		return nil
	}
	return &ClientAttestationError{Message: fmt.Sprintf(
		"refusing insecure URL %s: https is required for non-loopback hosts (use WithAllowInsecure() to override)", target)}
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}

// jwtSub reads the "sub" claim (the client id) from a compact JWT without verifying it.
func jwtSub(compactJWT string) (string, error) {
	parts := strings.Split(compactJWT, ".")
	if len(parts) < 2 {
		return "", &ClientAttestationError{Message: "minted attestation is not a valid JWT"}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", &ClientAttestationError{Message: "minted attestation payload is not valid base64url"}
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", &ClientAttestationError{Message: "minted attestation payload is not valid JSON"}
	}
	if claims.Sub == "" {
		return "", &ClientAttestationError{Message: "minted attestation has no sub (client id)"}
	}
	return claims.Sub, nil
}
