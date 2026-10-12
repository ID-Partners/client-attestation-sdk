package clientattestation

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Attester profiles: the part of the flow that differs from one attester to the next.
//
// The draft says what a Client Attestation, its PoP and the challenge endpoint look like, and how they are
// presented at the token endpoint. It does not say how a workload gets an attestation from its attester.
// That part — where the attester's endpoints are listed, what the mint request looks like, how the instance
// key is proven, and what comes back — is an AttesterProfile. ClientAttestation and
// AttestationIssuanceClient use PingFederateProfile unless told otherwise, which is exactly the behaviour
// of earlier releases. See docs/attester-profiles.md.

// AttesterMetadata says where the attester lives and what it expects.
type AttesterMetadata struct {
	// EvidenceAudience is the audience the workload's platform identity is requested for, and the
	// instance proof's aud. Required.
	EvidenceAudience string `json:"evidence_audience,omitempty"`
	// AttestationEndpoint is where the mint request goes.
	AttestationEndpoint string `json:"attestation_endpoint,omitempty"`
	// ChallengeEndpoint is the draft's challenge endpoint, if the attester issues challenges.
	ChallengeEndpoint string `json:"challenge_endpoint,omitempty"`
	// TokenEndpoint is the authorization server's token endpoint. A profile fills in its own fallback.
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	// PopAudience is the Client Attestation PoP aud (the AS issuer); it falls back to the token endpoint.
	PopAudience string `json:"pop_audience,omitempty"`
	// Document is the raw discovery document, when there was one.
	Document map[string]any `json:"-"`
}

// MintRequest is everything a profile needs to mint one attestation.
type MintRequest struct {
	// InstanceKey is the fresh key the attestation will be bound to (its cnf).
	InstanceKey *SigningKeyPair
	// Evidence is the workload's platform identity token (a JWT-SVID or equivalent).
	Evidence string
	// Challenge is the attester-issued challenge, or "".
	Challenge string
	// ClientID is set by AttestationIssuanceClient; "" in the evidence-first one-call flow, where the
	// attester maps the identity to a client.
	ClientID string
	// AuthorizationDetails is the optional RFC 9396 access request.
	AuthorizationDetails []map[string]any
	// Operator is the optional operator object (who answers for this workload).
	Operator map[string]any
}

// Sign signs claims as a compact JWS with the instance key under header typ (no jwk header). typ may not
// be one the SDK's own credentials use (AttestationTyp, PopTyp, DpopTyp): a profile could otherwise have
// the instance key sign a Client Attestation PoP or DPoP proof with claims of its choosing.
func (r *MintRequest) Sign(claims map[string]any, typ string) (string, error) {
	if reservedTyp(typ) {
		return "", fmt.Errorf("typ %q is reserved for the SDK's own credentials; a profile cannot sign it with the instance key", typ)
	}
	return r.InstanceKey.signCompact(claims, typ, false)
}

// reservedTyp reports whether typ names one of the SDK's own credential types, compared as RFC 7515
// section 4.1.9 says a verifier may: case-insensitively, with or without the "application/" prefix.
func reservedTyp(typ string) bool {
	t := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(typ)), "application/")
	return t == AttestationTyp || t == PopTyp || t == DpopTyp
}

// InstanceProof is a proof of possession of the instance key: {aud, jti, iat[, challenge]} signed with it
// under header typ.
func (r *MintRequest) InstanceProof(typ, audience string) (string, error) {
	claims := map[string]any{"aud": audience, "jti": uuid.NewString(), "iat": time.Now().Unix()}
	if r.Challenge != "" {
		claims["challenge"] = r.Challenge
	}
	return r.Sign(claims, typ)
}

// MintResult is what the attester returned: the attestation, and its lifetime in seconds if it said (0
// if not).
type MintResult struct {
	Attestation string
	ExpiresIn   int64
}

// AttesterTransport is how a profile talks to the attester. The client supplies it, so every call shares
// the client's HTTP client, timeout, redirect and size limits, https rule and logging (http.failed).
type AttesterTransport interface {
	// RequestJSON sends body (as JSON, if non-nil) and decodes the JSON response into out. step names the
	// call in logs ("discover", "mint"). A non-2xx status or a body that is not JSON is an error; an empty
	// 2xx body leaves out untouched.
	RequestJSON(ctx context.Context, step, method, url string, body any, out any) error
}

// AttesterProfile is the attester-specific part of the flow. Implement it and pass it with
// WithAttesterProfile (or AttestationIssuanceClient.Profile).
//
// Experimental (see docs/api.md): new in 0.4.0 and fitted to one real attester so far; a method added to
// it would break custom profiles. AttesterTransport, MintRequest and MintResult are Experimental with it.
type AttesterProfile interface {
	// Discover finds the attester's endpoints. It is called once per client and cached, and not called
	// at all when the caller passes WithAttesterMetadata.
	Discover(ctx context.Context, t AttesterTransport, attesterURL string) (*AttesterMetadata, error)
	// Mint exchanges the evidence and a proof of the instance key for an attestation.
	Mint(ctx context.Context, t AttesterTransport, metadata *AttesterMetadata, req *MintRequest) (*MintResult, error)
}

// PingFederate profile conventions.
const (
	// PingFederateWellKnownPath is the PingFederate profile's discovery document path.
	PingFederateWellKnownPath = "/.well-known/client-attester"
	// PingFederateDefaultTokenPath is the token endpoint used when discovery names none.
	PingFederateDefaultTokenPath = "/as/token.oauth2"
)

// wellKnownPath is the attester discovery document path (kept for existing callers in this package).
const wellKnownPath = PingFederateWellKnownPath

// PingFederateProfile is the attester this SDK was built against, and the default.
//
//   - Discovery: GET {attesterURL}/.well-known/client-attester, a JSON object with evidence_audience,
//     attestation_endpoint, challenge_endpoint, token_endpoint and pop_audience. With no token_endpoint,
//     {attesterURL}/as/token.oauth2.
//   - Mint: POST attestation_endpoint with JSON {[client_id,] instance_key, svid, proof
//     [, authorization_details][, operator]}, where proof is {aud: evidence_audience, jti, iat
//     [, challenge]} signed by the instance key with typ oauth-attestation-instance-proof+jwt
//     (InstanceProofTyp). The response is {"attestation": ..., "expires_in": ...}.
type PingFederateProfile struct{}

// Discover fetches the PingFederate discovery document.
func (PingFederateProfile) Discover(ctx context.Context, t AttesterTransport, attesterURL string) (*AttesterMetadata, error) {
	if attesterURL == "" {
		return nil, &ClientAttestationError{Message: "attesterURL is required for discovery"}
	}
	var doc map[string]any
	if err := t.RequestJSON(ctx, "discover", http.MethodGet, attesterURL+PingFederateWellKnownPath, nil, &doc); err != nil {
		return nil, err
	}
	str := func(key string) string {
		s, _ := doc[key].(string)
		return s
	}
	md := &AttesterMetadata{
		EvidenceAudience:    str("evidence_audience"),
		AttestationEndpoint: str("attestation_endpoint"),
		ChallengeEndpoint:   str("challenge_endpoint"),
		TokenEndpoint:       str("token_endpoint"),
		PopAudience:         str("pop_audience"),
		Document:            doc,
	}
	// Mint can't work without it, so fail here, before the client fetches evidence or a challenge.
	if md.AttestationEndpoint == "" {
		return nil, &ClientAttestationError{Message: "attester discovery document has no attestation_endpoint"}
	}
	// token_endpoint is advertised by current attesters; fall back to the standard PF path so an older
	// discovery document still works from the host alone.
	if md.TokenEndpoint == "" {
		md.TokenEndpoint = attesterURL + PingFederateDefaultTokenPath
	}
	return md, nil
}

// Mint sends the PingFederate mint request.
func (PingFederateProfile) Mint(ctx context.Context, t AttesterTransport, metadata *AttesterMetadata, req *MintRequest) (*MintResult, error) {
	if metadata.AttestationEndpoint == "" {
		return nil, &ClientAttestationError{Message: "attester discovery document has no attestation_endpoint"}
	}
	proof, err := req.InstanceProof(InstanceProofTyp, metadata.EvidenceAudience)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"instance_key": req.InstanceKey.PublicJWK(),
		"svid":         req.Evidence,
		"proof":        proof,
	}
	if req.ClientID != "" {
		body["client_id"] = req.ClientID
	}
	if len(req.AuthorizationDetails) > 0 {
		body["authorization_details"] = req.AuthorizationDetails
	}
	if len(req.Operator) > 0 {
		// Asked for at mint time so the ATTESTER is what states the operator, rather than the client
		// asserting it about itself at the token endpoint.
		body["operator"] = req.Operator
	}
	var response struct {
		Attestation string `json:"attestation"`
		ExpiresIn   any    `json:"expires_in"`
	}
	if err := t.RequestJSON(ctx, "mint", http.MethodPost, metadata.AttestationEndpoint, body, &response); err != nil {
		return nil, err
	}
	if response.Attestation == "" {
		return nil, &ClientAttestationError{Message: "attester response contained no attestation"}
	}
	expiresIn, _ := response.ExpiresIn.(float64)
	return &MintResult{Attestation: response.Attestation, ExpiresIn: int64(expiresIn)}, nil
}
