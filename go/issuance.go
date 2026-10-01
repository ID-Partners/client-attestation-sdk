package clientattestation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// InstanceProofTyp is the typ of the instance-key proof presented at the issuance endpoint
// (matches the server's InstanceKeyProofValidator.TYP).
const InstanceProofTyp = "oauth-attestation-instance-proof+jwt"

// IssuanceError is returned when the issuance endpoint rejects the request (non-2xx).
type IssuanceError struct {
	Status int
	Body   string
}

func (e *IssuanceError) Error() string {
	return fmt.Sprintf("attestation issuance failed: HTTP %d: %s", e.Status, e.Body)
}

// IssuedAttestation is a minted Client Attestation plus the instance key it is bound to.
type IssuedAttestation struct {
	Attestation string
	ExpiresIn   int64
	InstanceKey *SigningKeyPair
}

// Pop builds a fresh Client Attestation PoP for the token endpoint, signed by the bound instance key.
// challenge is the optional server challenge (pass "" to omit).
func (i *IssuedAttestation) Pop(audience, clientID, challenge string) (string, error) {
	b := NewPopBuilder(i.InstanceKey).Audience(audience).Challenge(challenge)
	if clientID != "" {
		b = b.ClientID(clientID)
	}
	return b.Build()
}

// Dpop builds a fresh DPoP proof (RFC 9449) for attestation combined mode (PoP method
// dpop_combined), signed by the bound instance key. method is the token request HTTP method (DPoP
// "htm"); uri is the token endpoint (DPoP "htu"); challenge is the optional server challenge (DPoP
// "nonce", pass "" to omit).
func (i *IssuedAttestation) Dpop(method, uri, challenge string) (string, error) {
	return NewDpopProofBuilder(i.InstanceKey).Method(method).URI(uri).Nonce(challenge).Build()
}

// AttestationIssuanceClient bootstraps a Client Attestation for a workload from its SPIFFE JWT-SVID by
// calling the issuance endpoint (POST /federation/attestation). The inverse of ClientAttestationBuilder:
// the AS mints the attestation and binds it to the workload's instance key.
type AttestationIssuanceClient struct {
	Endpoint       string // .../federation/attestation
	ClientID       string
	AttesterIssuer string // the SVID audience AND the instance-proof aud
	Source         SvidSource
	InstanceKey    *SigningKeyPair
	HTTPClient     *http.Client
}

// NewAttestationIssuanceClient generates a fresh ES256 instance key and returns a ready client.
func NewAttestationIssuanceClient(endpoint, clientID, attesterIssuer string, source SvidSource) (*AttestationIssuanceClient, error) {
	key, err := Generate("ES256")
	if err != nil {
		return nil, err
	}
	return &AttestationIssuanceClient{
		Endpoint:       strings.TrimRight(endpoint, "/"),
		ClientID:       clientID,
		AttesterIssuer: attesterIssuer,
		Source:         source,
		InstanceKey:    key,
		HTTPClient:     &http.Client{Timeout: 20 * time.Second},
	}, nil
}

// Bootstrap fetches the SVID, proves possession of the instance key, and exchanges them for a minted
// attestation. authorizationDetails and challenge are optional (pass nil / "").
func (c *AttestationIssuanceClient) Bootstrap(authorizationDetails []map[string]any, challenge string) (*IssuedAttestation, error) {
	svid, err := c.Source.Fetch(c.AttesterIssuer)
	if err != nil {
		return nil, err
	}

	proofClaims := map[string]any{"aud": c.AttesterIssuer, "jti": uuid.NewString(), "iat": time.Now().Unix()}
	if challenge != "" {
		proofClaims["challenge"] = challenge
	}
	proof, err := c.InstanceKey.signCompact(proofClaims, InstanceProofTyp, false)
	if err != nil {
		return nil, err
	}

	body := map[string]any{
		"client_id":    c.ClientID,
		"instance_key": c.InstanceKey.PublicJWK(),
		"svid":         svid,
		"proof":        proof,
	}
	if len(authorizationDetails) > 0 {
		body["authorization_details"] = authorizationDetails
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	client := safeClient(c.HTTPClient, 20*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := doRequest(ctx, client, http.MethodPost, c.Endpoint, map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}, payload, defaultMaxResponseBytes)
	if err != nil {
		return nil, err
	}
	if !res.ok() {
		return nil, &IssuanceError{Status: res.Status, Body: string(res.Body)}
	}
	var out struct {
		Attestation string `json:"attestation"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := decodeJSONOK(res, "POST "+c.Endpoint, &out); err != nil {
		return nil, err
	}
	return &IssuedAttestation{Attestation: out.Attestation, ExpiresIn: out.ExpiresIn, InstanceKey: c.InstanceKey}, nil
}
