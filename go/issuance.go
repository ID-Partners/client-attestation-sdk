package clientattestation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
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
//
// Experimental (see docs/api.md): it calls a PingFederate demo issuance servlet (/federation/attestation)
// whose protocol is not standardised.
type AttestationIssuanceClient struct {
	Endpoint       string // .../federation/attestation
	ClientID       string
	AttesterIssuer string // the SVID audience AND the instance-proof aud
	Source         SvidSource
	InstanceKey    *SigningKeyPair
	HTTPClient     *http.Client
	// Profile sets the mint protocol; nil means PingFederateProfile. The endpoint is given directly, so
	// the profile's Discover is not used. See docs/attester-profiles.md.
	Profile AttesterProfile
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
	profile := c.Profile
	if profile == nil {
		profile = PingFederateProfile{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	minted, err := profile.Mint(ctx, issuanceTransport{safeClient(c.HTTPClient, 20*time.Second)},
		&AttesterMetadata{EvidenceAudience: c.AttesterIssuer, AttestationEndpoint: c.Endpoint},
		&MintRequest{
			InstanceKey:          c.InstanceKey,
			Evidence:             svid,
			Challenge:            challenge,
			ClientID:             c.ClientID,
			AuthorizationDetails: authorizationDetails,
		})
	if err != nil {
		return nil, err
	}
	return &IssuedAttestation{Attestation: minted.Attestation, ExpiresIn: minted.ExpiresIn, InstanceKey: c.InstanceKey}, nil
}

// issuanceTransport is the issuance endpoint's AttesterTransport: a non-2xx answer is an *IssuanceError.
type issuanceTransport struct{ client *http.Client }

func (t issuanceTransport) RequestJSON(ctx context.Context, _ string, method, target string, body any, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	res, err := doRequest(ctx, t.client, method, target, map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}, payload, defaultMaxResponseBytes)
	if err != nil {
		return err
	}
	if !res.ok() {
		return &IssuanceError{Status: res.Status, Body: string(res.Body)}
	}
	return decodeJSONOK(res, method+" "+target, out)
}
