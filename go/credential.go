package clientattestation

// HTTP header names carried at the token endpoint.
const (
	AttestationHeader = "OAuth-Client-Attestation"
	PopHeader         = "OAuth-Client-Attestation-PoP"
	DpopHeader        = "DPoP"
)

// PoP method names: which proof-of-possession the client sends alongside the attestation.
const (
	// PopMethodAttestationPopJWT sends a dedicated OAuth-Client-Attestation-PoP JWT. The default.
	PopMethodAttestationPopJWT = "attestation_pop_jwt"
	// PopMethodDpopCombined sends a DPoP proof (RFC 9449) under the DPoP header instead, letting
	// the instance key double as a DPoP key.
	PopMethodDpopCombined = "dpop_combined"
)

// ClientAttestationCredential is the Attester-issued attestation JWT plus the
// instance key it is bound to. It produces the token-request headers — dedicated
// PoP-JWT mode or DPoP combined mode — minting a fresh proof of possession each
// call.
type ClientAttestationCredential struct {
	attestationJWT string
	instanceKey    *SigningKeyPair
}

// NewClientAttestationCredential wraps an attestation JWT and its instance key.
func NewClientAttestationCredential(attestationJWT string, instanceKey *SigningKeyPair) (*ClientAttestationCredential, error) {
	jwt, err := requireText(attestationJWT, "attestation_jwt")
	if err != nil {
		return nil, err
	}
	return &ClientAttestationCredential{attestationJWT: jwt, instanceKey: instanceKey}, nil
}

// PopHeaders returns the headers for dedicated PoP-JWT mode
// (PoP method attestation_pop_jwt): OAuth-Client-Attestation + OAuth-Client-Attestation-PoP.
// clientID becomes the PoP "iss" (pass "" to omit); audience is required;
// challenge is optional (pass "" to omit).
func (c *ClientAttestationCredential) PopHeaders(clientID, audience, challenge string) (map[string]string, error) {
	pop, err := NewPopBuilder(c.instanceKey).
		ClientID(clientID).
		Audience(audience).
		Challenge(challenge).
		Build()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		AttestationHeader: c.attestationJWT,
		PopHeader:         pop,
	}, nil
}

// DpopHeaders returns the headers for DPoP combined mode
// (PoP method dpop_combined): OAuth-Client-Attestation + DPoP (no PoP header).
// method is the token request HTTP method (DPoP "htm"); uri is the token endpoint
// (DPoP "htu"), required; challenge is the optional server challenge (DPoP
// "nonce", pass "" to omit).
func (c *ClientAttestationCredential) DpopHeaders(method, uri, challenge string) (map[string]string, error) {
	dpop, err := NewDpopProofBuilder(c.instanceKey).
		Method(method).
		URI(uri).
		Nonce(challenge).
		Build()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		AttestationHeader: c.attestationJWT,
		DpopHeader:        dpop,
	}, nil
}
