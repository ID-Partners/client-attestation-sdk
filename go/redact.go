package clientattestation

import (
	"fmt"
	"log/slog"
)

// Default string forms for the types that hold credentials. fmt's %v, %+v and %#v, and slog's text and
// JSON handlers, would otherwise print the access token, attestation, evidence, challenge or vault token
// they carry. Each prints its non-secret fields and replaces a secret with "<redacted:N bytes>", the same
// form the logging backstop uses.

// redacted is the printed form of a secret: "" stays visible as "", anything else is only its length.
func redacted(s string) string {
	if s == "" {
		return `""`
	}
	return fmt.Sprintf("<redacted:%d bytes>", len(s))
}

// String prints the attester base URL and PoP method, never the cached token or DPoP nonces.
func (c *ClientAttestation) String() string {
	return fmt.Sprintf("ClientAttestation{baseURL: %q, popMethod: %q}", c.baseURL, c.popMethod)
}

// GoString is String, so %#v does not print the cached token either.
func (c *ClientAttestation) GoString() string { return c.String() }

// String prints the vault address and key, never the vault token.
func (s *OpenBaoTransitSigner) String() string {
	return fmt.Sprintf("OpenBaoTransitSigner{base: %q, keyName: %q, algorithm: %q, keyID: %q}",
		s.base, s.keyName, s.algorithm, s.keyID)
}

// GoString is String, so %#v does not print the vault token either.
func (s *OpenBaoTransitSigner) GoString() string { return s.String() }

// String prints the attestation JWT redacted.
func (c *ClientAttestationCredential) String() string {
	return fmt.Sprintf("ClientAttestationCredential{attestationJWT: %s}", redacted(c.attestationJWT))
}

// GoString is String, so %#v does not print the attestation either.
func (c *ClientAttestationCredential) GoString() string { return c.String() }

// String prints the client ID and redacts the evidence and the challenge.
func (r MintRequest) String() string {
	return fmt.Sprintf("MintRequest{ClientID: %q, Evidence: %s, Challenge: %s}",
		r.ClientID, redacted(r.Evidence), redacted(r.Challenge))
}

// GoString is String, so %#v does not print the evidence either.
func (r MintRequest) GoString() string { return r.String() }

// LogValue is String, so slog's JSON handler does not print the exported Evidence and Challenge fields.
func (r MintRequest) LogValue() slog.Value { return slog.StringValue(r.String()) }

// String prints the lifetime and redacts the attestation.
func (r MintResult) String() string {
	return fmt.Sprintf("MintResult{Attestation: %s, ExpiresIn: %d}", redacted(r.Attestation), r.ExpiresIn)
}

// GoString is String, so %#v does not print the attestation either.
func (r MintResult) GoString() string { return r.String() }

// LogValue is String, so slog's JSON handler does not print the exported Attestation field.
func (r MintResult) LogValue() slog.Value { return slog.StringValue(r.String()) }

// String prints the lifetime and redacts the attestation.
func (i IssuedAttestation) String() string {
	return fmt.Sprintf("IssuedAttestation{Attestation: %s, ExpiresIn: %d}", redacted(i.Attestation), i.ExpiresIn)
}

// GoString is String, so %#v does not print the attestation either.
func (i IssuedAttestation) GoString() string { return i.String() }

// LogValue is String, so slog's JSON handler does not print the exported Attestation field.
func (i IssuedAttestation) LogValue() slog.Value { return slog.StringValue(i.String()) }

// String redacts the SVID.
func (s StaticSvidSource) String() string {
	return fmt.Sprintf("StaticSvidSource{SVID: %s}", redacted(s.SVID))
}

// GoString is String, so %#v does not print the SVID either.
func (s StaticSvidSource) GoString() string { return s.String() }

// LogValue is String, so slog's JSON handler does not print the exported SVID field.
func (s StaticSvidSource) LogValue() slog.Value { return slog.StringValue(s.String()) }
