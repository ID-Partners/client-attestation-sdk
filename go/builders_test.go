package clientattestation

import (
	"strings"
	"testing"
)

func TestAttestationExplicitTimesAndOptionalClaims(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	details := []map[string]any{{"type": "openid_credential"}}
	workload := map[string]any{"platform": "test"}
	attestation, err := NewClientAttestationBuilder(attester, attesterIss).
		ClientID(testClientID).
		ConfirmationJWK(instance.PublicJWK()).
		IssuedAt(1700000000).
		ExpiresAt(1700000300).
		AuthorizationDetails(details).
		Workload(workload).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	_, claims := verify(t, attestation, publicKey(t, attester))
	if claims["iat"] != float64(1700000000) {
		t.Errorf("iat = %v, want 1700000000", claims["iat"])
	}
	if claims["exp"] != float64(1700000300) {
		t.Errorf("exp = %v, want 1700000300", claims["exp"])
	}
	ad, ok := claims["authorization_details"].([]any)
	if !ok || len(ad) != 1 {
		t.Errorf("authorization_details = %v", claims["authorization_details"])
	}
	wl, ok := claims["workload"].(map[string]any)
	if !ok || wl["platform"] != "test" {
		t.Errorf("workload = %v", claims["workload"])
	}
}

func TestAttestationOperatorClaimMirrorsMayActShape(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := NewClientAttestationBuilder(attester, attesterIss).
		ClientID(testClientID).
		ConfirmationKey(instance).
		ExpiresIn(300).
		Operator("ops-team@example.com", "https://op.example.com").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	_, claims := verify(t, attestation, publicKey(t, attester))
	op, ok := claims["operator"].(map[string]any)
	if !ok {
		t.Fatalf("operator = %v, want map", claims["operator"])
	}
	if op["sub"] != "ops-team@example.com" || op["iss"] != "https://op.example.com" {
		t.Errorf("operator = %v, want {sub: ops-team@example.com, iss: https://op.example.com}", op)
	}
	// Top-level, NOT tucked inside workload: workload describes the running software, the
	// operator is an accountability statement about who answers for it.
	if wl, ok := claims["workload"].(map[string]any); ok {
		if _, present := wl["operator"]; present {
			t.Error("operator must not be nested inside workload")
		}
	}
}

func TestAttestationOperatorIssuerIsOptional(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := NewClientAttestationBuilder(attester, attesterIss).
		ClientID(testClientID).
		ConfirmationKey(instance).
		ExpiresIn(300).
		Operator("ops-team@example.com", "").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	_, claims := verify(t, attestation, publicKey(t, attester))
	op, ok := claims["operator"].(map[string]any)
	if !ok {
		t.Fatalf("operator = %v, want map", claims["operator"])
	}
	if op["sub"] != "ops-team@example.com" {
		t.Errorf("operator.sub = %v, want ops-team@example.com", op["sub"])
	}
	if _, present := op["iss"]; present {
		t.Error("operator.iss must be omitted when issuer is blank")
	}
}

func TestAttestationOmitsOperatorWhenNotSet(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := NewClientAttestationBuilder(attester, attesterIss).
		ClientID(testClientID).
		ConfirmationKey(instance).
		ExpiresIn(300).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	_, claims := verify(t, attestation, publicKey(t, attester))
	if _, present := claims["operator"]; present {
		t.Error("operator must be omitted when Operator() was never called")
	}
}

func TestAttestationOperatorRequiresASubject(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewClientAttestationBuilder(attester, attesterIss).
		ClientID(testClientID).
		ConfirmationKey(instance).
		ExpiresIn(300).
		Operator("", "https://op.example.com").
		Build()
	if err == nil || !strings.Contains(err.Error(), "operator sub") {
		t.Fatalf("err = %v, want an error mentioning %q", err, "operator sub")
	}
}

func TestAttestationExpiresInFromExplicitIssuedAt(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := NewClientAttestationBuilder(attester, attesterIss).
		ClientID(testClientID).
		ConfirmationKey(instance).
		IssuedAt(1700000000).
		ExpiresIn(600).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	_, claims := verify(t, attestation, publicKey(t, attester))
	if claims["exp"] != float64(1700000600) {
		t.Errorf("exp = %v, want iat+600", claims["exp"])
	}
}

func TestAttestationBuilderMissingFields(t *testing.T) {
	attester, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]*ClientAttestationBuilder{
		"missing issuer": NewClientAttestationBuilder(attester, "  ").
			ClientID(testClientID).ConfirmationKey(instance).ExpiresIn(300),
		"missing client_id": NewClientAttestationBuilder(attester, attesterIss).
			ConfirmationKey(instance).ExpiresIn(300),
		"missing cnf": NewClientAttestationBuilder(attester, attesterIss).
			ClientID(testClientID).ExpiresIn(300),
		"missing expiry": NewClientAttestationBuilder(attester, attesterIss).
			ClientID(testClientID).ConfirmationKey(instance),
	}
	for name, b := range cases {
		if _, err := b.Build(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestPopExplicitJtiIatAndChallenge(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	pop, err := NewPopBuilder(instance).
		Audience(testAudience).
		Challenge("nonce-123").
		JwtID("jti-1").
		IssuedAt(1700000000).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	_, claims := verify(t, pop, publicKey(t, instance))
	if claims["jti"] != "jti-1" {
		t.Errorf("jti = %v", claims["jti"])
	}
	if claims["iat"] != float64(1700000000) {
		t.Errorf("iat = %v", claims["iat"])
	}
	if claims["challenge"] != "nonce-123" {
		t.Errorf("challenge = %v", claims["challenge"])
	}
	if _, ok := claims["iss"]; ok {
		t.Error("iss must be omitted when no client_id is set")
	}
}

func TestPopRequiresAudience(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPopBuilder(instance).Build(); err == nil {
		t.Error("expected an error for a missing audience")
	}
}

func TestDpopExplicitJtiIatNonceAndMethod(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	dpop, err := NewDpopProofBuilder(instance).
		Method(""). // blank is ignored; htm stays POST
		Method("GET").
		URI(tokenEndpoint).
		Nonce("srv-nonce").
		JwtID("jti-2").
		IssuedAt(1700000000).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	_, claims := verify(t, dpop, publicKey(t, instance))
	if claims["htm"] != "GET" {
		t.Errorf("htm = %v", claims["htm"])
	}
	if claims["jti"] != "jti-2" {
		t.Errorf("jti = %v", claims["jti"])
	}
	if claims["iat"] != float64(1700000000) {
		t.Errorf("iat = %v", claims["iat"])
	}
	if claims["nonce"] != "srv-nonce" {
		t.Errorf("nonce = %v", claims["nonce"])
	}
}

func TestDpopRequiresURI(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDpopProofBuilder(instance).Build(); err == nil {
		t.Error("expected an error for a missing htu")
	}
}

func TestCredentialRequiresAttestationJWT(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClientAttestationCredential("   ", instance); err == nil {
		t.Error("expected an error for a blank attestation JWT")
	}
}

func TestCredentialHeaderErrorsPropagate(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := NewClientAttestationCredential("a.b.c", instance)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cred.PopHeaders(testClientID, "", ""); err == nil ||
		!strings.Contains(err.Error(), "audience") {
		t.Errorf("PopHeaders without audience: err = %v", err)
	}
	if _, err := cred.DpopHeaders("POST", "", ""); err == nil ||
		!strings.Contains(err.Error(), "htu") {
		t.Errorf("DpopHeaders without uri: err = %v", err)
	}
}
