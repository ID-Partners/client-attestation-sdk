import jwt
import pytest

from client_attestation_sdk import (
    ClientAttestationBuilder,
    DpopProofBuilder,
    PopBuilder,
    SigningKeyPair,
)

ATTESTER_ISS = "https://attester.example.com"
CLIENT_ID = "https://rp.example.com"
AUDIENCE = "https://as.example.com"
TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2"


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def test_attestation_explicit_timestamps_and_optional_claims():
    attester = SigningKeyPair.generate("ES256")
    instance = SigningKeyPair.generate("ES256")
    details = [{"type": "openid_credential", "credential_configuration_id": "pid"}]
    workload = {"platform": "gcp", "pool": "agents"}
    attestation = (
        ClientAttestationBuilder(attester, ATTESTER_ISS)
        .client_id(CLIENT_ID)
        .confirmation_key(instance)
        .issued_at(1000)
        .expires_at(2000)
        .authorization_details(details)
        .workload(workload)
        .build()
    )
    claims = _claims(attestation)
    assert claims["iat"] == 1000
    assert claims["exp"] == 2000
    assert claims["authorization_details"] == details
    assert claims["workload"] == workload


def test_attestation_operator_claim_mirrors_may_act_shape():
    """The operator names who ANSWERS for the client, distinct from the client (`sub`) and from
    any principal it acts for. Shaped like RFC 8693 `may_act` so an AS can lift it straight in."""
    attester = SigningKeyPair.generate("ES256")
    instance = SigningKeyPair.generate("ES256")
    attestation = (
        ClientAttestationBuilder(attester, ATTESTER_ISS)
        .client_id(CLIENT_ID)
        .confirmation_key(instance)
        .expires_in(300)
        .operator("ops-team@example.com", "https://op.example.com")
        .build()
    )
    claims = _claims(attestation)
    assert claims["operator"] == {"sub": "ops-team@example.com", "iss": "https://op.example.com"}
    # Top-level, NOT tucked inside workload: workload describes the running software, the
    # operator is an accountability statement about who answers for it.
    assert "operator" not in claims.get("workload", {})


def test_attestation_operator_issuer_is_optional():
    attester = SigningKeyPair.generate("ES256")
    instance = SigningKeyPair.generate("ES256")
    attestation = (
        ClientAttestationBuilder(attester, ATTESTER_ISS)
        .client_id(CLIENT_ID)
        .confirmation_key(instance)
        .expires_in(300)
        .operator("ops-team@example.com")
        .build()
    )
    assert _claims(attestation)["operator"] == {"sub": "ops-team@example.com"}


def test_attestation_omits_operator_when_not_set():
    """Every existing caller must be byte-for-byte unaffected."""
    attester = SigningKeyPair.generate("ES256")
    instance = SigningKeyPair.generate("ES256")
    attestation = (
        ClientAttestationBuilder(attester, ATTESTER_ISS)
        .client_id(CLIENT_ID)
        .confirmation_key(instance)
        .expires_in(300)
        .build()
    )
    assert "operator" not in _claims(attestation)


def test_attestation_operator_requires_a_subject():
    attester = SigningKeyPair.generate("ES256")
    with pytest.raises(ValueError):
        ClientAttestationBuilder(attester, ATTESTER_ISS).operator("", "https://op.example.com")


def test_attestation_expires_in_is_relative_to_issued_at():
    attester = SigningKeyPair.generate("ES256")
    instance = SigningKeyPair.generate("ES256")
    attestation = (
        ClientAttestationBuilder(attester, ATTESTER_ISS)
        .client_id(CLIENT_ID)
        .confirmation_key(instance)
        .issued_at(1000)
        .expires_in(300)
        .build()
    )
    claims = _claims(attestation)
    assert claims["iat"] == 1000
    assert claims["exp"] == 1300


def test_attestation_requires_issuer():
    attester = SigningKeyPair.generate("ES256")
    with pytest.raises(ValueError, match="issuer"):
        ClientAttestationBuilder(attester, "")
    with pytest.raises(ValueError, match="issuer"):
        ClientAttestationBuilder(attester, "   ")


def test_attestation_requires_client_id():
    attester = SigningKeyPair.generate("ES256")
    instance = SigningKeyPair.generate("ES256")
    builder = ClientAttestationBuilder(attester, ATTESTER_ISS).confirmation_key(instance).expires_in(300)
    with pytest.raises(ValueError, match="client_id"):
        builder.build()


def test_attestation_requires_confirmation_key():
    attester = SigningKeyPair.generate("ES256")
    builder = ClientAttestationBuilder(attester, ATTESTER_ISS).client_id(CLIENT_ID).expires_in(300)
    with pytest.raises(ValueError, match="cnf"):
        builder.build()


def test_attestation_requires_expiry():
    attester = SigningKeyPair.generate("ES256")
    instance = SigningKeyPair.generate("ES256")
    builder = ClientAttestationBuilder(attester, ATTESTER_ISS).client_id(CLIENT_ID).confirmation_key(instance)
    with pytest.raises(ValueError, match="expiry"):
        builder.build()


def test_pop_explicit_jti_iat_and_challenge():
    instance = SigningKeyPair.generate("ES256")
    pop = (
        PopBuilder(instance)
        .client_id(CLIENT_ID)
        .audience(AUDIENCE)
        .challenge("as-issued-challenge")
        .jwt_id("jti-1")
        .issued_at(1234)
        .build()
    )
    claims = _claims(pop)
    assert claims["jti"] == "jti-1"
    assert claims["iat"] == 1234
    assert claims["challenge"] == "as-issued-challenge"


def test_pop_requires_audience():
    instance = SigningKeyPair.generate("ES256")
    with pytest.raises(ValueError, match="aud"):
        PopBuilder(instance).client_id(CLIENT_ID).build()


def test_dpop_explicit_jti_iat_and_nonce():
    instance = SigningKeyPair.generate("ES256")
    dpop = (
        DpopProofBuilder(instance)
        .uri(TOKEN_ENDPOINT)
        .nonce("server-nonce")
        .jwt_id("jti-2")
        .issued_at(1234)
        .build()
    )
    claims = _claims(dpop)
    assert claims["htm"] == "POST"  # default method
    assert claims["jti"] == "jti-2"
    assert claims["iat"] == 1234
    assert claims["nonce"] == "server-nonce"


def test_dpop_requires_uri():
    instance = SigningKeyPair.generate("ES256")
    with pytest.raises(ValueError, match="htu"):
        DpopProofBuilder(instance).build()
