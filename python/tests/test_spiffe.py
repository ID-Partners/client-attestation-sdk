"""SPIFFE Workload API + the bridge into the OIDF client attestation."""
import jwt
import pytest

from client_attestation_sdk import (
    ClientAttestationBuilder,
    SigningKeyPair,
    SpiffeAgent,
    to_workload_claim,
    verify_jwt_svid,
)

TRUST_DOMAIN = "banking.demo"
AUD = "https://as.example.com"


def _agent() -> SpiffeAgent:
    agent = SpiffeAgent(TRUST_DOMAIN, SigningKeyPair.generate("ES256"))
    agent.register(
        {"docker:label:app": "payment-agent"},
        "payment-agent",
        {"region": "emea", "entitlements": ["initiate_payment"], "workload_type": "agent"},
    )
    return agent


def test_fetch_svid_for_attested_workload():
    agent = _agent()
    svid = agent.fetch_jwt_svid({"docker:label:app": "payment-agent", "unix:uid": "1000"}, AUD)
    assert svid.spiffe_id == "spiffe://banking.demo/payment-agent"
    assert svid.trust_domain == TRUST_DOMAIN
    assert svid.attributes["region"] == "emea"
    claims = verify_jwt_svid(svid.token, agent.trust_bundle(), AUD, TRUST_DOMAIN)
    assert claims["sub"] == svid.spiffe_id
    assert AUD in claims["aud"]


def test_unattested_workload_is_rejected():
    agent = _agent()
    with pytest.raises(PermissionError):
        agent.fetch_jwt_svid({"docker:label:app": "not-registered"}, AUD)


def test_verify_rejects_wrong_audience():
    agent = _agent()
    svid = agent.fetch_jwt_svid({"docker:label:app": "payment-agent"}, AUD)
    with pytest.raises(jwt.InvalidAudienceError):
        verify_jwt_svid(svid.token, agent.trust_bundle(), "https://someone-else.example.com", TRUST_DOMAIN)


def test_bridge_carries_spiffe_attributes_into_attestation():
    agent = _agent()
    svid = agent.fetch_jwt_svid({"docker:label:app": "payment-agent"}, AUD)

    attester = SigningKeyPair.generate("ES256")
    instance = SigningKeyPair.generate("ES256")
    attestation = (
        ClientAttestationBuilder(attester, "https://attester.example.com")
        .client_id(svid.spiffe_id)
        .confirmation_key(instance)
        .workload(to_workload_claim(svid))
        .expires_in(300)
        .build()
    )

    claims = jwt.decode(attestation, options={"verify_signature": False})
    workload = claims["workload"]
    assert claims["sub"] == "spiffe://banking.demo/payment-agent"
    assert workload["attested_by"] == "spiffe"
    assert workload["spiffe_id"] == svid.spiffe_id
    assert workload["attributes"]["entitlements"] == ["initiate_payment"]
    # the SVID travels along so the AS can independently verify the SPIFFE attestation
    assert verify_jwt_svid(workload["svid"], agent.trust_bundle(), AUD, TRUST_DOMAIN)["sub"] == svid.spiffe_id
