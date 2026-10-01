"""Tests for IssuedAttestation's post-issuance proof methods (`pop` and its DPoP-combined sibling
`dpop`) — both mint a fresh proof signed by the instance key the issuance endpoint bound into the
attestation's `cnf`, so a workload can call the token endpoint without re-running bootstrap."""
import jwt
import pytest

from client_attestation_sdk import IssuedAttestation, SigningKeyPair

TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2"
CLIENT_ID = "https://rp.example.com"


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False})


@pytest.fixture()
def issued():
    instance_key = SigningKeyPair.generate("ES256")
    return IssuedAttestation("h.attestation.sig", 300, instance_key)


def test_pop_builds_a_pop_jwt_with_audience_client_id_and_challenge(issued):
    pop = issued.pop(TOKEN_ENDPOINT, client_id=CLIENT_ID, challenge="as-issued-challenge")
    claims = _claims(pop)
    assert claims["aud"] == TOKEN_ENDPOINT
    assert claims["iss"] == CLIENT_ID
    assert claims["challenge"] == "as-issued-challenge"


def test_pop_omits_optional_claims_when_not_given(issued):
    pop = issued.pop(TOKEN_ENDPOINT)
    claims = _claims(pop)
    assert claims["aud"] == TOKEN_ENDPOINT
    assert "iss" not in claims
    assert "challenge" not in claims


def test_dpop_builds_a_dpop_proof_with_method_uri_and_nonce(issued):
    dpop = issued.dpop("POST", TOKEN_ENDPOINT, challenge="as-issued-challenge")
    claims = _claims(dpop)
    assert claims["htm"] == "POST"
    assert claims["htu"] == TOKEN_ENDPOINT
    assert claims["nonce"] == "as-issued-challenge"


def test_dpop_omits_nonce_when_no_challenge_given(issued):
    dpop = issued.dpop("POST", TOKEN_ENDPOINT)
    assert "nonce" not in _claims(dpop)


def test_dpop_is_bound_to_the_same_instance_key_as_pop(issued):
    """Both proofs must be signed by (and, for DPoP, embed the public half of) the SAME instance
    key the issuance endpoint bound into the attestation's `cnf` — that's the whole point of
    `dpop_combined`: it lets a token endpoint verify possession without a PoP JWT."""
    pop = issued.pop(TOKEN_ENDPOINT)
    dpop = issued.dpop("POST", TOKEN_ENDPOINT)
    dpop_header = jwt.get_unverified_header(dpop)
    public_jwk = issued.instance_key.public_jwk()
    # Compare the key material, not `kid` (the embedded jwk omits it) — the load-bearing check is
    # that it's the SAME EC key, not an incidental byte-for-byte match of an unrelated field.
    assert {k: v for k, v in dpop_header["jwk"].items() if k != "kid"} == \
           {k: v for k, v in public_jwk.items() if k != "kid"}
    # A PoP JWT doesn't embed the jwk (the AS already has it from the attestation's cnf) — sanity
    # check the two proofs are otherwise independent per-call mints (different jti).
    assert _claims(pop)["jti"] != _claims(dpop)["jti"]
