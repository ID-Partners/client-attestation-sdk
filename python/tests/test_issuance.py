"""Tests for IssuedAttestation's post-issuance proof methods (`pop` and its DPoP-combined sibling
`dpop`) — both mint a fresh proof signed by the instance key the issuance endpoint bound into the
attestation's `cnf`, so a workload can call the token endpoint without re-running bootstrap."""
import json

import jwt
import pytest

from client_attestation_sdk import (
    AttestationIssuanceClient,
    AttesterProfile,
    ClientAttestationError,
    IssuedAttestation,
    MintResult,
    SigningKeyPair,
    StaticSvidSource,
)
from client_attestation_sdk import _http

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


# ── the https rule ───────────────────────────────────────────────────────────────────────────────

class _Recorder:
    """Stands in for the SDK's one HTTP function: records every URL and answers with a minted attestation,
    so a test can show whether the SVID was sent anywhere, with no network."""

    def __init__(self):
        self.urls = []

    def __call__(self, method, url, **kwargs):
        self.urls.append(url)
        body = json.dumps({"attestation": "h.p.s", "client_attestation": "h.p.s"}).encode()
        return _http.HttpResponse(200, {"Content-Type": "application/json"}, body)


@pytest.fixture()
def recorder(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(_http, "request", rec)
    return rec


class _OffsiteProfile(AttesterProfile):
    """Mints through the transport at a URL of its own choosing, as a custom profile may."""

    def __init__(self, target):
        self.target = target

    def mint(self, transport, metadata, request):
        res = transport.request_json("mint", "POST", self.target, {"evidence": request.evidence})
        return MintResult(attestation=res["client_attestation"])


class _EmptyProfile(AttesterProfile):
    def __init__(self, result):
        self.result = result

    def mint(self, transport, metadata, request):
        return self.result


def _client(endpoint, **kwargs):
    return AttestationIssuanceClient(endpoint, "client-1", "https://attester.example", StaticSvidSource("svid"),
                                     **kwargs)


def test_plain_http_endpoint_is_refused_at_construction(recorder):
    with pytest.raises(ClientAttestationError, match="endpoint must use https"):
        _client("http://pf.example/federation/attestation")
    assert recorder.urls == []


def test_https_and_loopback_endpoints_are_allowed(recorder):
    assert _client("https://pf.example/federation/attestation").bootstrap().attestation == "h.p.s"
    assert _client("http://localhost:9031/federation/attestation").bootstrap().attestation == "h.p.s"
    assert recorder.urls == ["https://pf.example/federation/attestation",
                             "http://localhost:9031/federation/attestation"]


def test_a_custom_profiles_calls_keep_the_https_rule(recorder):
    client = _client("https://pf.example/federation/attestation",
                     profile=_OffsiteProfile("http://attester.example/mint"))
    with pytest.raises(ClientAttestationError, match="must use https"):
        client.bootstrap()
    assert recorder.urls == []


def test_allow_insecure_lifts_the_https_rule(recorder):
    assert _client("http://pf.example/federation/attestation", allow_insecure=True).bootstrap().attestation == "h.p.s"
    client = _client("http://pf.example/federation/attestation", allow_insecure=True,
                     profile=_OffsiteProfile("http://attester.example/mint"))
    assert client.bootstrap().attestation == "h.p.s"
    assert recorder.urls == ["http://pf.example/federation/attestation", "http://attester.example/mint"]


@pytest.mark.parametrize("result", [None, MintResult(attestation=""), MintResult(attestation=None)])
def test_a_profile_that_mints_nothing_is_an_error(result):
    client = _client("https://pf.example/federation/attestation", profile=_EmptyProfile(result))
    with pytest.raises(ClientAttestationError, match="no attestation"):
        client.bootstrap()
