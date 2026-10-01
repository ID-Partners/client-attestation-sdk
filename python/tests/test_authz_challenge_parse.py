"""parse_challenge against the shared vectors (validation/challenges.json). Every port must agree."""
import json
import os

import pytest

from authz_challenge import (
    AUTHN, CHALLENGE_TYPES, IDENTITY_PROOFING, RESOURCE_AUTHORISATION,
    Challenge, parse_challenge, parse_www_authenticate,
)

VALIDATION = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "validation"))


def _cases():
    with open(os.path.join(VALIDATION, "challenges.json")) as fh:
        return json.load(fh)["cases"]


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_vector(case):
    inp = case["input"]
    got = parse_challenge(inp.get("status"), inp.get("headers"), inp.get("body"))
    exp = case["expect"]
    if exp is None:
        assert got is None, f"{case['name']}: expected no challenge, got {got}"
        return
    assert isinstance(got, Challenge), f"{case['name']}: expected a Challenge"
    d = got.to_dict()
    for k, v in exp.items():
        assert d.get(k) == v, f"{case['name']}: {k}={d.get(k)!r}, expected {v!r}"
    # Nothing beyond the listed keys should carry a value (raw excluded by to_dict).
    extra = {k: v for k, v in d.items() if k not in exp}
    assert not extra, f"{case['name']}: unexpected populated fields {extra}"


def test_types_are_closed_set():
    assert set(CHALLENGE_TYPES) == {"authn", "resource_authorisation", "consent",
                                    "identity_proofing", "intent"}


def test_www_authenticate_parsing():
    assert parse_www_authenticate(None) == {}
    assert parse_www_authenticate("Basic realm=x") == {}
    assert parse_www_authenticate("Bearer") == {}
    p = parse_www_authenticate('Bearer realm="api", error="insufficient_scope", scope="a b", error_description="say \\"hi\\""')
    assert p == {"realm": "api", "error": "insufficient_scope", "scope": "a b",
                 "error_description": 'say "hi"'}
    # bare (unquoted) tokens are accepted
    assert parse_www_authenticate("bearer error=invalid_token, scope=read")["scope"] == "read"


def test_body_error_wins_over_header_error():
    # Kong's login gate: header says RFC 9470's code, body says the demo's — the body is authoritative
    # for the error string, but the acr_values comes through from either.
    ch = parse_challenge(401, {"WWW-Authenticate": 'Bearer error="insufficient_user_authentication", acr_values="x"'},
                         {"error": "login_required"})
    assert ch.type == AUTHN and ch.error == "login_required" and ch.acr_values == "x"


def test_status_alone_never_classifies():
    assert parse_challenge(401, {}, {}) is None
    assert parse_challenge(401, {}, "") is None
    assert parse_challenge(403, {"WWW-Authenticate": "Bearer"}, "nope") is None


def test_jsonrpc_data_without_wrapper_key():
    body = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32401, "message": "x",
                                                  "data": {"type": "identity_proofing", "doctype": "d"}}}
    ch = parse_challenge(200, {}, body)
    assert ch and ch.type == IDENTITY_PROOFING and ch.doctype == "d"


def test_bytes_body():
    raw = json.dumps({"error": "insufficient_scope", "scope": "s"}).encode()
    ch = parse_challenge(401, {}, raw)
    assert ch and ch.type == RESOURCE_AUTHORISATION and ch.scope == "s"


def test_raw_is_kept_but_not_compared():
    a = parse_challenge(401, {}, {"error": "insufficient_scope", "scope": "s"})
    b = parse_challenge(401, {"X-Extra": "1"}, {"error": "insufficient_scope", "scope": "s"})
    assert a == b            # raw is compare=False
    assert a.raw["body"]["scope"] == "s"
