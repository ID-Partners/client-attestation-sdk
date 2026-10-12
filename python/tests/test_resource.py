import json
import os
import time

import jwt
import pytest

from client_attestation_sdk import SigningKeyPair
from client_attestation_sdk.errors import TransportError
from client_attestation_sdk.token_validator import (
    AccessTokenValidator,
    IntrospectionConfig,
    ProtectedResource,
    ValidatorConfig,
    bearer_token,
    errors,
)

VALIDATION = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "validation"))


def _vectors():
    with open(os.path.join(VALIDATION, "tokens.json")) as fh:
        return json.load(fh)


def _resource(vectors):
    validator = AccessTokenValidator(ValidatorConfig(
        issuer=vectors["issuer"], audiences=[vectors["audience"]], jwks=vectors["jwks"],
        required_scopes=vectors["required_scopes"], accepted_algorithms=vectors["accepted_algorithms"]))
    return ProtectedResource(resource=vectors["audience"], authorization_servers=[vectors["issuer"]],
                             validator=validator, scopes_supported=["read", "write"])


def _token(vectors, name):
    return next(c["token"] for c in vectors["cases"] if c["name"] == name)


def test_bearer_extraction():
    assert bearer_token("Bearer abc.def.ghi") == "abc.def.ghi"
    assert bearer_token("bearer abc") == "abc"
    assert bearer_token("Basic abc") is None
    assert bearer_token("") is None
    assert bearer_token(None) is None
    assert bearer_token("Bearer ") is None


def _bearer_cases():
    with open(os.path.join(VALIDATION, "bearer.json")) as fh:
        return [(c["header"], c["token"]) for c in json.load(fh)["cases"]]


@pytest.mark.parametrize("header,token", _bearer_cases())
def test_bearer_extraction_shared_cases(header, token):
    # validation/bearer.json: the Go, Java and TypeScript tests read the same cases.
    assert bearer_token(header) == token


def test_bearer_extraction_is_linear():
    spaces = "Bearer a" + " " * 64000 + "b"
    newline = "Bearer" + " " * 64000 + "!\n!"
    started = time.perf_counter()
    assert bearer_token(spaces) == "a" + " " * 64000 + "b"
    assert bearer_token(newline) is None
    assert bearer_token("Bearer" + " \n" * 32000) == " "
    assert time.perf_counter() - started < 0.2


def test_metadata_rfc9728():
    md = _resource(_vectors()).metadata()
    assert md["resource"] == "https://api.example.com"
    assert md["authorization_servers"] == ["https://issuer.example.com"]
    assert md["bearer_methods_supported"] == ["header"]
    assert md["scopes_supported"] == ["read", "write"]


def test_metadata_path_and_url():
    pr = _resource(_vectors())
    assert pr.metadata_path() == "/.well-known/oauth-protected-resource"
    assert pr.metadata_url() == "https://api.example.com/.well-known/oauth-protected-resource"


def test_metadata_path_inserts_resource_path():
    v = _vectors()
    validator = AccessTokenValidator(ValidatorConfig(
        issuer=v["issuer"], audiences=["https://mcp.example.com/mcp"], jwks=v["jwks"]))
    pr = ProtectedResource("https://mcp.example.com/mcp", [v["issuer"]], validator)
    assert pr.metadata_path() == "/.well-known/oauth-protected-resource/mcp"
    assert pr.metadata_url() == "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"


def test_authenticate_valid_token():
    v = _vectors()
    decision = _resource(v).authenticate("Bearer " + _token(v, "valid"))
    assert decision.authorized and bool(decision) and decision.status == 200
    assert decision.result.subject == "agent-1"
    assert "read" in decision.result.scopes


def test_missing_token_challenges_401():
    decision = _resource(_vectors()).authenticate(None)
    assert not decision.authorized and decision.status == 401
    assert 'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"' in decision.www_authenticate


def test_expired_token_is_401_invalid_token():
    v = _vectors()
    decision = _resource(v).authenticate("Bearer " + _token(v, "expired"))
    assert decision.status == 401 and decision.error == "invalid_token"
    assert 'error="invalid_token"' in decision.www_authenticate


def test_wrong_audience_is_401():
    v = _vectors()
    decision = _resource(v).authenticate("Bearer " + _token(v, "wrong_audience"))
    assert decision.status == 401
    assert decision.result.error == errors.INVALID_AUDIENCE


def test_insufficient_scope_is_403():
    v = _vectors()
    decision = _resource(v).authenticate("Bearer " + _token(v, "valid"), required_scopes=["read", "admin"])
    assert decision.status == 403 and decision.error == "insufficient_scope"
    assert 'error="insufficient_scope"' in decision.www_authenticate


def test_resource_checks_its_own_audience_with_a_shared_validator():
    v = _vectors()
    other = "https://other.example.com"
    validator = AccessTokenValidator(ValidatorConfig(
        issuer=v["issuer"], audiences=[v["audience"], other], jwks=v["jwks"]))
    token = _token(v, "valid")
    assert validator.validate(token).valid
    decision = ProtectedResource(other, [v["issuer"]], validator).authenticate("Bearer " + token)
    assert not decision.authorized
    assert decision.status == 401
    assert decision.result.error == errors.INVALID_AUDIENCE
    assert decision.error == "invalid_token"
    assert ProtectedResource(v["audience"], [v["issuer"]], validator).authenticate("Bearer " + token).authorized


@pytest.mark.parametrize("cnf", [{"jkt": "bound-key"}, {"x5t#S256": "certificate"}, {}, "malformed"])
def test_bearer_guard_refuses_confirmation_without_proof(cnf):
    key = SigningKeyPair.generate("ES256")
    validator = AccessTokenValidator(ValidatorConfig(
        issuer="https://issuer.test", audiences=["https://api.test"], jwks={"keys": [key.public_jwk()]}))
    resource = ProtectedResource("https://api.test", ["https://issuer.test"], validator)
    claims = {"iss": "https://issuer.test", "aud": "https://api.test", "exp": int(time.time()) + 300, "cnf": cnf}
    token = jwt.encode(claims, key.private_key, algorithm="ES256", headers={"typ": "at+jwt", "kid": key.key_id})
    assert validator.validate(token).valid
    decision = resource.authenticate("Bearer " + token)
    assert not decision.authorized
    assert decision.status == 401
    assert decision.result.error == errors.INVALID_TOKEN
    assert decision.error == "invalid_token"
    claims["cnf"] = None
    bearer = jwt.encode(claims, key.private_key, algorithm="ES256", headers={"typ": "at+jwt", "kid": key.key_id})
    assert resource.authenticate("Bearer " + bearer).authorized


def _introspecting_resource(response):
    """A guard for https://api.test whose validator accepts another resource too and introspects to `response`."""
    def post(url, body, headers):
        if response is None:
            raise TransportError("introspection endpoint returned HTTP 503", status=503)
        return response

    config = ValidatorConfig(issuer="https://issuer.test", audiences=["https://api.test", "https://other.test"],
                             jwks={"keys": []},
                             introspection=IntrospectionConfig("https://issuer.test/introspect", "rs", "secret"))
    return ProtectedResource("https://api.test", ["https://issuer.test"],
                             AccessTokenValidator(config, http_post=post))


def test_authenticate_active_binds_this_resource_and_refuses_confirmation():
    active = {"active": True, "sub": "agent-1", "aud": "https://api.test"}
    assert _introspecting_resource(active).authenticate_active("Bearer opaque").authorized
    for response, error in [({**active, "aud": "https://other.test"}, errors.INVALID_AUDIENCE),
                            ({k: v for k, v in active.items() if k != "aud"}, errors.INVALID_AUDIENCE),
                            ({**active, "cnf": {"jkt": "bound-key"}}, errors.INVALID_TOKEN),
                            ({"active": False}, errors.INACTIVE)]:
        decision = _introspecting_resource(response).authenticate_active("Bearer opaque")
        assert not decision.authorized and decision.status == 401 and decision.result.error == error
    missing = _introspecting_resource(active).authenticate_active(None)
    assert not missing.authorized and missing.status == 401
    with pytest.raises(TransportError):
        _introspecting_resource(None).authenticate_active("Bearer opaque")
