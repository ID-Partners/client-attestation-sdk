import json
import os

from token_validator import (
    AccessTokenValidator,
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
