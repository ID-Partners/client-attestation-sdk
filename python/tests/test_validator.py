import json
import os

from client_attestation_sdk.errors import TransportError
from client_attestation_sdk.token_validator import AccessTokenValidator, IntrospectionConfig, ValidatorConfig, errors

VALIDATION = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "validation"))


def _vectors():
    with open(os.path.join(VALIDATION, "tokens.json")) as fh:
        return json.load(fh)


def _validator(vectors, **overrides):
    cfg = ValidatorConfig(
        issuer=vectors["issuer"], audiences=[vectors["audience"]], jwks=vectors["jwks"],
        required_scopes=vectors["required_scopes"], accepted_algorithms=vectors["accepted_algorithms"],
        **overrides,
    )
    return AccessTokenValidator(cfg)


def _case_validator(vectors, case):
    """The validator a vector case asks for: the shared config plus the case's overrides and clock."""
    options = {"accepted_algorithms": vectors["accepted_algorithms"], **(case.get("config") or {})}
    cfg = ValidatorConfig(
        issuer=vectors["issuer"], audiences=[vectors["audience"]], jwks=vectors["jwks"],
        required_scopes=vectors["required_scopes"], **options,
    )
    clock = (lambda: float(case["now"])) if "now" in case else None
    return AccessTokenValidator(cfg, clock=clock)


def test_vectors_match_expected():
    vectors = _vectors()
    for case in vectors["cases"]:
        result = _case_validator(vectors, case).validate(case["token"])
        got = "valid" if result.valid else result.error
        assert got == case["expect"], f"{case['name']}: expected {case['expect']}, got {got}"


def test_introspection_vectors_match_expected():
    vectors = _vectors()
    with open(os.path.join(VALIDATION, "introspection.json")) as fh:
        cases = json.load(fh)["cases"]
    for case in cases:
        def post(url, body, headers, case=case):
            if case.get("transport_error"):
                raise TransportError("introspection endpoint returned HTTP 503", status=503)
            return case["response"]

        endpoint = None if case.get("no_endpoint") else IntrospectionConfig("https://as/introspect", "rs", "s")
        validator = AccessTokenValidator(ValidatorConfig(
            issuer=vectors["issuer"], audiences=[vectors["audience"]], jwks=vectors["jwks"],
            required_scopes=vectors["required_scopes"], introspection=endpoint), http_post=post)
        try:
            result = validator.validate_active("opaque")
            got = "valid" if result.valid else result.error
        except (TransportError, ValueError):
            got = "raises"
        assert got == case["expect"], f"{case['name']}: expected {case['expect']}, got {got}"


def test_valid_exposes_subject_and_scopes():
    vectors = _vectors()
    validator = _validator(vectors)
    token = next(c["token"] for c in vectors["cases"] if c["name"] == "valid")
    result = validator.validate(token)
    assert result.valid
    assert result.subject == "agent-1"
    assert "read" in result.scopes and "write" in result.scopes
    assert vectors["audience"] in result.audience


def test_required_scope_override():
    vectors = _vectors()
    validator = _validator(vectors)
    token = next(c["token"] for c in vectors["cases"] if c["name"] == "valid")
    result = validator.validate(token, required_scopes=["read", "admin"])
    assert not result.valid and result.error == errors.INSUFFICIENT_SCOPE


def test_introspection_basic_auth_and_active():
    vectors = _vectors()
    captured = {}

    def fake_post(url, body, headers):
        captured.update(url=url, body=body, headers=headers)
        return {"active": True, "scope": "read write", "sub": "agent-1", "aud": vectors["audience"]}

    cfg = ValidatorConfig(
        issuer=vectors["issuer"], audiences=[vectors["audience"]], jwks=vectors["jwks"], required_scopes=["read"],
        introspection=IntrospectionConfig("https://issuer.example.com/introspect", "rs-1", "s3cret"),
    )
    validator = AccessTokenValidator(cfg, http_post=fake_post)
    result = validator.validate_active("opaque-token")
    assert result.valid and result.subject == "agent-1"
    assert captured["url"].endswith("/introspect")
    assert "token=opaque-token" in captured["body"]
    assert captured["headers"]["Authorization"].startswith("Basic ")


def test_introspection_inactive():
    vectors = _vectors()
    cfg = ValidatorConfig(
        issuer=vectors["issuer"], audiences=[vectors["audience"]], jwks=vectors["jwks"],
        introspection=IntrospectionConfig("https://issuer.example.com/introspect", "rs-1", "s3cret"),
    )
    validator = AccessTokenValidator(cfg, http_post=lambda *a: {"active": False})
    result = validator.validate_active("revoked")
    assert not result.valid and result.error == errors.INACTIVE
