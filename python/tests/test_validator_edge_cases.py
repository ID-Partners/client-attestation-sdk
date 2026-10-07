import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest

from client_attestation_sdk import SigningKeyPair
from client_attestation_sdk.token_validator import (
    AccessTokenValidator,
    IntrospectionConfig,
    ValidationResult,
    ValidatorConfig,
    errors,
)

ISSUER = "https://issuer.example.com"
AUDIENCE = "https://api.example.com"

KEY = SigningKeyPair.generate("ES256")


def _config(**overrides):
    base = dict(issuer=ISSUER, audiences=[AUDIENCE], jwks={"keys": [KEY.public_jwk()]},
                required_scopes=["read"], accepted_algorithms=["ES256"])
    base.update(overrides)
    return ValidatorConfig(**base)


def _token(overrides=None, **headers):
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "agent-1", "scope": "read write",
              "exp": int(time.time()) + 300}
    claims.update(overrides or {})
    for name in [k for k, v in claims.items() if v is None]:
        del claims[name]
    return jwt.encode(claims, KEY.private_key, algorithm="ES256",
                      headers={"kid": KEY.key_id, "typ": "at+jwt", **headers})


def test_malformed_token():
    result = AccessTokenValidator(_config()).validate("not-a-jwt")
    assert not result.valid and result.error == errors.INVALID_TOKEN


def test_unaccepted_algorithm():
    token = jwt.encode({"iss": ISSUER}, "shared-secret-of-at-least-32-bytes!", algorithm="HS256")
    result = AccessTokenValidator(_config()).validate(token)
    assert not result.valid and result.error == errors.UNSUPPORTED_ALGORITHM


def test_unknown_kid():
    token = _token(kid="unknown-kid")
    result = AccessTokenValidator(_config()).validate(token)
    assert not result.valid and result.error == errors.KEY_NOT_FOUND


def test_non_json_payload_is_rejected():
    # a genuine signature over a payload that is not a JSON object
    token = jwt.PyJWS().encode(b"not json", KEY.private_key, algorithm="ES256",
                               headers={"kid": KEY.key_id})
    result = AccessTokenValidator(_config()).validate(token)
    assert not result.valid and result.error == errors.INVALID_SIGNATURE


def test_alg_none_is_rejected_even_when_accepted():
    # a misconfigured validator accepting "none" still fails: PyJWT refuses a key with alg=none
    token = jwt.encode({"iss": ISSUER}, None, algorithm="none", headers={"kid": KEY.key_id})
    result = AccessTokenValidator(_config(accepted_algorithms=["ES256", "none"])).validate(token)
    assert not result.valid and result.error == errors.INVALID_TOKEN


def test_scp_list_claim_grants_scopes():
    token = _token({"scope": None, "scp": ["read", "write"]})
    result = AccessTokenValidator(_config()).validate(token)
    assert result.valid and result.scopes == ["read", "write"]


def test_no_scope_claim_at_all():
    token = _token({"scope": None})
    result = AccessTokenValidator(_config()).validate(token)
    assert not result.valid and result.error == errors.INSUFFICIENT_SCOPE
    relaxed = AccessTokenValidator(_config(required_scopes=[])).validate(token)
    assert relaxed.valid and relaxed.scopes == []


def test_introspect_without_configuration_raises():
    with pytest.raises(ValueError, match="introspection"):
        AccessTokenValidator(_config()).introspect("opaque-token")


def test_introspection_client_secret_post():
    captured = {}

    def fake_post(url, body, headers):
        captured.update(url=url, body=body, headers=headers)
        return {"active": True, "scope": "read", "aud": AUDIENCE}

    cfg = _config(introspection=IntrospectionConfig(
        "https://issuer.example.com/introspect", "rs-1", "s3cret", auth_method="client_secret_post"))
    result = AccessTokenValidator(cfg, http_post=fake_post).validate_active("opaque-token")
    assert result.valid
    assert "Authorization" not in captured["headers"]
    form = urllib.parse.parse_qs(captured["body"])
    assert form["client_id"] == ["rs-1"] and form["client_secret"] == ["s3cret"]


def test_validate_active_missing_scope():
    cfg = _config(introspection=IntrospectionConfig("https://issuer.example.com/introspect", "rs-1", "s3cret"))
    validator = AccessTokenValidator(cfg, http_post=lambda *a: {"active": True, "scope": "read", "aud": AUDIENCE})
    result = validator.validate_active("opaque-token", required_scopes=["read", "admin"])
    assert not result.valid and result.error == errors.INSUFFICIENT_SCOPE


def test_validate_active_wrong_audience():
    cfg = _config(introspection=IntrospectionConfig("https://issuer.example.com/introspect", "rs-1", "s3cret"))
    validator = AccessTokenValidator(
        cfg, http_post=lambda *a: {"active": True, "scope": "read", "aud": "https://other.example.com"})
    result = validator.validate_active("opaque-token")
    assert not result.valid and result.error == errors.INVALID_AUDIENCE


def test_validate_active_without_audience_claim():
    cfg = _config(introspection=IntrospectionConfig("https://issuer.example.com/introspect", "rs-1", "s3cret"))
    validator = AccessTokenValidator(cfg, http_post=lambda *a: {"active": True, "scope": "read"})
    result = validator.validate_active("opaque-token")
    assert result.valid and result.audience == []


def test_default_post_transport_reaches_introspection_endpoint():
    received = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8")
            received.update(path=self.path, form=urllib.parse.parse_qs(body))
            data = json.dumps({"active": True, "scope": "read", "sub": "agent-1", "aud": AUDIENCE}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_address[1]}/introspect"
        cfg = _config(introspection=IntrospectionConfig(endpoint, "rs-1", "s3cret"))
        result = AccessTokenValidator(cfg).validate_active("opaque-token")
        assert result.valid and result.subject == "agent-1"
        assert received["path"] == "/introspect"
        assert received["form"]["token"] == ["opaque-token"]
    finally:
        server.shutdown()


def test_result_truthiness_and_repr():
    ok = AccessTokenValidator(_config()).validate(_token())
    assert ok.valid and bool(ok)
    assert "agent-1" in repr(ok)
    failed = ValidationResult.failure(errors.EXPIRED, "token has expired")
    assert not bool(failed)
    assert errors.EXPIRED in repr(failed) and "invalid" in repr(failed)


# -- the checks the shared vectors pin (exp, iat, typ), and the config the validator now refuses --


def test_issuer_and_audience_are_required():
    with pytest.raises(ValueError):
        _config(issuer=None)
    with pytest.raises(ValueError):
        _config(audiences=[])


def test_token_type_comparison_follows_rfc7515():
    validator = AccessTokenValidator(_config())
    assert validator.validate(_token(typ="application/at+jwt")).valid
    assert validator.validate(_token(typ="AT+JWT")).valid
    assert validator.validate(_token(typ="JWT")).error == errors.INVALID_TOKEN_TYPE


def test_token_type_check_can_be_turned_off():
    assert AccessTokenValidator(_config(accepted_token_types=None)).validate(_token(typ="JWT")).valid


def test_non_numeric_exp_is_malformed():
    for bad in ("4102444800", True):
        result = AccessTokenValidator(_config()).validate(_token({"exp": bad}))
        assert result.error == errors.INVALID_TOKEN


def test_iat_within_leeway_is_accepted():
    soon = int(time.time()) + 30
    assert AccessTokenValidator(_config()).validate(_token({"iat": soon})).valid


def test_jwk_declared_alg_binds_the_key():
    # the same EC key, published as ES384-only: an ES256 token signed with it must not resolve
    jwk = {**KEY.public_jwk(), "alg": "ES384"}
    validator = AccessTokenValidator(_config(jwks={"keys": [jwk]}, accepted_algorithms=["ES256", "ES384"]))
    assert validator.validate(_token()).error == errors.KEY_NOT_FOUND


def test_protected_resource_refuses_a_validator_for_another_audience():
    from client_attestation_sdk.token_validator import ProtectedResource

    validator = AccessTokenValidator(_config())
    with pytest.raises(ValueError):
        ProtectedResource("https://other.example.com", [ISSUER], validator)
