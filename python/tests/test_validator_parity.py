"""The decisions validation/SEMANTICS.md pins for every port, beyond what the shared vectors reach: the
default introspection transport's cap and strict parsing, injected transports that return junk, the clock,
the strict JSON reader's edges, and the key lookup for a token without a kid."""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest

from client_attestation_sdk import SigningKeyPair
from client_attestation_sdk.errors import TransportError
from client_attestation_sdk.token_validator import (
    AccessTokenValidator,
    IntrospectionConfig,
    ValidatorConfig,
    errors,
)
from client_attestation_sdk.token_validator import _strict
from client_attestation_sdk.token_validator.jwks import JwksProvider
from client_attestation_sdk.token_validator.validator import MAX_INTROSPECTION_BYTES

ISSUER = "https://issuer.example.com"
AUDIENCE = "https://api.example.com"
KEY = SigningKeyPair.generate("ES256")


def _config(**overrides):
    base = dict(issuer=ISSUER, audiences=[AUDIENCE], jwks={"keys": [KEY.public_jwk()]},
                required_scopes=["read"], accepted_algorithms=["ES256"])
    base.update(overrides)
    return ValidatorConfig(**base)


def _token(claims=None, **headers):
    body = {"iss": ISSUER, "aud": AUDIENCE, "sub": "agent-1", "scope": "read", "exp": 2_000_000_000}
    body.update(claims or {})
    return jwt.encode(body, KEY.private_key, algorithm="ES256",
                      headers={"kid": KEY.key_id, "typ": "at+jwt", **headers})


def _serve(status, body):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/introspect"


@pytest.mark.parametrize("body, message", [
    (b'{"active": true, "active": false}', "duplicate member name"),
    (b"[true]", "not a JSON object"),
    (b'{"active": true,}', "not JSON"),
    (b'{"active": true, "x": "' + b"a" * MAX_INTROSPECTION_BYTES + b'"}', "larger than"),
])
def test_default_introspection_transport_refuses_what_every_port_refuses(body, message):
    server, endpoint = _serve(200, body)
    try:
        validator = AccessTokenValidator(_config(introspection=IntrospectionConfig(endpoint, "rs", "s")))
        with pytest.raises(TransportError, match=message):
            validator.validate_active("opaque")
    finally:
        server.shutdown()


def test_default_introspection_transport_reads_a_strict_object_with_replacement_utf8():
    server, endpoint = _serve(200, b'{"active": true, "scope": "read", "sub": "agent-\xff"}')
    try:
        validator = AccessTokenValidator(_config(introspection=IntrospectionConfig(endpoint, "rs", "s")))
        result = validator.validate_active("opaque")
        assert result.valid and result.subject == "agent-�"
    finally:
        server.shutdown()


def test_introspection_failure_raises_never_a_verdict():
    server, endpoint = _serve(503, b"{}")
    try:
        validator = AccessTokenValidator(_config(introspection=IntrospectionConfig(endpoint, "rs", "s")))
        with pytest.raises(TransportError):
            validator.validate_active("opaque")
    finally:
        server.shutdown()
    with pytest.raises(ValueError, match="no introspection endpoint"):
        AccessTokenValidator(_config()).validate_active("opaque")


@pytest.mark.parametrize("junk", [None, ["active"], "active", 1])
def test_an_injected_transport_returning_a_non_object_raises(junk):
    cfg = _config(introspection=IntrospectionConfig("https://as/introspect", "rs", "s"))
    with pytest.raises(TransportError, match="not an object"):
        AccessTokenValidator(cfg, http_post=lambda *a: junk).validate_active("opaque")


def test_the_injected_clock_decides_expiry_and_leeway():
    token = _token({"exp": 1_000_000})
    assert AccessTokenValidator(_config(), clock=lambda: 1_000_059.9).validate(token).valid
    assert AccessTokenValidator(_config(), clock=lambda: 1_000_061).validate(token).error == errors.EXPIRED
    zero = _config(leeway_seconds=0)
    assert AccessTokenValidator(zero, clock=lambda: 1_000_000).validate(token).valid
    assert AccessTokenValidator(zero, clock=lambda: 1_000_001).validate(token).error == errors.EXPIRED


def test_an_explicitly_empty_allow_list_accepts_nothing():
    assert AccessTokenValidator(_config(accepted_algorithms=[])).validate(_token()).error == \
        errors.UNSUPPORTED_ALGORITHM
    assert AccessTokenValidator(_config(accepted_token_types=[])).validate(_token()).error == \
        errors.INVALID_TOKEN_TYPE


def test_the_validator_never_raises_on_hostile_tokens():
    # the shared vectors pin the verdicts; these are the shapes that used to reach an unguarded exception
    hostile = [
        None, 7, "", "..", "a.b.c.d", "e30.e30.", "!!.e30.e30",
        _token({"exp": float("inf")}),   # PyJWT writes Infinity, which no strict reader accepts
        _token({"nbf": float("nan")}),
        _token({"exp": 10**400}),
    ]
    validator = AccessTokenValidator(_config())
    for token in hostile:
        result = validator.validate(token)
        assert not result.valid and result.error in (errors.INVALID_TOKEN, errors.UNSUPPORTED_ALGORITHM)


def test_a_signature_the_algorithm_cannot_parse_is_invalid():
    head, payload, _ = _token().split(".")
    short = base64.urlsafe_b64encode(b"\x01" * 10).rstrip(b"=").decode()
    result = AccessTokenValidator(_config()).validate(f"{head}.{payload}.{short}")
    assert result.error == errors.INVALID_SIGNATURE
    # an EC key whose JWK declares no alg, offered for RS256: the RSA verifier can't use it at all
    no_alg = {k: v for k, v in KEY.public_jwk().items() if k != "alg"}
    rs = _config(jwks={"keys": [no_alg]}, accepted_algorithms=["RS256"])
    forged = jwt.utils.base64url_encode(json.dumps({"alg": "RS256", "kid": KEY.key_id}).encode()).decode()
    result = AccessTokenValidator(rs).validate(f"{forged}.{payload}.{short}")
    assert result.error == errors.INVALID_SIGNATURE


def test_strict_reader_edges():
    assert _strict.parse_object(b'{"a": "x\\"y{[", "b": [1, {"c": null}]}') == \
        {"a": 'x"y{[', "b": [1, {"c": None}]}
    for bad in (b'{"a": Infinity}', b'{"a": -Infinity}', b"{" * 70 + b"}" * 70, b'{"a":1}{"b":2}'):
        with pytest.raises(_strict.Malformed):
            _strict.parse_object(bad)
    # a number Python can't make an int of reads as a double, as in every other port
    assert _strict.parse_object(b'{"n": ' + b"9" * 5000 + b"}")["n"] == float("inf")
    with pytest.raises(_strict.Malformed, match="out of range"):
        _strict.numeric_date({"exp": -(2**53)}, "exp")
    assert _strict.numeric_date({"exp": -4.9}, "exp") == -4


def test_a_token_without_kid_matches_only_a_single_key_set():
    other = SigningKeyPair.generate("ES256")
    no_kid = {k: v for k, v in KEY.public_jwk().items() if k != "kid"}
    two = JwksProvider(jwks={"keys": [no_kid, other.public_jwk()]})
    assert two.resolve(None, "ES256") is None
    one = JwksProvider(jwks={"keys": [no_kid]})
    assert one.resolve(None, "ES256") is not None


def test_result_subject_is_a_string_or_none():
    validator = AccessTokenValidator(_config())
    assert validator.validate(_token({"sub": None})).subject is None
    assert validator.validate(_token({"sub": 7})).error == errors.INVALID_TOKEN
    assert json.loads(json.dumps(validator.validate(_token()).claims))["sub"] == "agent-1"
