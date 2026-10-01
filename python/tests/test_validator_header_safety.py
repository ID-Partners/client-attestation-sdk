"""Item 15: WWW-Authenticate quoting strips control characters, and no failure message echoes
unverified token data (kid / alg / iss / aud) into error_description."""
import base64
import json
import time

import jwt
import pytest

from client_attestation_sdk import SigningKeyPair
from token_validator import AccessTokenValidator, ProtectedResource, ValidatorConfig, errors
from token_validator.resource import _quote

ISSUER = "https://issuer.example.com"
AUDIENCE = "https://api.example.com"
KEY = SigningKeyPair.generate("ES256")
MARK = "EVIL\r\nX-Injected: 1\x00\x7f\""


def _validator(**kw):
    base = dict(issuer=ISSUER, audiences=[AUDIENCE], jwks={"keys": [KEY.public_jwk()]},
                required_scopes=["read"], accepted_algorithms=["ES256"])
    base.update(kw)
    return AccessTokenValidator(ValidatorConfig(**base))


def _b64(obj):
    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _signed(claims=None, **headers):
    body = {"iss": ISSUER, "aud": AUDIENCE, "scope": "read", "exp": int(time.time()) + 300}
    body.update(claims or {})
    return jwt.encode(body, KEY.private_key, algorithm="ES256",
                      headers={"kid": KEY.key_id, "typ": "at+jwt", **headers})


def test_quote_strips_every_control_character_and_escapes():
    controls = "".join(chr(c) for c in range(0x20)) + "\x7f"
    assert _quote("a" + controls + "b") == "ab"
    assert _quote('say "hi" \\ bye') == 'say \\"hi\\" \\\\ bye'
    assert _quote("line1\r\nSet-Cookie: x") == "line1Set-Cookie: x"
    assert _quote("café \t tab") == "café  tab"


def test_challenge_header_never_contains_control_characters():
    pr = ProtectedResource(AUDIENCE, [ISSUER], _validator())
    header = pr.challenge("invalid_token\r\n", 'bad\r\n"x"\x00\\')
    assert not any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in header)
    assert header.startswith('Bearer error="invalid_token", error_description="bad\\"x\\"\\\\"')
    assert header.endswith('resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"')


@pytest.mark.parametrize("case", ["alg", "kid", "iss", "aud", "malformed_header", "none_alg"])
def test_failure_messages_do_not_echo_token_data(case):
    v = _validator()
    if case == "alg":
        token = _b64({"alg": MARK, "kid": KEY.key_id}) + "." + _b64({"iss": MARK}) + ".sig"
        expect = errors.UNSUPPORTED_ALGORITHM
    elif case == "kid":
        token = _signed(kid=MARK)
        expect = errors.KEY_NOT_FOUND
    elif case == "iss":
        token = _signed({"iss": MARK})
        expect = errors.INVALID_ISSUER
    elif case == "aud":
        token = _signed({"aud": MARK})
        expect = errors.INVALID_AUDIENCE
    elif case == "malformed_header":
        token = _b64(b'{"alg": "' + MARK.encode() + b'"') + "." + _b64({}) + ".sig"
        expect = errors.INVALID_TOKEN
    else:
        v = _validator(accepted_algorithms=["ES256", "none"])
        token = jwt.encode({"iss": MARK}, None, algorithm="none", headers={"kid": KEY.key_id})
        expect = errors.INVALID_TOKEN
    result = v.validate(token)
    assert not result.valid and result.error == expect
    assert "EVIL" not in result.error_description and "Injected" not in result.error_description
    if case == "alg":
        assert result.error_description == "algorithm not accepted"


def test_undecodable_signed_token_gets_a_generic_message():
    token = jwt.PyJWS().encode(b"EVIL not json", KEY.private_key, algorithm="ES256",
                               headers={"kid": KEY.key_id})
    result = _validator().validate(token)
    assert result.error == errors.INVALID_SIGNATURE
    assert "EVIL" not in result.error_description


def test_authenticate_end_to_end_keeps_the_header_clean():
    pr = ProtectedResource(AUDIENCE, [ISSUER], _validator())
    token = _b64({"alg": MARK}) + "." + _b64({}) + ".sig"
    decision = pr.authenticate("Bearer " + token)
    assert decision.status == 401 and decision.error_description == "algorithm not accepted"
    assert "EVIL" not in decision.www_authenticate and "\r" not in decision.www_authenticate
