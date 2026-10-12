"""Config-time checks on the validator: the https rule for its own endpoints, option types, and AS-metadata
discovery's issuer, https and strict-JSON checks."""
import json
import time

import jwt
import pytest

from client_attestation_sdk import SigningKeyPair
from client_attestation_sdk.errors import TransportError
from client_attestation_sdk.token_validator import (
    AccessTokenValidator, IntrospectionConfig, ValidatorConfig, discover,
)
from client_attestation_sdk.token_validator.discovery import _expected_issuer

ISSUER = "https://issuer.example.com"
AUDIENCE = "https://api.example.com"
WELL_KNOWN = ISSUER + "/.well-known/oauth-authorization-server"
METADATA = {"issuer": ISSUER, "jwks_uri": ISSUER + "/jwks", "introspection_endpoint": ISSUER + "/introspect"}

INSECURE = [
    "http://issuer.example.com/jwks",
    "http://127.0.0.2/jwks",
    "http://localhost.attacker.example/jwks",
    "http://localhost@attacker.example/jwks",
    "issuer.example.com/jwks",
]
SECURE = [
    "https://issuer.example.com/jwks",
    "HTTPS://issuer.example.com/jwks",
    "http://localhost:8080/jwks",
    "http://LOCALHOST/jwks",
    "http://127.0.0.1:9000/jwks",
    "http://[::1]:8080/jwks",
]


# -- the https rule: an http jwks_uri lets anyone on the path serve keys; an http introspection endpoint
# -- hands them the resource server's client secret


@pytest.mark.parametrize("url", INSECURE)
def test_insecure_jwks_uri_is_refused(url):
    with pytest.raises(ValueError, match="jwks_uri"):
        ValidatorConfig(ISSUER, AUDIENCE, jwks_uri=url)


@pytest.mark.parametrize("url", INSECURE)
def test_insecure_introspection_endpoint_is_refused(url):
    with pytest.raises(ValueError, match="introspection endpoint") as info:
        ValidatorConfig(ISSUER, AUDIENCE, introspection=IntrospectionConfig(url, "rs", "s3cret"))
    assert "s3cret" not in str(info.value)


@pytest.mark.parametrize("url", INSECURE)
def test_allow_insecure_opts_out(url):
    cfg = ValidatorConfig(ISSUER, AUDIENCE, jwks_uri=url, introspection=IntrospectionConfig(url, "rs", "s"),
                          allow_insecure=True)
    assert cfg.allow_insecure is True


@pytest.mark.parametrize("url", SECURE)
def test_https_and_loopback_are_accepted(url):
    cfg = ValidatorConfig(ISSUER, AUDIENCE, jwks_uri=url, introspection=IntrospectionConfig(url, "rs", "s"))
    assert cfg.allow_insecure is False


# -- option types


@pytest.mark.parametrize("leeway", [float("nan"), float("inf"), -1, 1.5, 60.0, "60", True, None])
def test_bad_leeway_is_refused(leeway):
    with pytest.raises(ValueError, match="leeway_seconds"):
        ValidatorConfig(ISSUER, AUDIENCE, leeway_seconds=leeway)


def test_nan_leeway_no_longer_disables_the_expiry_check():
    # NaN made every exp/nbf/iat comparison false: an expired token validated
    pair = SigningKeyPair.generate("ES256")
    token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) - 3600},
                       pair.private_key, algorithm="ES256", headers={"kid": pair.key_id})
    with pytest.raises(ValueError):
        AccessTokenValidator(ValidatorConfig(ISSUER, AUDIENCE, jwks={"keys": [pair.public_jwk()]},
                                             leeway_seconds=float("nan"))).validate(token)
    assert ValidatorConfig(ISSUER, AUDIENCE, leeway_seconds=0).leeway_seconds == 0


@pytest.mark.parametrize("option", ["accepted_token_types", "accepted_algorithms", "required_scopes"])
def test_bare_string_list_option_is_refused(option):
    # a bare string iterated as its characters: accepted_token_types="at+jwt" accepted typ "t"
    with pytest.raises(ValueError, match=option):
        ValidatorConfig(ISSUER, AUDIENCE, **{option: "at+jwt"})
    with pytest.raises(ValueError, match=option):
        ValidatorConfig(ISSUER, AUDIENCE, **{option: ["ok", 7]})
    with pytest.raises(ValueError, match=option):
        ValidatorConfig(ISSUER, AUDIENCE, **{option: 5})


def test_audiences_and_allow_insecure_types():
    assert ValidatorConfig(ISSUER, AUDIENCE).audiences == [AUDIENCE]
    with pytest.raises(ValueError, match="audiences"):
        ValidatorConfig(ISSUER, [AUDIENCE, 7])
    with pytest.raises(ValueError, match="allow_insecure"):
        ValidatorConfig(ISSUER, AUDIENCE, allow_insecure="yes")


# -- the validator keeps its own copy of its config: reusing the object for another validator, or changing it
# -- later, must not change what a live validator accepts


@pytest.mark.parametrize("mutate, claims, expect", [
    (lambda c: setattr(c, "issuer", None), {"iss": None}, "invalid_issuer"),
    (lambda c: c.audiences.__setitem__(0, "https://other.example.com"), {"aud": "https://other.example.com"},
     "invalid_audience"),
    (lambda c: c.required_scopes.__setitem__(0, "admin"), {}, None),
])
def test_validator_ignores_later_config_changes(mutate, claims, expect):
    pair = SigningKeyPair.generate("ES256")
    config = ValidatorConfig(ISSUER, [AUDIENCE], jwks={"keys": [pair.public_jwk()]}, required_scopes=["read"])
    validator = AccessTokenValidator(config)
    mutate(config)
    payload = {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 300, "scope": "read", **claims}
    token = jwt.encode({k: v for k, v in payload.items() if v is not None}, pair.private_key, algorithm="ES256",
                       headers={"kid": pair.key_id, "typ": "at+jwt"})
    assert validator.validate(token).error == expect


def test_validator_ignores_later_introspection_changes():
    introspection = IntrospectionConfig(ISSUER + "/introspect", "rs", "s3cret")
    posted = []
    validator = AccessTokenValidator(ValidatorConfig(ISSUER, AUDIENCE, introspection=introspection),
                                     http_post=lambda url, body, headers: posted.append(url) or {"active": True})
    introspection.endpoint = "http://attacker.example/introspect"
    validator.validate_active("opaque")
    assert posted == [ISSUER + "/introspect"]


def test_a_config_changed_before_the_validator_is_built_is_checked_again():
    # ValidatorConfig checks at construction; a config changed afterwards and then handed to a validator
    # must not skip those checks (an emptied issuer, an http introspection endpoint, a NaN leeway)
    def changed(**attrs):
        cfg = ValidatorConfig(ISSUER, AUDIENCE, introspection=IntrospectionConfig(ISSUER + "/introspect", "rs", "s"))
        for name, value in attrs.items():
            if name == "endpoint":
                cfg.introspection.endpoint = value
            else:
                setattr(cfg, name, value)
        return cfg
    for attrs, message in (({"issuer": None}, "issuer"), ({"issuer": ""}, "issuer"),
                           ({"audiences": []}, "audience"),
                           ({"endpoint": "http://attacker.example/introspect"}, "https"),
                           ({"jwks_uri": "http://attacker.example/jwks"}, "https"),
                           ({"leeway_seconds": float("nan")}, "leeway"),
                           ({"accepted_algorithms": "ES256"}, "list")):
        with pytest.raises(ValueError, match=message):
            AccessTokenValidator(changed(**attrs))


# -- discovery


def _serve(doc):
    return lambda url: doc if isinstance(doc, str) else json.dumps(doc)


def test_discover_refuses_metadata_for_another_issuer():
    # RFC 8414 section 3.3: otherwise whoever answers for the metadata URL picks the issuer and keys
    forged = {"issuer": "https://attacker.example", "jwks_uri": "https://attacker.example/jwks"}
    with pytest.raises(TransportError, match="attacker.example"):
        discover(WELL_KNOWN, _serve(forged))
    for doc in ({"jwks_uri": ISSUER + "/jwks"}, {"issuer": 7}):
        with pytest.raises(TransportError):
            discover(WELL_KNOWN, _serve(doc))
    with pytest.raises(TransportError):
        discover(WELL_KNOWN, _serve(METADATA), issuer="https://other.example")
    assert discover("https://meta.example/config", _serve(METADATA), issuer=ISSUER) == METADATA


def test_discover_derives_the_expected_issuer():
    assert _expected_issuer("https://as.example/.well-known/oauth-authorization-server") == "https://as.example"
    assert (_expected_issuer("https://as.example/.well-known/oauth-authorization-server/tenant/1")
            == "https://as.example/tenant/1")
    assert _expected_issuer("https://as.example/.well-known/openid-configuration/tenant") == "https://as.example/tenant"
    assert (_expected_issuer("https://as.example/realms/x/.well-known/openid-configuration")
            == "https://as.example/realms/x")
    assert (_expected_issuer("HTTPS://as.example:8443/realms/x/.well-known/oauth-authorization-server")
            == "https://as.example:8443/realms/x")
    assert _expected_issuer("https://as.example/metadata") is None
    assert _expected_issuer("https://as.example/.well-known/oauth-authorization-serverx") is None
    assert _expected_issuer("https://as.example/.well-known/openid-configuration?x=1") is None
    assert _expected_issuer("https://[::1/.well-known/openid-configuration") is None
    # a terminating "/" dropped from the issuer when the URL was built is accepted back
    assert discover("https://as.example/.well-known/openid-configuration",
                    _serve({"issuer": "https://as.example/"}))["issuer"] == "https://as.example/"
    # anything else names no issuer: the caller must say which one
    with pytest.raises(ValueError, match="issuer="):
        discover("https://as.example/metadata", _serve(METADATA))


def test_discover_requires_https():
    calls = []

    def get(url):
        calls.append(url)
        return json.dumps({"issuer": "http://issuer.example.com"})

    with pytest.raises(ValueError, match="metadata URL"):
        discover("http://issuer.example.com/.well-known/oauth-authorization-server", get)
    assert calls == []
    for name in ("jwks_uri", "introspection_endpoint"):
        with pytest.raises(TransportError, match=name):
            discover(WELL_KNOWN, _serve({"issuer": ISSUER, name: "http://issuer.example.com/x"}))
    with pytest.raises(TransportError, match="jwks_uri"):
        discover(WELL_KNOWN, _serve({"issuer": ISSUER, "jwks_uri": ["https://x"]}))
    doc = {"issuer": "http://issuer.example.com", "jwks_uri": "http://issuer.example.com/jwks"}
    assert discover("http://issuer.example.com/.well-known/oauth-authorization-server", _serve(doc),
                    allow_insecure=True) == doc


@pytest.mark.parametrize("body", [
    json.dumps([METADATA]),
    '{"issuer": "https://issuer.example.com", "issuer": "https://attacker.example"}',
    '{"issuer": "https://issuer.example.com", "x": NaN}',
    '{"issuer": "https://issuer.example.com", "x": ' + "[" * 2000 + "]" * 2000 + "}",
])
def test_discover_parses_strictly(body):
    # one strict JSON object: no arrays, duplicates, NaN or unbounded nesting (which raised RecursionError)
    with pytest.raises(TransportError):
        discover(WELL_KNOWN, _serve(body))


def test_the_validator_copy_does_not_normalise_token_types_twice():
    # typ "application/application/foo" normalises to "application/foo"; the copy must not strip a second prefix
    cfg = ValidatorConfig(ISSUER, AUDIENCE, accepted_token_types=["application/application/foo"])
    assert cfg.accepted_token_types == ("application/foo",)
    assert AccessTokenValidator(cfg).config.accepted_token_types == ("application/foo",)
