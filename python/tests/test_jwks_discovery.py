import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import ed25519

from client_attestation_sdk import SigningKeyPair
from client_attestation_sdk.token_validator import discover
from client_attestation_sdk.token_validator.jwks import JwksProvider


class JsonServer:
    """Serves one fixed JSON document on every GET, so the default urllib transports can be exercised
    without external network."""

    def __init__(self, body):
        self._body = body
        self._server = HTTPServer(("127.0.0.1", 0), self._handler())
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def close(self):
        self._server.shutdown()

    def _handler(srv):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                data = srv._body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return Handler


def _jwk(algorithm, kid):
    jwk = SigningKeyPair.generate(algorithm).public_jwk()
    jwk["kid"] = kid
    jwk.pop("alg", None)
    return jwk


def _okp_jwk(kid):
    public = ed25519.Ed25519PrivateKey.generate().public_key()
    jwk = json.loads(jwt.get_algorithm_by_name("EdDSA").to_jwk(public))
    jwk["kid"] = kid
    return jwk


def test_algorithm_inferred_from_key_type_and_bad_keys_skipped():
    jwks = {"keys": [
        _jwk("ES256", "ec-key"),                            # EC without alg -> ES256
        _jwk("RS256", "rsa-key"),                           # RSA without alg -> RS256
        _okp_jwk("okp-key"),                                # OKP without alg -> EdDSA
        {"kty": "oct", "kid": "oct-key", "k": "c2VjcmV0"},  # unknown kty -> RS256 default, unloadable
        {"kty": "EC", "crv": "P-256", "kid": "broken"},     # malformed (no coordinates), skipped
    ]}
    provider = JwksProvider(jwks=jwks)
    assert provider.resolve("ec-key") is not None
    assert provider.resolve("rsa-key") is not None
    assert provider.resolve("okp-key") is not None
    assert provider.resolve("oct-key") is None
    assert provider.resolve("broken") is None


def test_resolve_without_kid_falls_back_to_single_key():
    provider = JwksProvider(jwks={"keys": [_jwk("ES256", "only-key")]})
    assert provider.resolve(None) is not None


def test_resolve_unknown_kid_from_static_jwks_returns_none():
    provider = JwksProvider(jwks={"keys": [_jwk("ES256", "only-key")]})
    assert provider.resolve("nope") is None


def test_jwks_uri_fetched_on_demand_with_injected_transport():
    document = {"keys": [_jwk("ES256", "remote-key")]}
    fetched = []

    def fake_get(url):
        fetched.append(url)
        return json.dumps(document)

    provider = JwksProvider(jwks_uri="https://issuer.example.com/jwks", http_get=fake_get)
    assert provider.resolve("remote-key") is not None
    assert fetched == ["https://issuer.example.com/jwks"]
    assert provider.resolve("still-unknown") is None


def test_jwks_uri_default_transport_fetches_over_http():
    server = JsonServer(json.dumps({"keys": [_jwk("ES256", "served-key")]}))
    try:
        provider = JwksProvider(jwks_uri=server.url + "/jwks")
        assert provider.resolve("served-key") is not None
    finally:
        server.close()


def test_discover_fetches_metadata_document():
    metadata = {
        "issuer": "https://issuer.example.com",
        "jwks_uri": "https://issuer.example.com/jwks",
        "introspection_endpoint": "https://issuer.example.com/introspect",
    }
    server = JsonServer(json.dumps(metadata))
    try:
        assert discover(server.url + "/.well-known/oauth-authorization-server") == metadata
    finally:
        server.close()


def test_discover_with_injected_transport():
    metadata = {"issuer": "https://issuer.example.com"}
    assert discover("https://issuer.example.com/.well-known/oauth-authorization-server",
                    http_get=lambda url: json.dumps(metadata)) == metadata


# -- refresh policy: cooldown, single flight, max age, failure handling --


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _counting_get(document):
    calls = []

    def get(url):
        calls.append(url)
        if isinstance(document, Exception):
            raise document
        return json.dumps(document) if not callable(document) else json.dumps(document())

    return get, calls


def test_unknown_kids_cannot_force_a_fetch_per_request():
    get, calls = _counting_get({"keys": [_jwk("ES256", "real")]})
    clock = FakeClock()
    provider = JwksProvider(jwks_uri="https://as/jwks", http_get=get, clock=clock)
    assert provider.resolve("real") is not None
    for i in range(100):
        assert provider.resolve(f"made-up-{i}") is None
    assert len(calls) == 1
    clock.now += 30
    provider.resolve("made-up-again")
    assert len(calls) == 2


def test_concurrent_misses_share_one_fetch():
    started = threading.Event()
    release = threading.Event()
    calls = []

    def slow_get(url):
        calls.append(url)
        started.set()
        release.wait(5)
        return json.dumps({"keys": [_jwk("ES256", "k")]})

    provider = JwksProvider(jwks_uri="https://as/jwks", http_get=slow_get)
    results = []
    threads = [threading.Thread(target=lambda: results.append(provider.resolve("k"))) for _ in range(10)]
    for t in threads:
        t.start()
    started.wait(5)
    release.set()
    for t in threads:
        t.join(5)
    assert len(calls) == 1
    assert len(results) == 10 and all(r is not None for r in results)


def test_keys_are_refreshed_once_they_are_old():
    rotation = {"kid": "old"}
    get, calls = _counting_get(lambda: {"keys": [_jwk("ES256", rotation["kid"])]})
    clock = FakeClock()
    provider = JwksProvider(jwks_uri="https://as/jwks", http_get=get, clock=clock, max_age_seconds=600)
    assert provider.resolve("old") is not None
    rotation["kid"] = "new"
    clock.now += 599
    assert provider.resolve("old") is not None and len(calls) == 1
    clock.now += 1
    assert provider.resolve("old") is None
    assert provider.resolve("new") is not None and len(calls) == 2


def test_a_failed_refresh_keeps_the_keys_already_held():
    state = {"fail": False}

    def get(url):
        if state["fail"]:
            raise OSError("issuer down")
        return json.dumps({"keys": [_jwk("ES256", "k")]})

    clock = FakeClock()
    provider = JwksProvider(jwks_uri="https://as/jwks", http_get=get, clock=clock, max_age_seconds=60)
    assert provider.resolve("k") is not None
    state["fail"] = True
    clock.now += 120
    assert provider.resolve("k") is not None
    assert "issuer down" in provider.last_error


def test_fetch_failure_is_key_not_found_not_an_exception():
    from client_attestation_sdk.token_validator import AccessTokenValidator, ValidatorConfig, errors

    key = SigningKeyPair.generate("ES256")

    def get(url):
        raise OSError("connection refused")

    validator = AccessTokenValidator(
        ValidatorConfig("https://as", ["https://rs"], jwks_uri="https://as/jwks"), http_get=get)
    token = jwt.encode({"iss": "https://as", "aud": "https://rs", "exp": 4102444800}, key.private_key,
                       algorithm="ES256", headers={"kid": key.key_id, "typ": "at+jwt"})
    result = validator.validate(token)
    assert result.error == errors.KEY_NOT_FOUND
    assert "connection refused" in result.error_description


def test_oversized_jwks_is_refused():
    get, _ = _counting_get({"keys": [], "padding": "x" * (512 * 1024)})
    provider = JwksProvider(jwks_uri="https://as/jwks", http_get=get)
    assert provider.resolve("any") is None
    assert "larger than" in provider.last_error


def test_default_transport_refuses_an_oversized_body():
    server = JsonServer(json.dumps({"keys": [], "padding": "x" * (512 * 1024)}))
    try:
        provider = JwksProvider(jwks_uri=server.url + "/jwks")
        assert provider.resolve("any") is None
        assert "larger than" in provider.last_error
    finally:
        server.close()
