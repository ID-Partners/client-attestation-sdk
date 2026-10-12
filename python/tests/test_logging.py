"""Logging: the shared event vocabulary (docs/logging.md), silent by default, and never a credential.

The leak test runs every instrumented flow with the SDK's loggers at DEBUG and fails if any captured
message or attribute holds a JWT (`eyJ`), a challenge value, or private key material."""
import base64
import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest

from client_attestation_sdk import ClientAttestation, SigningKeyPair, StaticSvidSource, _http, _log
from client_attestation_sdk.errors import TransportError

AUD = "https://attester.example.com"  # the evidence_audience the fake attester's discovery document names

ATTESTER_KEY = SigningKeyPair.generate("ES256")
SVID = jwt.encode({"sub": "spiffe://example.org/workload", "aud": "https://attester.example.com"},
                  ATTESTER_KEY.private_key, algorithm="ES256")
CHALLENGE = "chal-SECRET-VALUE"


def _jwt(claims):
    return jwt.encode(claims, ATTESTER_KEY.private_key, algorithm="ES256", headers={"kid": ATTESTER_KEY.key_id})


class _Server(BaseHTTPRequestHandler):
    state = {}

    def log_message(self, *args):
        pass

    def _send(self, code, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        base = f"http://{self.headers['Host']}"
        if self.path == "/.well-known/client-attester":
            return self._send(200, {
                "attestation_endpoint": base + "/attest",
                "challenge_endpoint": base + "/challenge",
                "token_endpoint": base + "/token",
                "evidence_audience": "https://attester.example.com",
            })
        return self._resource()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        s = self.state
        if self.path == "/challenge":
            if s.get("challenge_down"):
                return self._send(503, {"error": "unavailable"})
            return self._send(200, {"attestation_challenge": CHALLENGE})
        if self.path == "/attest":
            body = json.loads(raw)
            return self._send(200, {"attestation": _jwt({"sub": "client-1", "cnf": {"jwk": body["instance_key"]}})})
        if self.path == "/token":
            dpop = self.headers.get("DPoP")
            if dpop and s.get("as_nonce") and jwt.decode(dpop, options={"verify_signature": False}).get(
                    "nonce") != s["as_nonce"]:
                return self._send(400, {"error": "use_dpop_nonce"}, {"DPoP-Nonce": s["as_nonce"]})
            if s.get("token_fails"):
                return self._send(400, {"error": "invalid_client"})
            return self._send(200, {"access_token": _jwt({"sub": "client-1", "n": time.time()}),
                                    "expires_in": 300, "token_type": "DPoP" if dpop else "Bearer"})
        return self._resource()

    def _resource(self):
        if self.headers.get("DPoP") and jwt.decode(self.headers["DPoP"], options={
                "verify_signature": False}).get("nonce") != "rs-n1":
            return self._send(401, {"error": "use_dpop_nonce"}, {
                "WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "rs-n1"})
        return self._send(200, {"ok": True})


@pytest.fixture()
def server():
    _Server.state = {}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Server)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    @property
    def events(self):
        return [getattr(r, "event", None) for r in self.records]

    def dump(self):
        """Everything a handler could write: the rendered message and the structured attributes."""
        return "\n".join(r.getMessage() + " " + json.dumps(getattr(r, "attributes", {}), default=str)
                         for r in self.records)


@pytest.fixture()
def capture():
    logger = logging.getLogger(_log.LOGGER_NAME)
    handler = _Capture()
    old = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    yield handler
    logger.removeHandler(handler)
    logger.setLevel(old)


class _Adapter:
    """A requests-shaped adapter over the SDK transport, enough to drive `requests_auth()`."""

    def send(self, request, **kwargs):
        import types
        raw = _http.request(request.method, request.url, headers=request.headers, body=request.body, timeout=2)
        response = types.SimpleNamespace(status_code=raw.status, headers=raw.headers, content=raw.body,
                                         request=request, connection=self, history=[], close=lambda: None,
                                         is_redirect=False)
        for hook in request.hooks["response"]:
            response = hook(response, **kwargs)
        return response


class _Request:
    def __init__(self, method, url, body=None):
        self.method, self.url, self.body, self.headers, self.hooks = method, url, body, {}, {"response": []}

    def register_hook(self, event, hook):
        self.hooks[event].append(hook)

    def copy(self):
        clone = _Request(self.method, self.url, self.body)
        clone.headers, clone.hooks = dict(self.headers), self.hooks
        return clone


def _assert_no_secrets(text, *secrets):
    assert "eyJ" not in text
    for secret in secrets:
        assert secret not in text
    for member in ("d", "p", "q", "dp", "dq", "qi", "k"):
        assert f'"{member}":' not in text


def test_silent_by_default():
    root = logging.getLogger(_log.LOGGER_NAME)
    assert any(isinstance(h, logging.NullHandler) for h in root.handlers)


def test_full_flows_log_the_vocabulary_and_never_a_credential(server, capture):
    # Bearer (PoP JWT): initial, cache hit, forced refresh.
    ca = ClientAttestation(server, evidence=StaticSvidSource(SVID), evidence_audience=AUD, timeout=2)
    ca.token()
    ca.token()
    ca.token(force_refresh=True)
    ca.token(asserted_context={"type": "t", "value": "v"})

    # DPoP combined: the AS demands its own nonce, then a resource does too.
    _Server.state["as_nonce"] = "as-n1"
    dpop = ClientAttestation(server, evidence=StaticSvidSource(SVID), evidence_audience=AUD, pop_method="dpop_combined", timeout=2)
    auth = dpop.requests_auth()
    assert _Adapter().send(auth(_Request("POST", server + "/api?q=secret-query", b"x"))).status_code == 200

    # Challenge endpoint down with require_challenge=False, then a token endpoint that refuses.
    _Server.state.update(challenge_down=True, token_fails=True, as_nonce=None)
    lax = ClientAttestation(server, evidence=StaticSvidSource(SVID), evidence_audience=AUD, require_challenge=False, timeout=2)
    with pytest.raises(TransportError):
        lax.token()

    events = capture.events
    for name in ("token.refreshing", "discovery.fetched", "discovery.cached", "evidence.obtained",
                 "challenge.fetched", "attestation.minted", "token.obtained", "token.cache_hit",
                 "dpop.nonce_retry", "challenge.skipped", "http.failed"):
        assert name in events, name
    reasons = [r.attributes["reason"] for r in capture.records if r.event == "token.refreshing"]
    assert reasons[:4] == ["initial", "forced", "asserted_context", "initial"]
    retries = [r.attributes["at"] for r in capture.records if r.event == "dpop.nonce_retry"]
    assert retries == ["token_endpoint", "resource"]
    obtained = [r.attributes for r in capture.records if r.event == "token.obtained"]
    assert obtained[0]["token_type"] == "Bearer" and obtained[0]["expires_in"] == 300
    assert obtained[0]["client_id"] == "client-1"
    assert obtained[-1]["token_type"] == "DPoP" and obtained[-1]["pop_method"] == "dpop_combined"
    failures = [r.attributes for r in capture.records if r.event == "http.failed"]
    assert {"step": "challenge", "status": 503, "reason": "status"}.items() <= failures[0].items()
    assert {"step": "token", "status": 400, "reason": "status", "path": "/token"}.items() <= failures[-1].items()
    # The nonce challenge that was retried is not a failure.
    assert not any(f.get("status") == 400 and f.get("step") == "token" for f in failures[:-1])

    _assert_no_secrets(capture.dump(), CHALLENGE, "as-n1", "rs-n1", "secret-query")


def test_transport_failure_is_classified(capture):
    ca = ClientAttestation("http://127.0.0.1:9", evidence=StaticSvidSource(SVID), evidence_audience=AUD, timeout=1)
    with pytest.raises(TransportError):
        ca.token()
    failed = [r.attributes for r in capture.records if r.event == "http.failed"]
    assert failed and failed[0]["reason"] == "network" and failed[0]["step"] == "discover"
    assert "status" not in failed[0]


def test_failure_reason_classification():
    assert _log.failure_reason(TransportError("x returned HTTP 302", status=302)) == "redirect"
    assert _log.failure_reason(TransportError("body is larger than 10 bytes", status=200)) == "too_large"
    assert _log.failure_reason(TransportError("x returned malformed JSON: y", status=200)) == "malformed"
    assert _log.failure_reason(TransportError("x returned HTTP 500", status=500)) == "status"
    assert _log.failure_reason(TransportError("GET x failed: timed out")) == "timeout"
    assert _log.failure_reason(TransportError("GET x failed: refused")) == "network"
    assert _log.host("https://user:pw@[::1]:8443/a?b=c") == "[::1]:8443"
    assert _log.host("not a url") is None
    assert _log.path("https://h") == "/"


def test_emit_redacts_jwt_values_and_credential_keys(capture):
    logger = _log.get("test")
    _log.emit(logger, logging.INFO, "x.y", leaked=SVID, access_token="opaque", flag=True, empty="", none=None)
    record = capture.records[-1]
    assert record.attributes["leaked"].startswith("<redacted:")
    assert record.attributes["access_token"].startswith("<redacted:")
    assert "none" not in record.attributes
    assert record.getMessage().startswith('x.y leaked="<redacted:') and "flag=true" in record.getMessage()
    _assert_no_secrets(capture.dump(), "opaque")


# Synthetic, built here so no scanner mistakes them for real ones.
VAULT_TOKENS = tuple(prefix + "TESTONLY" * 3 + suffix for prefix in ("hvs.", "hvb.", "hvr.", "s.", "b.", "r.")
                     for suffix in ("", "-_x9"))


@pytest.mark.parametrize("key", ["auth_req_id", "code", "handle", "token", "secret", "password",
                                 "assertion", "client_assertion", "vault_token", "x-vault-token",
                                 "X-Vault-Token", "Authorization", "dpop", "private_key", "refresh_token",
                                 "session_token", "api-token", "client_secret", "db_password"])
def test_emit_redacts_any_value_under_a_credential_key(capture, key):
    _log.emit(_log.get("test"), logging.INFO, "x.y", **{key: "opaque-value-123", "n": 7})
    record = capture.records[-1]
    assert record.attributes[key] == "<redacted:16 bytes>" and record.attributes["n"] == 7
    _assert_no_secrets(capture.dump(), "opaque-value-123")


@pytest.mark.parametrize("value", [*VAULT_TOKENS, *(f"X-Vault-Token: {t}" for t in VAULT_TOKENS),
                                   "Bearer 2YotnFZFEjr1zCsicMWpAA", "DPoP 2YotnFZFEjr1zCsicMWpAA",
                                   "bearer opaque", "Basic YWxhZGRpbjpvcGVuc2VzYW1l",
                                   " Bearer 2YotnFZFEjr1zCsicMWpAA",
                                   "Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA"])
def test_emit_redacts_values_that_carry_a_credential(capture, value):
    _log.emit(_log.get("test"), logging.INFO, "x.y", detail=value)
    assert capture.records[-1].attributes["detail"].startswith("<redacted:")
    _assert_no_secrets(capture.dump(), value)


def _redaction_cases():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "validation", "redaction.json")
    with open(path) as fh:
        return [(c["key"], c["value"], c["redacted"]) for c in json.load(fh)["cases"]]


@pytest.mark.parametrize("key,value,redacted", _redaction_cases())
def test_emit_redaction_shared_cases(capture, key, value, redacted):
    # validation/redaction.json: the Go, Java and TypeScript tests read the same cases.
    _log.emit(_log.get("test"), logging.INFO, "x.y", **{key: value})
    got = capture.records[-1].attributes[key]
    if redacted:
        assert isinstance(got, str) and got.startswith("<redacted:")
    else:
        assert got == value


def test_emit_keeps_ordinary_attributes(capture):
    """A backstop, not a filter: the vocabulary in docs/logging.md passes through untouched."""
    attrs = {"host": "pf.example.com:9031", "path": "/as/token.oauth2", "method": "POST", "status": 400,
             "step": "ciba_poll", "reason": "timeout", "token_type": "Bearer", "pop_method": "dpop_combined",
             "client_id": "urn:agent:x", "alg": "ES256", "source": "StaticSvidSource", "at": "token_endpoint",
             "keys": 3, "result": "invalid_audience", "mode": "introspection", "resolver": "ciba",
             "kind": "resource_authorisation", "outcome": "pending", "channel": "device", "reused": False,
             "fallback": "bubble_up", "ok": True, "interval": 5, "error": "authorization_pending",
             "expires_in": 120, "detail": "s.example.com", "other": "hvs.short", "label": "bob.smith",
             "host2": "vault.s.abcdefghijklmnopqrstuvwxyz.internal", "word": "DPoP", "scheme": "Bearer"}
    _log.emit(_log.get("test"), logging.INFO, "token.obtained", **attrs)
    assert capture.records[-1].attributes == attrs
    assert "<redacted" not in capture.records[-1].getMessage()


def test_validator_logs_verdicts_and_jwks_activity(capture):
    from client_attestation_sdk.token_validator import AccessTokenValidator, ValidatorConfig, errors

    key = SigningKeyPair.generate("ES256")
    jwks = json.dumps({"keys": [{**key.public_jwk(), "kid": key.key_id}]})
    calls = {"n": 0}

    def get(url):
        calls["n"] += 1
        if calls["n"] == 2:
            raise TransportError("GET https://as/jwks returned HTTP 500", status=500)
        if calls["n"] == 3:
            return "not json"
        return jwks

    validator = AccessTokenValidator(
        ValidatorConfig("https://as", ["https://rs"], jwks_uri="https://as/jwks?tenant=secret"), http_get=get)
    good = jwt.encode({"iss": "https://as", "aud": "https://rs", "exp": 4102444800}, key.private_key,
                      algorithm="ES256", headers={"kid": key.key_id, "typ": "at+jwt"})
    expired = jwt.encode({"iss": "https://as", "aud": "https://rs", "exp": 1000}, key.private_key,
                         algorithm="ES256", headers={"kid": key.key_id, "typ": "at+jwt"})
    unknown = jwt.encode({"iss": "https://as", "aud": "https://rs", "exp": 4102444800}, key.private_key,
                         algorithm="ES256", headers={"kid": "nope", "typ": "at+jwt"})
    assert validator.validate(good).valid
    assert validator.validate(expired).error == errors.EXPIRED
    assert validator.validate(unknown).error == errors.KEY_NOT_FOUND  # throttled: fetched moments ago
    assert validator.validate(unknown).error == errors.KEY_NOT_FOUND  # throttled

    validator._jwks._min_refresh = 0
    validator.validate(unknown)  # fetch fails: HTTP 500
    validator.validate(unknown)  # fetch fails: malformed

    verdicts = [(r.attributes["result"], r.levelno) for r in capture.records if r.event == "token.validated"]
    assert verdicts[:3] == [("valid", logging.DEBUG), ("expired", logging.INFO), ("key_not_found", logging.INFO)]
    assert "jwks.fetched" in capture.events and "jwks.refetch_throttled" in capture.events
    fetched = [r.attributes for r in capture.records if r.event == "jwks.fetched"]
    assert fetched[0] == {"host": "as", "keys": 1}
    failed = [r.attributes for r in capture.records if r.event == "jwks.fetch_failed"]
    assert failed == [{"host": "as", "reason": "status", "status": 500}, {"host": "as", "reason": "malformed"}]
    _assert_no_secrets(capture.dump(), "tenant=secret")


def test_introspection_verdict_and_failure(capture):
    from client_attestation_sdk.token_validator import AccessTokenValidator, IntrospectionConfig, ValidatorConfig

    answers = [{"active": True, "scope": "a", "aud": "https://rs"}, {"active": False}]

    def post(url, body, headers):
        if not answers:
            raise TransportError("POST https://as/introspect failed: timed out")
        return answers.pop(0)

    config = ValidatorConfig("https://as", ["https://rs"], jwks={"keys": []},
                             introspection=IntrospectionConfig("https://as/introspect", "rs", "s3cret-value"))
    validator = AccessTokenValidator(config, http_post=post)
    assert validator.validate_active(SVID).valid
    assert not validator.validate_active(SVID).valid
    with pytest.raises(TransportError):
        validator.validate_active(SVID)
    verdicts = [r.attributes for r in capture.records if r.event == "token.validated"]
    assert verdicts == [{"result": "valid", "mode": "introspection"}, {"result": "inactive", "mode": "introspection"}]
    failed = [r.attributes for r in capture.records if r.event == "http.failed"]
    assert failed == [{"step": "introspection", "method": "POST", "host": "as", "path": "/introspect",
                       "reason": "timeout"}]
    _assert_no_secrets(capture.dump(), "s3cret-value")


def test_authz_ceremony_logs_outcomes_not_codes(capture):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from client_attestation_sdk.authz_challenge import (APPROVED, CHANNEL_DEVICE, CibaClient, CibaResolver, Hooks, Pending,
                                 PrivateKeyJwtAuth, parse_challenge)

    bc, tok = "https://pf.example/as/bc-auth.ciba", "https://pf.example/as/token.oauth2"

    class FakeAS:
        token_answers, refuse = [], False

        def __call__(self, method, url, form, headers):
            if url == bc:
                if self.refuse:
                    return 400, json.dumps({"error": "unknown_user_id"})
                return 200, json.dumps({"auth_req_id": "req-1", "interval": 3, "expires_in": 120})
            if self.token_answers:
                return self.token_answers.pop(0)
            return 400, json.dumps({"error": "authorization_pending"})

    class Clock:
        t = 2_000_000.0

        def __call__(self):
            return self.t

    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    fake, clock = FakeAS(), Clock()
    client = CibaClient(bc_auth_endpoint=bc, token_endpoint=tok, client_id="urn:agent:x",
                        client_auth=PrivateKeyJwtAuth(client_id="urn:agent:x", private_key_pem=pem, kid="k"),
                        issuer="https://localhost:9031", http=fake, clock=clock)
    resolver = CibaResolver(client, Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0), clock=clock)
    AUTHZ_CHALLENGE = parse_challenge(401, {}, {"error": "insufficient_scope", "scope": "pay"})
    INSTR = {"amount": "9000", "currency": "AUD"}
    res = resolver.resolve(AUTHZ_CHALLENGE, subject="alice", instruction=INSTR, initiator="urn:agent:x")
    assert isinstance(res, Pending)
    resolver.poll(res.code)
    fake.token_answers = [(200, json.dumps({"access_token": SVID}))]
    clock.t += 4
    assert resolver.poll(res.code).status == APPROVED
    assert not resolver.verify_resume(res.code, subject="mallory", instruction=INSTR)[0]
    assert resolver.verify_resume(res.code, subject="alice", instruction=INSTR)[0]

    # bc-auth refused
    fake.refuse = True
    resolver.resolve(AUTHZ_CHALLENGE, subject="bob", instruction=INSTR, initiator="urn:agent:x")

    events = capture.events
    for name in ("authz.ciba_requested", "authz.ciba_polled", "authz.resolve", "authz.poll",
                 "authz.resume_verified", "http.failed"):
        assert name in events, name
    resolves = [r.attributes for r in capture.records if r.event == "authz.resolve"]
    assert resolves[0] == {"resolver": "ciba", "kind": res.kind, "outcome": "pending", "channel": "device",
                           "reused": False}
    assert resolves[-1]["outcome"] == "unavailable" and resolves[-1]["fallback"] == "bubble_up"
    resumes = [r.attributes for r in capture.records if r.event == "authz.resume_verified"]
    assert resumes[0]["ok"] is False and resumes[0]["reason"] == "ceremony subject does not match"
    assert resumes[1] == {"resolver": "ciba", "ok": True}
    polled = [r.attributes for r in capture.records if r.event == "authz.ciba_polled"]
    assert polled[-1] == {"outcome": "approved", "status": 200}
    failed = [r.attributes for r in capture.records if r.event == "http.failed"]
    assert failed[-1]["step"] == "ciba_request" and failed[-1]["host"] == "pf.example"
    dump = capture.dump()
    _assert_no_secrets(dump, res.code, res.reference, "alice", "9000", "req-1")
    assert bc not in dump and "PRIVATE KEY" not in dump
