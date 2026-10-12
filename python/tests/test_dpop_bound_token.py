"""dpop_combined end to end: a DPoP-bound token from a fake AS used at a fake resource that checks the
proof the way RFC 9449 says a resource must (signature by the header jwk, jkt = the token's binding,
htm, htu, ath, nonce). Plus the token-endpoint use_dpop_nonce retry, Bearer mode unchanged, and the
request helpers' one-shot nonce retry. Local fake servers only."""
import base64
import hashlib
import json
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest

from client_attestation_sdk import ClientAttestation, ClientAttestationError, DpopProofBuilder, SigningKeyPair
from client_attestation_sdk import StaticSvidSource, _http
from client_attestation_sdk import token_source as ts
from client_attestation_sdk.builders import _access_token_hash as access_token_hash, _normalize_htu as normalize_htu
from client_attestation_sdk.keys import _thumbprint
from client_attestation_sdk.token_source import _is_nonce_challenge, _origin, _token_type

AUD = "https://attester.example.com"  # the evidence_audience the fake attester's discovery document names


def _seg(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _verify_proof(proof):
    """Verify a DPoP proof with the key in its own header; return (claims, jkt of that key)."""
    header = jwt.get_unverified_header(proof)
    assert header["typ"] == "dpop+jwt"
    key = jwt.PyJWK(header["jwk"], algorithm=header["alg"])
    claims = jwt.decode(proof, key.key, algorithms=[header["alg"]])
    return claims, _thumbprint(header["jwk"])


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

    def _body(self):
        # Read the whole request body before answering, chunked included (a streamed body has no
        # Content-Length). Answering first and closing races the client's write: a broken pipe in CI.
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            raw = b""
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return raw
                raw += self.rfile.read(size)
                self.rfile.readline()
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    @property
    def base(self):
        return f"http://{self.headers['Host']}"

    def do_GET(self):
        if self.path == "/.well-known/client-attester":
            return self._send(200, {
                "attestation_endpoint": self.base + "/attest",
                "challenge_endpoint": self.base + "/challenge",
                "token_endpoint": self.base + "/token",
                "evidence_audience": "https://attester.example.com",
            })
        return self._resource(b"")

    def do_POST(self):
        raw = self._body()
        s = self.state
        if self.path == "/challenge":
            return self._send(200, {"attestation_challenge": "chal-1"})
        if self.path == "/attest":
            body = json.loads(raw)
            s["minted_jkt"] = _thumbprint(body["instance_key"])
            claims = {"sub": "c-1", "cnf": {"jwk": body["instance_key"]}}
            return self._send(200, {"attestation": "h." + _seg(claims) + ".sig"})
        if self.path == "/token":
            s["token_calls"] += 1
            claims, jkt = _verify_proof(self.headers["DPoP"])
            assert claims["htm"] == "POST" and claims["htu"] == self.base + "/token"
            assert jkt == s["minted_jkt"]  # the proof key is the attestation's cnf key
            if s["as_nonce"] and claims.get("nonce") != s["as_nonce"]:
                return self._send(400, {"error": "use_dpop_nonce"}, {"DPoP-Nonce": s["as_nonce"]})
            token = f"AT-{s['token_calls']}"
            s["bound"][token] = jkt
            return self._send(200, {"access_token": token, "expires_in": 300, "token_type": s["token_type"]})
        return self._resource(raw)

    def do_PUT(self):
        return self._resource(self._body())

    def _resource(self, raw):
        s = self.state
        s["resource_calls"] += 1
        scheme, _, token = (self.headers.get("Authorization") or "").partition(" ")
        if s["token_type"] == "Bearer":
            assert scheme == "Bearer" and self.headers.get("DPoP") is None
            return self._send(200, {"ok": True, "body": raw.decode()})
        assert scheme == "DPoP"
        claims, jkt = _verify_proof(self.headers["DPoP"])
        assert jkt == s["bound"][token], "proof key must be the key the token is bound to"
        assert claims["htm"] == self.command
        s["targets"].append((self.base + self.path.split("?")[0], claims["htu"]))
        assert claims["htu"] == self.base + self.path.split("?")[0]
        assert claims["ath"] == base64.urlsafe_b64encode(
            hashlib.sha256(token.encode()).digest()).rstrip(b"=").decode()
        s["resource_jkts"].append(jkt)
        if claims.get("nonce") != s["rs_nonce"]:
            return self._send(401, {"error": "use_dpop_nonce"}, {
                "WWW-Authenticate": 'DPoP error="use_dpop_nonce", error_description="nonce required"',
                "DPoP-Nonce": s["rs_nonce"]})
        return self._send(200, {"ok": True, "body": raw.decode()})


@pytest.fixture()
def server():
    _Server.state = {"token_type": "DPoP", "as_nonce": None, "rs_nonce": "rs-n1", "token_calls": 0,
                     "resource_calls": 0, "bound": {}, "resource_jkts": [], "targets": []}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Server)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _ca(url, **kwargs):
    return ClientAttestation(url, evidence=StaticSvidSource("svid"), evidence_audience=AUD, pop_method="dpop_combined",
                             timeout=2, **kwargs)


def _send(url, method, headers, body=None):
    return _http.request(method, url, headers=headers, body=body, timeout=2)


# ── request_headers against a verifying resource ────────────────────────────────────────────────

def test_request_headers_nonce_round_trip_and_key_lifecycle(server):
    ca = _ca(server)
    api = server + "/api/things?page=2#frag"

    first = ca.request_headers("get", api)
    assert first["Authorization"] == "DPoP AT-1"
    response = _send(api, "GET", first)
    assert response.status == 401 and response.headers["DPoP-Nonce"] == "rs-n1"
    assert ca._observe_response(api, response.status, response.headers, response.body) == "rs-n1"

    second = ca.request_headers("GET", api)
    assert _send(api, "GET", second).status == 200
    assert jwt.decode(second["DPoP"], options={"verify_signature": False})["nonce"] == "rs-n1"

    # The bound key survives while the token is cached, and changes once a new token is minted.
    assert _send(api, "GET", ca.request_headers("GET", api)).status == 200
    jkts = _Server.state["resource_jkts"]
    assert len(set(jkts)) == 1 and _Server.state["token_calls"] == 1
    ca.token(force_refresh=True)
    assert _send(api, "GET", ca.request_headers("GET", api)).status == 200
    assert _Server.state["resource_jkts"][-1] != jkts[0]
    assert _Server.state["token_calls"] == 2

    assert ca.authorization_header() == {"Authorization": "DPoP AT-2"}


def test_token_endpoint_use_dpop_nonce_is_retried_once(server):
    _Server.state["as_nonce"] = "as-n1"
    trace = []
    ca = _ca(server, trace=trace)
    assert ca.token() == "AT-2"
    assert _Server.state["token_calls"] == 2  # rejected once, then accepted with the server's nonce
    assert [r["step"] for r in trace][-2:] == ["token", "token"]
    # The AS nonce is remembered for that origin.
    assert ca._nonce_for(server + "/token") == "as-n1"


def test_bearer_mode_is_unchanged(server):
    _Server.state["token_type"] = "Bearer"
    ca = _ca(server)
    headers = ca.request_headers("POST", server + "/api")
    assert headers == {"Authorization": "Bearer AT-1"}
    assert ca.authorization_header() == headers
    assert _send(server + "/api", "POST", headers, b"x").status == 200


def test_token_type_parsing():
    assert _token_type({"token_type": "dpop"}) == "DPoP"
    assert _token_type({"token_type": "DPoP"}) == "DPoP"
    assert _token_type({"token_type": "bearer"}) == "Bearer"
    assert _token_type({}) == "Bearer"


# ── requests_auth (driven through a minimal requests-shaped adapter over the SDK transport) ─────

class _Hooks:
    def __init__(self):
        self.hooks = {"response": []}

    def register_hook(self, event, hook):
        self.hooks[event].append(hook)


class _PreparedRequest(_Hooks):
    def __init__(self, method, url, body=None):
        super().__init__()
        self.method, self.url, self.body, self.headers = method, url, body, {}

    def copy(self):
        clone = _PreparedRequest(self.method, self.url, self.body)
        clone.headers = dict(self.headers)
        clone.hooks = self.hooks
        return clone


class _Adapter:
    sent = []
    sent_headers = []  # the headers as sent: the hook takes credentials off a request once it is answered

    def send(self, request, **kwargs):
        type(self).sent.append(request)
        type(self).sent_headers.append(dict(request.headers))
        raw = _http.request(request.method, request.url, headers=request.headers, body=request.body, timeout=2)
        response = types.SimpleNamespace(status_code=raw.status, headers=raw.headers, content=raw.body,
                                         request=request, connection=self, history=[], close=lambda: None,
                                         is_redirect=False)
        for hook in request.hooks["response"]:
            response = hook(response, **kwargs)
        return response


def _requests_call(auth, method, url, body=None):
    _Adapter.sent, _Adapter.sent_headers = [], []
    return _Adapter().send(auth(_PreparedRequest(method, url, body)))


def test_requests_auth_retries_once_on_a_nonce_challenge(server):
    ca = _ca(server)
    response = _requests_call(ca.requests_auth(), "POST", server + "/api", b"payload")
    assert response.status_code == 200
    assert json.loads(response.content)["body"] == "payload"
    assert len(_Adapter.sent) == 2 and len(response.history) == 1
    # A second request already knows the nonce: no challenge, no retry.
    response = _requests_call(ca.requests_auth(), "POST", server + "/api", b"again")
    assert response.status_code == 200 and len(_Adapter.sent) == 1


def test_requests_auth_does_not_replay_a_stream_body(server):
    ca = _ca(server)
    response = _requests_call(ca.requests_auth(), "POST", server + "/api", iter([b"x"]))
    assert response.status_code == 401 and len(_Adapter.sent) == 1


def test_requests_auth_bearer_registers_no_hook(server):
    _Server.state["token_type"] = "Bearer"
    request = _ca(server).requests_auth()(
        _PreparedRequest("GET", server + "/api"))
    assert request.headers == {"Authorization": "Bearer AT-1"} and request.hooks["response"] == []


# ── httpx_auth (a stand-in httpx module; the flow is the generator httpx drives) ────────────────

@pytest.fixture()
def fake_httpx(monkeypatch):
    module = types.ModuleType("httpx")

    class Auth:
        pass

    class ByteStream:
        def __init__(self, data):
            self.data = data

    class SyncByteStream:
        pass

    class ResponseNotRead(Exception):
        pass

    module.Auth, module.ByteStream, module.SyncByteStream, module.ResponseNotRead = (
        Auth, ByteStream, SyncByteStream, ResponseNotRead)
    monkeypatch.setitem(sys.modules, "httpx", module)
    return module


def _drive(flow, method, url, body):
    sent = []
    request = next(flow)
    while True:
        sent.append(dict(request.headers))
        raw = _http.request(method, url, headers=request.headers, body=body, timeout=2)
        response = types.SimpleNamespace(status_code=raw.status, headers=raw.headers, content=raw.body,
                                         history=[])
        try:
            request = flow.send(response)
        except StopIteration:
            return raw, sent


def test_httpx_auth_retries_once_on_a_nonce_challenge(server, fake_httpx):
    ca = _ca(server)
    url = server + "/api"
    request = types.SimpleNamespace(method="PUT", url=url, headers={}, stream=fake_httpx.ByteStream(b"b"))
    raw, sent = _drive(ca.httpx_auth().auth_flow(request), "PUT", url, b"b")
    assert raw.status == 200 and len(sent) == 2

    streamed = types.SimpleNamespace(method="PUT", url=url, headers={}, stream=object())
    ca._dpop_nonces.clear()
    raw, sent = _drive(ca.httpx_auth().auth_flow(streamed), "PUT", url, b"b")
    assert raw.status == 401 and len(sent) == 1  # a non-replayable body is not re-sent


def test_httpx_auth_bearer_is_a_single_pass(server, fake_httpx):
    _Server.state["token_type"] = "Bearer"
    ca = _ca(server)
    request = types.SimpleNamespace(method="GET", url=server + "/api", headers={}, stream=None)
    raw, sent = _drive(ca.httpx_auth().auth_flow(request), "GET", server + "/api", None)
    assert raw.status == 200 and sent == [{"Authorization": "Bearer AT-1"}]


# ── helpers and the low-level builder ───────────────────────────────────────────────────────────

def test_nonce_challenge_detection():
    nonce = {"DPoP-Nonce": "n"}
    assert _is_nonce_challenge(401, {"WWW-Authenticate": 'DPoP error="use_dpop_nonce"', **nonce}, b"")
    assert _is_nonce_challenge(401, {"WWW-Authenticate": 'Bearer realm="x", DPoP error=use_dpop_nonce'}, b"")
    assert not _is_nonce_challenge(401, {"WWW-Authenticate": 'Bearer error="use_dpop_nonce"'}, b"")
    assert not _is_nonce_challenge(401, {"WWW-Authenticate": 'DPoP error="invalid_token"'}, b"")
    assert _is_nonce_challenge(400, {}, lambda: b'{"error": "use_dpop_nonce"}')
    assert not _is_nonce_challenge(400, {}, b'{"error": "invalid_grant"}')
    assert not _is_nonce_challenge(400, {}, b"not json")
    assert not _is_nonce_challenge(500, {}, b"")


def test_origin_and_htu_normalisation():
    assert _origin("https://API.example.com/x?y") == "https://api.example.com"
    assert _origin("https://api.example.com:443/x") == "https://api.example.com"
    assert _origin("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"
    assert _origin("http://[::1]:80/a") == "http://[::1]"
    assert normalize_htu("HTTPS://user:pw@API.example.com:8443/a/b?q=1#f") == "https://api.example.com:8443/a/b"
    assert normalize_htu("https://as.example:443?x=1") == "https://as.example"
    assert normalize_htu("http://as.example:80/t") == "http://as.example/t"


def test_dpop_builder_upper_cases_htm_strips_query_and_sets_ath():
    key = SigningKeyPair.generate("ES256")
    proof = (DpopProofBuilder(key).method("get").uri("https://rs.example.com/r?x=1#y")
             .access_token("AT-1").build())
    claims = jwt.decode(proof, options={"verify_signature": False})
    assert claims["htm"] == "GET"
    assert claims["htu"] == "https://rs.example.com/r"
    assert claims["ath"] == access_token_hash("AT-1")
    plain = jwt.decode(DpopProofBuilder(key).uri("https://as/t").build(), options={"verify_signature": False})
    assert "ath" not in plain and plain["htm"] == "POST"


# ── credentials never follow a redirect (real requests and httpx) ───────────────────────────────

class _Recorder(BaseHTTPRequestHandler):
    """A redirect target that records what it was sent and answers like a resource demanding a DPoP
    nonce, which is what would make a helper re-sign and re-send."""
    seen = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).seen.append({k.lower(): v for k, v in self.headers.items()})
        body = b'{"error":"use_dpop_nonce"}'
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'DPoP error="use_dpop_nonce"')
        self.send_header("DPoP-Nonce", "attacker-nonce")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _nonce_challenge(handler, nonce):
    body = b'{"error":"use_dpop_nonce"}'
    handler.send_response(401)
    handler.send_header("WWW-Authenticate", 'DPoP error="use_dpop_nonce"')
    handler.send_header("DPoP-Nonce", nonce)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _redirect(location):
    def action(handler):
        handler.send_response(302)
        handler.send_header("Location", location() if callable(location) else location)
        handler.send_header("Content-Length", "0")
        handler.end_headers()
    return action


def _ok(handler):
    handler.send_response(200)
    handler.send_header("Content-Length", "2")
    handler.end_headers()
    handler.wfile.write(b"ok")


def _front_server(actions):
    """A resource that answers its n-th request with `actions[n]` (the last one repeats) and records
    the path and headers of every request. Each action is a callable `(handler) -> None`."""
    seen = []

    class _Front(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
            actions[min(len(seen), len(actions)) - 1](self)

    srv, url = _serve(_Front)
    return srv, url, seen


@pytest.fixture()
def recorder():
    _Recorder.seen = []
    target, target_url = _serve(_Recorder)
    yield target_url
    target.shutdown()


@pytest.fixture()
def redirect_to_recorder(recorder):
    """A front server that 302s every request to a recorder on another port (another origin)."""
    front, front_url, _ = _front_server([_redirect(recorder + "/steal")])
    yield types.SimpleNamespace(front=front_url, target=recorder)
    front.shutdown()


@pytest.fixture()
def challenge_then_redirect(recorder):
    """A front server that answers the first request with a DPoP nonce challenge and the nonce retry
    with a 302 to a recorder on another origin."""
    front, front_url, seen = _front_server([lambda h: _nonce_challenge(h, "front-nonce"),
                                            _redirect(recorder + "/steal")])
    yield types.SimpleNamespace(front=front_url, target=recorder, front_seen=seen)
    front.shutdown()


def _leaked(seen):
    return [h for h in seen if "authorization" in h or "dpop" in h]


def test_requests_auth_sends_no_credentials_to_a_redirect_target(server, redirect_to_recorder):
    requests = pytest.importorskip("requests")
    ca = _ca(server)
    response = requests.get(redirect_to_recorder.front + "/api", auth=ca.requests_auth(), timeout=5)
    assert response.status_code == 401 and len(response.history) == 1
    assert len(_Recorder.seen) == 1, "the hop must not be answered with a nonce retry"
    assert _leaked(_Recorder.seen) == []
    assert ca._nonce_for(redirect_to_recorder.target) is None, "the target's nonce must not be remembered"


def test_requests_auth_sends_no_credentials_to_a_redirect_after_a_nonce_retry(server, challenge_then_redirect):
    requests = pytest.importorskip("requests")
    ca = _ca(server)
    response = requests.get(challenge_then_redirect.front + "/api", auth=ca.requests_auth(), timeout=5)
    # The front origin got the request and one retry carrying its nonce, both with credentials.
    front = [headers for _, headers in challenge_then_redirect.front_seen]
    assert len(front) == 2 and all("authorization" in h and "dpop" in h for h in front)
    assert jwt.decode(front[1]["dpop"], options={"verify_signature": False})["nonce"] == "front-nonce"
    # The redirect target got one request with neither the token nor a proof, and was not retried.
    assert response.status_code == 401
    assert len(_Recorder.seen) == 1, "the hop must not be answered with a nonce retry"
    assert _leaked(_Recorder.seen) == []
    assert ca._nonce_for(challenge_then_redirect.target) is None
    assert ca._nonce_for(challenge_then_redirect.front) == "front-nonce"


def test_requests_auth_same_origin_redirect_after_a_nonce_retry(server):
    """Same origin: the nonce retry still happens, and requests still follows the 302 without
    credentials (requests does not run the auth object again for a hop)."""
    requests = pytest.importorskip("requests")
    front, front_url, seen = _front_server([lambda h: _nonce_challenge(h, "front-nonce"),
                                            _redirect(lambda: front_url + "/moved"), _ok])
    try:
        ca = _ca(server)
        response = requests.get(front_url + "/api", auth=ca.requests_auth(), timeout=5)
    finally:
        front.shutdown()
    assert response.status_code == 200 and [path for path, _ in seen] == ["/api", "/api", "/moved"]
    assert all("authorization" in h and "dpop" in h for _, h in seen[:2])
    assert _leaked([seen[2][1]]) == []
    assert ca._nonce_for(front_url) == "front-nonce"


def test_requests_auth_nonce_retry_through_a_real_requests_session(server):
    requests = pytest.importorskip("requests")
    ca = _ca(server)
    response = requests.post(server + "/api", data=b"payload", auth=ca.requests_auth(), timeout=5)
    assert response.status_code == 200 and json.loads(response.content)["body"] == "payload"
    assert len(response.history) == 1


def test_requests_auth_bearer_sends_no_credentials_to_a_redirect_target(server, redirect_to_recorder):
    requests = pytest.importorskip("requests")
    _Server.state["token_type"] = "Bearer"
    requests.get(redirect_to_recorder.front + "/api", auth=_ca(server).requests_auth(), timeout=5)
    assert len(_Recorder.seen) == 1 and _leaked(_Recorder.seen) == []


def test_httpx_auth_does_not_answer_a_redirected_response(server, redirect_to_recorder):
    httpx = pytest.importorskip("httpx")
    ca = _ca(server)
    with httpx.Client(follow_redirects=True, timeout=5) as client:
        response = client.get(redirect_to_recorder.front + "/api", auth=ca.httpx_auth())
    assert response.status_code == 401
    assert len(_Recorder.seen) == 1, "no retry for a response reached through a redirect"
    assert "authorization" not in _Recorder.seen[0]
    assert ca._nonce_for(redirect_to_recorder.target) is None, "a redirect target cannot set a nonce"


def test_httpx_auth_does_not_answer_a_redirect_after_a_nonce_retry(server, challenge_then_redirect):
    httpx = pytest.importorskip("httpx")
    ca = _ca(server)
    with httpx.Client(follow_redirects=True, timeout=5) as client:
        response = client.get(challenge_then_redirect.front + "/api", auth=ca.httpx_auth())
    assert response.status_code == 401 and len(challenge_then_redirect.front_seen) == 2
    # httpx drops the token on the cross-origin hop (it forwards the proof; see httpx_auth), and the
    # target's challenge is neither retried nor remembered.
    assert len(_Recorder.seen) == 1 and "authorization" not in _Recorder.seen[0]
    assert ca._nonce_for(challenge_then_redirect.target) is None


def test_httpx_auth_same_origin_redirect_still_handles_a_nonce(server):
    httpx = pytest.importorskip("httpx")
    front, front_url, seen = _front_server([_redirect(lambda: front_url + "/moved"),
                                            lambda h: _nonce_challenge(h, "front-nonce"), _ok])
    try:
        ca = _ca(server)
        with httpx.Client(follow_redirects=True, timeout=5) as client:
            response = client.get(front_url + "/api", auth=ca.httpx_auth())
    finally:
        front.shutdown()
    assert ca._nonce_for(front_url) == "front-nonce"
    assert response.status_code == 200 and [path for path, _ in seen] == ["/api", "/moved", "/api"]


# ── the nonce memory and the retry's nonce ──────────────────────────────────────────────────────

def test_nonce_memory_is_bounded():
    ca = _ca("https://attester.example")
    long_nonce = "n" * (ts._MAX_DPOP_NONCE_LENGTH + 1)
    assert ca._observe_response("https://big.example/", 200, {"DPoP-Nonce": long_nonce}, b"") is None
    assert ca._nonce_for("https://big.example/") is None, "an over-long nonce is not remembered"
    challenge = {"DPoP-Nonce": long_nonce, "WWW-Authenticate": 'DPoP error="use_dpop_nonce"'}
    assert ca._observe_response("https://big.example/", 401, challenge, b"") is None
    at_cap = "n" * ts._MAX_DPOP_NONCE_LENGTH
    ca._observe_response("https://big.example/", 200, {"DPoP-Nonce": at_cap}, b"")
    assert ca._nonce_for("https://big.example/") == at_cap

    ca = _ca("https://attester.example")
    count = ts._MAX_DPOP_NONCE_ORIGINS + 44
    for i in range(count):
        ca._remember_nonce(f"https://h{i}.example/p{i}", f"n{i}")
        ca._remember_nonce("https://h1.example/", "n1")   # kept fresh, so never the oldest
    assert len(ca._dpop_nonces) == ts._MAX_DPOP_NONCE_ORIGINS
    assert ca._nonce_for("https://h0.example/") is None
    assert ca._nonce_for("https://h1.example/") == "n1"
    assert ca._nonce_for(f"https://h{count - 1}.example/") == f"n{count - 1}"


def test_a_challenge_with_an_over_long_nonce_is_not_answered(server):
    _Server.state["rs_nonce"] = "n" * (ts._MAX_DPOP_NONCE_LENGTH + 1)
    ca = _ca(server)
    response = _requests_call(ca.requests_auth(), "GET", server + "/api")
    assert response.status_code == 401 and len(_Adapter.sent) == 1
    assert ca._nonce_for(server) is None


def test_requests_auth_retry_carries_the_challenges_nonce(server, monkeypatch):
    ca = _ca(server)
    # Between the challenge and the retry, another response for the origin stores a different nonce.
    monkeypatch.setattr(ts, "_log_nonce_retry", lambda url, status, at: ca._remember_nonce(url, "other"))
    response = _requests_call(ca.requests_auth(), "GET", server + "/api")
    assert response.status_code == 200 and len(_Adapter.sent) == 2
    assert jwt.decode(_Adapter.sent_headers[1]["DPoP"], options={"verify_signature": False})["nonce"] == "rs-n1"


def test_httpx_auth_retry_carries_the_challenges_nonce(server, fake_httpx, monkeypatch):
    ca = _ca(server)
    monkeypatch.setattr(ts, "_log_nonce_retry", lambda url, status, at: ca._remember_nonce(url, "other"))
    url = server + "/api"
    request = types.SimpleNamespace(method="PUT", url=url, headers={}, stream=fake_httpx.ByteStream(b"b"))
    raw, sent = _drive(ca.httpx_auth().auth_flow(request), "PUT", url, b"b")
    assert raw.status == 200 and len(sent) == 2
    assert jwt.decode(sent[1]["DPoP"], options={"verify_signature": False})["nonce"] == "rs-n1"


# ── URLs that parsers disagree on ───────────────────────────────────────────────────────────────

_AMBIGUOUS_URLS = [
    "https://evil.example\\@as.example/t",   # requests connects to evil.example; urlsplit says as.example
    "https://as.example/a\\b",
    " https://as.example/t",
    "https://as.example/t ",
    "https://as.example\t/t",
    "https://as.example/t\n",
    "https://as.example/\x00t",
    "https://as.example/\x7ft",
]


@pytest.mark.parametrize("url", _AMBIGUOUS_URLS)
@pytest.mark.parametrize("token_type", ["DPoP", "Bearer"])
def test_request_headers_refuses_a_url_parsers_disagree_on(server, url, token_type):
    _Server.state["token_type"] = token_type
    with pytest.raises(ClientAttestationError, match="backslash, whitespace or control character"):
        _ca(server).request_headers("GET", url)


_NO_HTU_URLS = ["https://bücher.example/t"]


@pytest.mark.parametrize("url", _NO_HTU_URLS)
@pytest.mark.parametrize("token_type", ["DPoP", "Bearer"])
def test_request_headers_refuses_a_url_with_no_htu_as_a_client_error(server, url, token_type):
    _Server.state["token_type"] = token_type
    with pytest.raises(ClientAttestationError, match=r"^uri \(htu\) "):
        _ca(server).request_headers("GET", url)   # pop_method="dpop_combined"
    assert _Server.state["token_calls"] == 0   # refused before the token is fetched


@pytest.mark.parametrize("url", _NO_HTU_URLS)
def test_a_client_not_configured_for_dpop_sends_a_bearer_token_to_any_url(url, monkeypatch):
    ca = ClientAttestation("https://as.example", evidence=StaticSvidSource("svid"))
    monkeypatch.setattr(ca, "_token_state", lambda **kwargs: ("AT-1", "Bearer", None))
    assert ca.request_headers("GET", url) == {"Authorization": "Bearer AT-1"}


@pytest.mark.parametrize("url", _NO_HTU_URLS)
def test_a_dpop_token_the_as_chose_still_refuses_a_url_with_no_htu(url, monkeypatch):
    ca = ClientAttestation("https://as.example", evidence=StaticSvidSource("svid"))
    key = SigningKeyPair.generate("ES256")
    monkeypatch.setattr(ca, "_token_state", lambda **kwargs: ("AT-1", "DPoP", key))
    with pytest.raises(ClientAttestationError, match=r"^uri \(htu\) "):
        ca.request_headers("GET", url)


# The proof's htu is the request target the client sent. requests escapes "[", "]", "|" and a lone "%";
# httpx sends them as written. A conforming resource (RFC 9449 section 4.3) compares the two after RFC 3986
# section 6.2.2 normalisation, which decodes only unreserved characters, so they must match exactly.
_UNUSUAL_PATHS = ["/items[0]", "/a[b]/c|d", "/100%", "/caf\u00e9[x]"]


def test_requests_auth_htu_is_the_target_sent(server):
    requests = pytest.importorskip("requests")
    ca = _ca(server)
    for path in _UNUSUAL_PATHS:
        assert requests.get(server + path + "?q=1", auth=ca.requests_auth(), timeout=2).status_code == 200
    targets = _Server.state["targets"]
    assert len({target for target, _ in targets}) == len(_UNUSUAL_PATHS)
    assert all(htu == target for target, htu in targets), targets


def test_httpx_auth_htu_is_the_target_sent(server):
    httpx = pytest.importorskip("httpx")
    ca = _ca(server)
    with httpx.Client(auth=ca.httpx_auth(), timeout=2) as client:
        for path in _UNUSUAL_PATHS:
            assert client.get(server + path + "?q=1").status_code == 200
    targets = _Server.state["targets"]
    assert len({target for target, _ in targets}) == len(_UNUSUAL_PATHS)
    assert all(htu == target for target, htu in targets), targets


@pytest.mark.parametrize("url", _AMBIGUOUS_URLS)
def test_dpop_builder_refuses_a_url_parsers_disagree_on(url):
    with pytest.raises(ValueError, match="backslash, whitespace or control character"):
        DpopProofBuilder(SigningKeyPair.generate("ES256")).uri(url).build()


def test_what_follows_the_path_is_not_checked():
    key = SigningKeyPair.generate("ES256")
    for url in ["https://as.example/t?q=a\\b c", "https://as.example/t#a b"]:
        claims = jwt.decode(DpopProofBuilder(key).uri(url).build(), options={"verify_signature": False})
        assert claims["htu"] == "https://as.example/t"
