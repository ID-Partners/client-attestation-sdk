"""The shared HTTP transport (client_attestation_sdk._http) and the call sites that use it: no redirects,
a body cap, typed errors for non-2xx / malformed JSON / network failure / timeout. Local servers only."""
import base64
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from client_attestation_sdk.authz_challenge import CibaClient, CibaError
from client_attestation_sdk.authz_challenge.ciba import urllib_http
from client_attestation_sdk import (
    AttestationIssuanceClient,
    ClientAttestation,
    ClientAttestationError,
    HttpSvidSource,
    IssuanceError,
    OpenBaoTransitSigner,
    StaticSvidSource,
    TransportError,
)
from client_attestation_sdk import _http
from client_attestation_sdk import evidence as evidence_mod
from client_attestation_sdk.token_validator import AccessTokenValidator, IntrospectionConfig, ValidatorConfig, discover
from client_attestation_sdk.token_validator.jwks import JwksProvider

AUD = "https://attester.example"  # the evidence_audience the fake attester's discovery document names


class Route:
    def __init__(self, status=200, body=b"{}", headers=None, delay=0.0):
        self.status = status
        self.body = body if isinstance(body, bytes) else body.encode("utf-8")
        self.headers = headers or {"Content-Type": "application/json"}
        self.delay = delay


class Server:
    """Answers each path from a route table and records every path it was asked for."""

    def __init__(self, routes):
        self.routes = routes
        self.hits = []
        self.requests = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def close(self):
        self._server.shutdown()
        self._server.server_close()

    def _handler(srv):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _answer(self):
                path = self.path.split("?", 1)[0]
                srv.hits.append(path)
                length = int(self.headers.get("Content-Length", 0) or 0)
                srv.requests.append((path, self.headers, self.rfile.read(length)))
                route = srv.routes.get(path, Route(404, b'{"error":"not_found"}'))
                if route.delay:
                    time.sleep(route.delay)
                self.send_response(route.status)
                for key, value in route.headers.items():
                    self.send_header(key, value.replace("{base}", srv.url))
                self.send_header("Content-Length", str(len(route.body)))
                self.end_headers()
                self.wfile.write(route.body)

            do_GET = _answer
            do_POST = _answer

        return Handler


@pytest.fixture
def server():
    servers = []

    def make(routes):
        s = Server(routes)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


class RawServer:
    """Reads one request per connection, then writes ``prefix`` at once and ``drip`` a byte every
    ``interval`` seconds. Records each request line. Used for slow servers and as a stand-in proxy."""

    def __init__(self, prefix=b"", drip=b"", interval=0.2):
        self.prefix, self.drip, self.interval = prefix, drip, interval
        self.lines = []
        self._closed = threading.Event()
        self._sock = socket.create_server(("127.0.0.1", 0))
        threading.Thread(target=self._accept, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self._sock.getsockname()[1]}"

    def close(self):
        self._closed.set()
        self._sock.close()

    def _accept(self):
        while not self._closed.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        with conn:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                request += chunk
            self.lines.append(request.split(b"\r\n", 1)[0].decode())
            try:
                conn.sendall(self.prefix)
                for byte in self.drip:
                    if self._closed.wait(self.interval):
                        return
                    conn.sendall(bytes([byte]))
            except OSError:
                pass


@pytest.fixture
def raw_server():
    servers = []

    def make(**kwargs):
        s = RawServer(**kwargs)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


def _redirect(to="/target", status=302):
    return Route(status, b"", headers={"Location": "{base}" + to})


# -- the transport itself -------------------------------------------------------------------------
def test_successful_request_returns_status_headers_and_body(server):
    srv = server({"/ok": Route(200, b'{"a": 1}')})
    response = _http.request("GET", srv.url + "/ok", timeout=2)
    assert response.status == 200 and response.ok
    assert response.headers.get("content-type") == "application/json"
    assert _http.json_ok(response, "ok") == {"a": 1}


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_is_refused_and_target_never_contacted(server, status):
    srv = server({"/start": _redirect("/target", status), "/target": Route(200, b'{"stolen": true}')})
    with pytest.raises(TransportError) as info:
        _http.request("POST", srv.url + "/start", headers={"Authorization": "Bearer secret"},
                      body=b"x=1", timeout=2)
    assert info.value.status == status
    assert "redirect" in str(info.value)
    assert srv.hits == ["/start"]


def test_oversized_body_is_refused(server):
    srv = server({"/big": Route(200, b"x" * 101)})
    with pytest.raises(TransportError, match="larger than 100 bytes"):
        _http.request("GET", srv.url + "/big", timeout=2, max_bytes=100)
    assert _http.request("GET", srv.url + "/big", timeout=2, max_bytes=101).body == b"x" * 101


def test_default_cap_is_one_mebibyte(server):
    srv = server({"/big": Route(200, b"x" * (1024 * 1024 + 1))})
    with pytest.raises(TransportError, match="larger than 1048576 bytes"):
        _http.request("GET", srv.url + "/big", timeout=5)


def test_non_2xx_is_returned_by_request_and_raised_by_json_ok(server):
    long_body = json.dumps({"error": "server_error", "error_description": "y" * 2000})
    srv = server({"/err": Route(500, long_body)})
    response = _http.request("GET", srv.url + "/err", timeout=2)
    assert response.status == 500 and not response.ok
    with pytest.raises(TransportError) as info:
        _http.json_ok(response, "thing")
    assert info.value.status == 500
    assert str(info.value).startswith("thing returned HTTP 500: ")
    assert len(str(info.value)) <= len("thing returned HTTP 500: ") + 512
    assert info.value.body == long_body[:512]
    with pytest.raises(TransportError):
        _http.text_ok(response, "thing")


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b""])
def test_malformed_json_is_a_typed_error(server, body):
    srv = server({"/bad": Route(200, body)})
    with pytest.raises(TransportError) as info:
        _http.json_ok(_http.request("GET", srv.url + "/bad", timeout=2), "bad")
    assert info.value.status == 200


def test_empty_body_allowed_when_asked(server):
    srv = server({"/empty": Route(200, b"")})
    assert _http.json_ok(_http.request("GET", srv.url + "/empty", timeout=2), "e", allow_empty=True) == {}


def test_timeout_is_a_typed_error(server):
    srv = server({"/slow": Route(200, b"{}", delay=1.0)})
    started = time.monotonic()
    with pytest.raises(TransportError) as info:
        _http.request("GET", srv.url + "/slow", timeout=0.2)
    assert info.value.status is None
    assert time.monotonic() - started < 0.9


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_timeout_bounds_the_whole_call_not_each_read(raw_server, phase):
    # One byte every 0.2 s never trips a per-read timeout of 1 s; the call must still end at about 1 s,
    # not when the server finishes (25 bytes, 5 s).
    head = b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\n"
    if phase == "headers":
        srv = raw_server(prefix=b"HTTP/1.1 200 OK\r\n", drip=b"X-Slow: " + b"a" * 17 + b"\r\n\r\n")
    else:
        srv = raw_server(prefix=head + b"\r\n", drip=b"x" * 25)
    started = time.monotonic()
    with pytest.raises(TransportError, match="timed out") as info:
        _http.request("GET", srv.url + "/drip", timeout=1.0)
    assert info.value.status is None
    assert time.monotonic() - started < 1.8


def test_deadline_spent_before_connect_is_a_timeout(raw_server):
    srv = raw_server(prefix=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    with pytest.raises(TransportError, match="timed out"):
        _http.request("GET", srv.url + "/", timeout=0)
    assert srv.lines == []


def _point_env_proxies_at(proxy, monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, proxy.url)
        monkeypatch.setenv(name.lower(), proxy.url)
    for name in ("NO_PROXY", "no_proxy", "REQUEST_METHOD"):
        monkeypatch.delenv(name, raising=False)
    _http._environment_proxies.cache_clear()  # the SDK reads the variables once


@pytest.fixture
def env_proxy(raw_server, monkeypatch):
    """Every proxy variable pointed at a recording stand-in that answers 502."""
    proxy = raw_server(prefix=b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
    _point_env_proxies_at(proxy, monkeypatch)
    yield proxy
    _http._environment_proxies.cache_clear()


def test_direct_calls_never_use_a_proxy_even_for_https(env_proxy):
    # direct=True (the metadata servers) skips the proxy for any URL, https to a remote host included.
    for context in (None, ssl.create_default_context()):
        with pytest.raises(TransportError):
            _http.request("GET", "https://192.0.2.1/x", timeout=0.3, context=context, direct=True)
    assert env_proxy.lines == []


def test_proxy_connect_reply_is_under_the_deadline(raw_server, monkeypatch):
    # A proxy that answers CONNECT a byte every 0.2 s must not hold a 1 s call open.
    proxy = raw_server(drip=b"HTTP/1.1 200 Connection established\r\nX-Pad: " + b"a" * 20 + b"\r\n\r\n")
    _point_env_proxies_at(proxy, monkeypatch)
    try:
        started = time.monotonic()
        with pytest.raises(TransportError, match="timed out"):
            _http.request("GET", "https://192.0.2.1/x", timeout=1.0)
        assert time.monotonic() - started < 1.8
        assert proxy.lines and proxy.lines[0].startswith("CONNECT 192.0.2.1:443 ")
    finally:
        _http._environment_proxies.cache_clear()


class _Blackholed(socket.socket):
    """A socket for which 192.0.2.1 never answers: connect waits out its timeout, as a dropped SYN does."""
    shares = []

    def connect(self, address):
        if address[0] == "192.0.2.1":
            _Blackholed.shares.append(self.gettimeout())
            time.sleep(self.gettimeout())
            raise TimeoutError("timed out")
        return super().connect(address)


def test_an_address_that_never_answers_does_not_starve_the_next(server, monkeypatch):
    # A blackholed first address (an unreachable AAAA in front of a working A) gets only its share of the
    # deadline; the next address is then tried with what is left.
    srv = server({"/x": Route(200, b'{"ok": true}')})
    port = int(srv.url.rsplit(":", 1)[1])
    real = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        if host == "dual.test":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", port)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(_http, "_new_socket", _Blackholed)
    _Blackholed.shares.clear()
    started = time.monotonic()
    response = _http.request("GET", f"http://dual.test:{port}/x", timeout=2.0)
    assert response.status == 200
    assert len(_Blackholed.shares) == 1 and 0.8 < _Blackholed.shares[0] <= 1.0
    assert time.monotonic() - started < 1.8


def test_connect_stops_at_the_deadline_when_no_address_answers(monkeypatch):
    def getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", port))] * 3

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(_http, "_new_socket", _Blackholed)
    _Blackholed.shares.clear()
    started = time.monotonic()
    with pytest.raises(TransportError, match="timed out"):
        _http.request("GET", "http://dual.test/x", timeout=0.9)
    assert time.monotonic() - started < 1.5
    assert len(_Blackholed.shares) == 3


def test_env_proxy_is_never_used_for_loopback_or_plain_http(server, env_proxy):
    srv = server({"/v1/transit/keys/k": Route(200, b'{"direct": true}')})
    for context in (None, ssl.create_default_context()):  # the shared opener and a per-call one
        response = _http.request("GET", srv.url + "/v1/transit/keys/k", headers={"X-Vault-Token": "s.secret"},
                                 timeout=2, context=context)
        assert response.status == 200 and _http.json_ok(response, "vault") == {"direct": True}
        with pytest.raises(TransportError):  # plain http to a remote host goes direct (and fails here)
            _http.request("GET", "http://192.0.2.1/computeMetadata/v1/", timeout=0.3, context=context)
    assert env_proxy.lines == []


def test_env_proxy_still_tunnels_https_to_remote_hosts(env_proxy):
    with pytest.raises(TransportError):
        _http.request("GET", "https://192.0.2.1/x", timeout=2)
    # http.client sends the CONNECT as HTTP/1.0 before Python 3.12 and HTTP/1.1 from 3.12.
    assert len(env_proxy.lines) == 1 and env_proxy.lines[0].startswith("CONNECT 192.0.2.1:443 HTTP/1.")


@pytest.mark.parametrize("host,direct", [
    ("127.0.0.1", True), ("127.8.0.1", True), ("::1", True), ("localhost", True), ("LocalHost.", True),
    ("vault.localhost", True), ("::ffff:127.0.0.1", True), ("0.0.0.0", True), ("169.254.169.254", True),
    ("fe80::1", True), ("fd00:ec2::254", True), ("metadata.google.internal", True), ("metadata", True),
    ("127.1", True), ("0x7f000001", True), ("2130706433", True), ("0177.0.0.1", True), ("169.254.43518", True),
    ("as.example.com", False), ("10.1", False), ("0x0a000001", False), ("münchen.example", False), ("10.0.0.1", False), ("8.8.8.8", False), ("2001:db8::1", False),
    (None, False),
])
def test_hosts_that_never_use_a_proxy(host, direct):
    assert _http._never_proxied(host) is direct


@pytest.mark.parametrize("url,shown", [
    ("https://alice:s3cret@127.0.0.1:1/token?x=1", "https://127.0.0.1:1/token"),
    # no explicit port: urllib would hand "s3cret@example.invalid" to http.client as a port and quote it
    ("https://alice:s3cret@example.invalid/x", "https://example.invalid/x"),
    ("http://alice:s3cret@example.invalid/x?q=1#f", "http://example.invalid/x"),
    ("https://alice@example.invalid/x", "https://example.invalid/x"),
])
def test_userinfo_urls_are_refused_without_naming_the_userinfo(url, shown):
    with pytest.raises(TransportError, match="userinfo") as info:
        _http.request("GET", url, timeout=1)
    assert "s3cret" not in str(info.value) and "alice" not in str(info.value)
    assert str(info.value).startswith(f"GET {shown}: ")


def test_userinfo_never_reaches_a_proxy(env_proxy):
    with pytest.raises(TransportError) as info:
        _http.request("GET", "https://alice:s3cret@192.0.2.1/x", timeout=1)
    assert "s3cret" not in str(info.value)
    assert env_proxy.lines == []


def test_connection_refused_is_a_typed_error(server):
    srv = server({})
    url = srv.url
    srv.close()
    with pytest.raises(TransportError) as info:
        _http.request("GET", url + "/gone", timeout=2)
    assert info.value.status is None
    assert isinstance(info.value, ClientAttestationError)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "data:,hello"])
def test_non_http_schemes_are_refused(url):
    with pytest.raises(TransportError, match="only http and https"):
        _http.request("GET", url, timeout=1)


def test_tls_context_is_accepted(server):
    srv = server({"/ok": Route(200, b"{}")})
    response = _http.request("GET", srv.url + "/ok", timeout=2, context=ssl.create_default_context())
    assert response.status == 200


def test_require_names_the_missing_member():
    assert _http.require({"a": 1}, "a", "doc") == 1
    with pytest.raises(TransportError, match="doc has no b"):
        _http.require({"a": 1}, "b", "doc")


# -- call sites -----------------------------------------------------------------------------------
def _jwt(claims):
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return seg({"alg": "ES256", "typ": "x"}) + "." + seg(claims) + ".c2ln"


def _attester(server, token_route):
    holder = {}
    routes = {
        "/challenge": Route(200, b'{"attestation_challenge": "c-1"}'),
        "/attest": Route(200, json.dumps({"attestation": _jwt({"sub": "client-1"})})),
        "/token": token_route,
    }
    srv = server(routes)
    holder["srv"] = srv
    routes["/.well-known/client-attester"] = Route(200, json.dumps({
        "evidence_audience": "https://attester.example",
        "challenge_endpoint": srv.url + "/challenge",
        "attestation_endpoint": srv.url + "/attest",
        "token_endpoint": srv.url + "/token",
    }))
    return srv


def test_token_flow_end_to_end(server):
    srv = _attester(server, Route(200, b'{"access_token": "at-1", "expires_in": 300}'))
    ca = ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), evidence_audience=AUD, timeout=2)
    assert ca.token() == "at-1"
    token_request = [r for r in srv.requests if r[0] == "/token"][0]
    assert token_request[1]["OAuth-Client-Attestation"]


def test_token_endpoint_error_keeps_status_and_body(server):
    error = b'{"error": "invalid_client", "error_description": "use_attestation_challenge"}'
    srv = _attester(server, Route(400, error))
    ca = ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), evidence_audience=AUD, timeout=2)
    with pytest.raises(ClientAttestationError) as info:
        ca.token()
    assert isinstance(info.value, TransportError)
    assert info.value.status == 400
    assert json.loads(info.value.body)["error"] == "invalid_client"
    assert str(info.value).startswith("token endpoint returned HTTP 400")


def test_token_endpoint_redirect_is_not_followed(server):
    srv = _attester(server, _redirect("/elsewhere", 307))
    ca = ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), evidence_audience=AUD, timeout=2)
    with pytest.raises(TransportError) as info:
        ca.token()
    assert info.value.status == 307
    assert "/elsewhere" not in srv.hits


def test_token_endpoint_malformed_json_is_typed(server):
    srv = _attester(server, Route(200, b"<html>oops</html>"))
    ca = ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), evidence_audience=AUD, timeout=2)
    with pytest.raises(TransportError, match="malformed JSON"):
        ca.token()


def test_discovery_without_attestation_endpoint_is_typed(server):
    srv = server({"/.well-known/client-attester": Route(200, b'{"evidence_audience": "aud"}')})
    ca = ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), evidence_audience="aud", timeout=2)
    with pytest.raises(TransportError, match="no attestation_endpoint"):
        ca.token()


def test_discovery_network_failure_is_typed(server):
    srv = server({})
    url = srv.url
    srv.close()
    with pytest.raises(TransportError):
        ClientAttestation(url, evidence=StaticSvidSource("svid"), evidence_audience=AUD, timeout=1).token()


def test_minted_attestation_that_is_not_a_jwt_is_typed(server):
    srv = _attester(server, Route(200, b'{"access_token": "at-1"}'))
    srv.routes["/attest"] = Route(200, b'{"attestation": "garbage"}')
    with pytest.raises(ClientAttestationError, match="not a decodable JWT"):
        ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), evidence_audience=AUD, timeout=2).token()


def _issuance(srv):
    return AttestationIssuanceClient(srv.url + "/issue", "client-1", "https://attester.example",
                                     StaticSvidSource("svid"))


def test_issuance_rejection_is_issuance_error(server):
    srv = server({"/issue": Route(403, b'{"error": "access_denied"}')})
    with pytest.raises(IssuanceError) as info:
        _issuance(srv).bootstrap()
    assert info.value.status == 403 and "access_denied" in info.value.body
    assert isinstance(info.value, ClientAttestationError)


def test_issuance_missing_attestation_is_typed(server):
    srv = server({"/issue": Route(200, b'{"expires_in": 60}')})
    with pytest.raises(TransportError, match="no attestation"):
        _issuance(srv).bootstrap()


def test_issuance_redirect_is_refused(server):
    srv = server({"/issue": _redirect("/target"), "/target": Route(200, b'{"attestation": "x"}')})
    with pytest.raises(TransportError) as info:
        _issuance(srv).bootstrap()
    assert info.value.status == 302 and srv.hits == ["/issue"]


def test_http_svid_source_errors_are_typed(server):
    srv = server({"/svid": Route(200, b'{"svid": "jwt"}'), "/nosvid": Route(200, b"{}"),
                  "/broken": Route(502, b"bad gateway")})
    assert HttpSvidSource(srv.url + "/svid").fetch("aud") == "jwt"
    with pytest.raises(TransportError, match="no svid"):
        HttpSvidSource(srv.url + "/nosvid").fetch("aud")
    with pytest.raises(TransportError) as info:
        HttpSvidSource(srv.url + "/broken").fetch("aud")
    assert info.value.status == 502


def test_cloud_metadata_sources_are_typed(server, monkeypatch):
    srv = server({"/gcp": Route(200, b"  gcp-token \n", headers={"Metadata-Flavor": "Google"}),
                  "/gcp-down": Route(503, b"no"),
                  "/azure": Route(200, b'{"token_type": "Bearer"}')})
    monkeypatch.setattr(evidence_mod, "GCP_METADATA_IDENTITY", srv.url + "/gcp")
    assert evidence_mod.GoogleMetadataSvidSource(timeout=2).fetch("aud") == "gcp-token"
    monkeypatch.setattr(evidence_mod, "GCP_METADATA_IDENTITY", srv.url + "/gcp-down")
    with pytest.raises(TransportError) as info:
        evidence_mod.GoogleMetadataSvidSource(timeout=2).fetch("aud")
    assert info.value.status == 503
    monkeypatch.setattr(evidence_mod, "AZURE_IMDS_IDENTITY", srv.url + "/azure")
    with pytest.raises(TransportError, match="no access_token"):
        evidence_mod.AzureImdsSvidSource(timeout=2, resource="aud").fetch("aud")


def test_metadata_probes_answer_false_off_cloud(server, monkeypatch):
    srv = server({"/metadata/instance": Route(200, b'{"compute": {}}')})
    monkeypatch.setattr(evidence_mod, "AZURE_IMDS_INSTANCE", srv.url + "/metadata/instance")
    assert evidence_mod._azure_imds_available(timeout=2) is True
    monkeypatch.setattr(evidence_mod, "AZURE_IMDS_INSTANCE", srv.url + "/nope")
    assert evidence_mod._azure_imds_available(timeout=2) is False
    url = srv.url
    srv.close()
    monkeypatch.setattr(evidence_mod, "AZURE_IMDS_INSTANCE", url + "/metadata/instance")
    assert evidence_mod._azure_imds_available(timeout=1) is False


def test_openbao_redirect_and_unreachable_are_typed(server):
    srv = server({"/v1/transit/keys/k": _redirect("/target"), "/target": Route(200, b"{}")})
    with pytest.raises(TransportError) as info:
        OpenBaoTransitSigner(srv.url, "tok", "k")
    assert info.value.status == 302 and "/target" not in srv.hits
    url = srv.url
    srv.close()
    with pytest.raises(TransportError, match="OpenBao unreachable"):
        OpenBaoTransitSigner(url, "tok", "k")


def test_openbao_malformed_metadata_is_typed(server):
    srv = server({"/v1/transit/keys/k": Route(200, b'{"data": {"type": "ecdsa-p256"}}'),
                  "/v1/transit/keys/j": Route(200, b"not json")})
    with pytest.raises(TransportError, match="malformed"):
        OpenBaoTransitSigner(srv.url, "tok", "k")
    with pytest.raises(TransportError, match="malformed JSON"):
        OpenBaoTransitSigner(srv.url, "tok", "j")


def test_introspection_errors_are_typed(server):
    srv = server({"/introspect": Route(401, b'{"error": "invalid_client"}'), "/html": Route(200, b"<html>")})
    for path, status in (("/introspect", 401), ("/html", 200)):
        cfg = ValidatorConfig(issuer="https://as", audiences=["https://rs"], jwks={"keys": []},
                              introspection=IntrospectionConfig(srv.url + path, "rs", "secret"))
        with pytest.raises(TransportError) as info:
            AccessTokenValidator(cfg).validate_active("opaque")
        assert info.value.status == status


def test_discovery_and_jwks_refuse_redirects(server):
    srv = server({"/meta": _redirect("/target"), "/jwks": _redirect("/target"),
                  "/target": Route(200, b'{"keys": []}')})
    with pytest.raises(TransportError):
        discover(srv.url + "/meta", issuer="https://issuer.example.com")
    provider = JwksProvider(jwks_uri=srv.url + "/jwks")
    assert provider.resolve("kid") is None
    assert "302" in provider.last_error
    assert "/target" not in srv.hits


def test_ciba_transport_errors_become_ciba_errors(server):
    srv = server({"/bc": _redirect("/target"), "/target": Route(200, b'{"auth_req_id": "x"}'),
                  "/slow": Route(200, b"{}", delay=1.0), "/list": Route(200, b"[]"),
                  "/pending": Route(400, b'{"error": "authorization_pending"}')})
    http = urllib_http(timeout=0.3, dangerously_disable_tls_verification=True)
    assert http("POST", srv.url + "/pending", {"a": "b"}, {"X-Extra": "1"})[0] == 400
    with pytest.raises(CibaError) as info:
        http("POST", srv.url + "/bc", {"a": "b"}, {})
    assert info.value.status == 302 and "/target" not in srv.hits
    with pytest.raises(CibaError):
        http("POST", srv.url + "/slow", {}, {})

    class NoAuth:
        def apply(self, endpoint, form):
            pass

    client = CibaClient(bc_auth_endpoint=srv.url + "/list", token_endpoint=srv.url + "/pending",
                        client_id="c", client_auth=NoAuth(), issuer="https://as", http=http)
    with pytest.raises(CibaError, match="not an object"):
        client.request(login_hint="user")



def test_every_opener_holds_only_the_sdk_proxy_handler():
    """urllib adds its own environment ProxyHandler (which proxies plain http) to an opener unless one is
    given; the SDK's is the only one, with or without a custom TLS context."""
    import urllib.request

    for opener in (_http._opener(None), _http._opener(ssl.create_default_context())):
        handlers = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
        assert len(handlers) == 1 and isinstance(handlers[0], _http._ProxyHandler)
    assert _http._opener(None) is _http._DEFAULT_OPENER
