"""Bounds on what the client takes from places it does not control: a token endpoint's expires_in, the
expiry skew it is configured with, and a resource's 400 body read to look for a DPoP nonce challenge.
Local fake servers only; the requests and httpx cases run when those libraries are installed."""
import base64
import io
import json
import sys
import threading
import time
import types
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from client_attestation_sdk import AttesterMetadata, ClientAttestation, StaticSvidSource
from client_attestation_sdk import token_source as ts

CAP = 64 * 1024
BIG = json.dumps({"error": "use_dpop_nonce"}).encode() + b" " * CAP   # starts like a challenge, too long


def _seg(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


class _Server(BaseHTTPRequestHandler):
    """A mint and token endpoint (expires_in spliced in raw from `state`), and resource paths that
    answer 400 + DPoP-Nonce with a small challenge, an oversized body or an endless one."""

    protocol_version = "HTTP/1.1"
    state = {}

    def log_message(self, *args):
        pass

    def _answer(self, status, body, headers=None):
        self.send_response(status)
        for key, value in {"Content-Type": "application/json", **(headers or {})}.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        s = self.state
        if self.path == "/mint":
            return self._answer(200, json.dumps({"attestation": "h." + _seg({"sub": "c-1"}) + ".s"}).encode())
        s["token_calls"] += 1
        tail = "" if s["expires_in"] is None else ', "expires_in": ' + s["expires_in"]
        token_type = "DPoP" if self.headers.get("DPoP") else "Bearer"
        body = f'{{"access_token": "AT-{s["token_calls"]}", "token_type": "{token_type}"{tail}}}'
        return self._answer(200, body.encode())

    def do_GET(self):
        s = self.state
        s["resource_calls"] += 1
        nonce = {"DPoP-Nonce": "rs-n1"}
        if self.path == "/big":
            return self._answer(400, BIG, nonce)
        if self.path == "/endless":
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("DPoP-Nonce", "rs-n1")
            self.end_headers()
            try:
                self.wfile.write(b'{"error": "use_dpop_nonce"}')
                while not s["stop"].is_set():
                    self.wfile.write(b" " * 16384)
            except OSError:
                pass
            self.close_connection = True
            return None
        # "/small": a real challenge until the proof carries the nonce
        if s["resource_calls"] == 1:
            return self._answer(400, b'{"error": "use_dpop_nonce"}', nonce)
        return self._answer(200, b'{"ok": true}')


@pytest.fixture()
def server():
    _Server.state = {"expires_in": "300", "token_calls": 0, "resource_calls": 0, "stop": threading.Event()}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Server)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    _Server.state["stop"].set()
    srv.shutdown()


def _ca(url, **kwargs):
    meta = AttesterMetadata(evidence_audience="aud", attestation_endpoint=url + "/mint",
                            token_endpoint=url + "/token")
    return ClientAttestation(metadata=meta, evidence=StaticSvidSource("svid"), timeout=2, **kwargs)


# ── expires_in ──────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("expires_in, cached", [
    ("3600", True),
    ("3600.5", True),
    ('"3600"', True),     # a numeric string, as some servers send
    (None, False),        # missing: no expiry, not cached
    ("null", False),
    ("0", False),
    ("-60", False),
    ("1e400", False),     # json reads this as inf
    ("Infinity", False),  # which Python's json accepts
    ("NaN", False),
    ("1" + "0" * 400, False),  # an integer too large for a float
    ('"soon"', False),
    ('"1e3"', False),
    ('"inf"', False),
    ("true", False),
    ("[3600]", False),
])
def test_expires_in_is_parsed_the_same_way_in_every_port(server, expires_in, cached):
    _Server.state["expires_in"] = expires_in
    ca = _ca(server)
    first, second = ca.token(), ca.token()
    assert (first == second and _Server.state["token_calls"] == 1) is cached


def test_a_token_is_cached_for_at_most_24_hours(server, monkeypatch):
    _Server.state["expires_in"] = "1e15"
    ca = _ca(server)
    start = time.monotonic()
    ca.token()
    monkeypatch.setattr(ts.time, "monotonic", lambda: start + 23 * 3600)
    ca.token()
    assert _Server.state["token_calls"] == 1
    monkeypatch.setattr(ts.time, "monotonic", lambda: start + 24 * 3600 + 1)
    ca.token()
    assert _Server.state["token_calls"] == 2


def test_the_token_cache_follows_the_monotonic_clock_not_the_wall_clock(server, monkeypatch):
    ca = _ca(server)                       # expires_in 300, so cached for 270 seconds
    wall, mono = time.time(), time.monotonic()
    ca.token()
    # The wall clock jumps forward two hours (an NTP step): the token is still fresh.
    monkeypatch.setattr(ts.time, "time", lambda: wall + 7200)
    ca.token()
    assert _Server.state["token_calls"] == 1
    # An hour passes, but the wall clock is stepped back two hours: the token has still expired.
    monkeypatch.setattr(ts.time, "monotonic", lambda: mono + 3600)
    monkeypatch.setattr(ts.time, "time", lambda: wall - 3600)
    ca.token()
    assert _Server.state["token_calls"] == 2


def test_force_refresh_with_an_invalid_expires_in_does_not_keep_the_old_expiry(server):
    ca = _ca(server)
    ca.token()
    _Server.state["expires_in"] = '"soon"'
    refreshed = ca.token(force_refresh=True)
    assert ca.token() != refreshed, "the refreshed token must not be served until the old expiry"
    assert _Server.state["token_calls"] == 3


def test_token_obtained_logs_the_cached_lifetime(server, caplog):
    _Server.state["expires_in"] = "1e15"
    with caplog.at_level("INFO", logger="client_attestation_sdk"):
        _ca(server).token()
    obtained = [r for r in caplog.records if getattr(r, "event", None) == "token.obtained"]
    assert obtained and obtained[0].attributes["expires_in"] == 24 * 3600


# ── expiry_skew_seconds ─────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("skew", [-1, -0.5, float("nan"), float("inf"), "30", True, None])
def test_expiry_skew_must_be_a_finite_number_not_negative(skew):
    with pytest.raises(ValueError, match="expiry_skew_seconds"):
        ClientAttestation("https://attester.example", expiry_skew_seconds=skew)


def test_zero_expiry_skew_is_accepted():
    ClientAttestation("https://attester.example", expiry_skew_seconds=0)


# ── the 400 nonce-challenge body, through the real libraries ────────────────────────────────────

def test_requests_auth_does_not_read_past_64_kib(server):
    requests = pytest.importorskip("requests")
    ca = _ca(server, pop_method="dpop_combined")
    with requests.Session() as session:
        response = session.get(server + "/big", auth=ca.requests_auth(), timeout=5)
        assert response.status_code == 400 and response.content == BIG
        assert _Server.state["resource_calls"] == 1  # not a challenge: not re-sent

        response = session.get(server + "/endless", auth=ca.requests_auth(), stream=True, timeout=5)
        assert response.status_code == 400 and _Server.state["resource_calls"] == 2
        first = next(response.iter_content(1024))
        assert first.startswith(b'{"error": "use_dpop_nonce"}')  # the bytes read are handed back
        response.close()

        _Server.state["resource_calls"] = 0
        response = session.get(server + "/small", auth=ca.requests_auth(), timeout=5)
        assert response.status_code == 200 and _Server.state["resource_calls"] == 2


def test_httpx_auth_does_not_read_past_64_kib(server):
    httpx = pytest.importorskip("httpx")
    ca = _ca(server, pop_method="dpop_combined")
    with httpx.Client(timeout=5) as client:
        response = client.get(server + "/big", auth=ca.httpx_auth())
        assert response.status_code == 400 and response.content == BIG
        assert _Server.state["resource_calls"] == 1

        with client.stream("GET", server + "/endless", auth=ca.httpx_auth()) as response:
            assert response.status_code == 400 and _Server.state["resource_calls"] == 2
            first = next(response.iter_raw())
            assert first.startswith(b'{"error": "use_dpop_nonce"}')

        _Server.state["resource_calls"] = 0
        response = client.get(server + "/small", auth=ca.httpx_auth())
        assert response.status_code == 200 and _Server.state["resource_calls"] == 2


# ── the 400 nonce-challenge body, against stand-ins (no requests or httpx needed) ───────────────

class _Raw:
    """A urllib3-shaped response body: read(amt, decode_content=...) and stream(amt, decode_content=...)."""

    def __init__(self, data, fail_after=None):
        self._data = io.BytesIO(data)
        self._fail_after = fail_after
        self.closed = False

    def read(self, amt=None, decode_content=None):
        if self._fail_after is not None and self._data.tell() >= self._fail_after:
            raise OSError("connection reset")
        return self._data.read(amt if amt is None or self._fail_after is None
                               else min(amt, self._fail_after - self._data.tell()))

    def stream(self, amt=2 ** 16, decode_content=None):
        while chunk := self.read(amt):
            yield chunk

    def release_conn(self):
        self.closed = True


def _requests_response(data, **raw_kwargs):
    return types.SimpleNamespace(_content=False, _content_consumed=False, raw=_Raw(data, **raw_kwargs))


def test_requests_body_reads_a_small_body_into_the_response():
    response = _requests_response(b'{"error": "use_dpop_nonce"}')
    assert ts._requests_body(response) == b'{"error": "use_dpop_nonce"}'
    assert response._content == b'{"error": "use_dpop_nonce"}' and response._content_consumed


def test_requests_body_puts_back_what_it_read_from_a_long_body():
    response = _requests_response(BIG)
    assert ts._requests_body(response) is None
    raw = response.raw
    assert b"".join(raw.stream(1000, decode_content=True)) == BIG
    response = _requests_response(BIG)
    ts._requests_body(response)
    assert response.raw.read(10) == BIG[:10]
    assert response.raw.read() == BIG[10:]
    assert response.raw.read(5) == b""          # past the put-back bytes: the original stream
    response.raw.release_conn()                 # anything else goes to the original
    assert response.raw._raw.closed


def test_requests_body_that_fails_mid_read_is_not_a_challenge():
    response = _requests_response(BIG, fail_after=100)
    assert ts._requests_body(response) is None
    assert response.raw.read(100) == BIG[:100]
    with pytest.raises(OSError):
        response.raw.read(1)


class _FailOnce(_Raw):
    """A body whose read fails once, mid-way, and then reads as ended (as a dead connection may)."""

    def read(self, amt=None, decode_content=None):
        if self._fail_after is not None and self._data.tell() >= self._fail_after:
            self._fail_after = None
            self._data.seek(0, io.SEEK_END)
            raise OSError("connection reset")
        return super().read(amt, decode_content)


def test_requests_body_failure_reaches_the_caller_after_the_bytes_read():
    """A read error during the peek is not swallowed: the caller gets the bytes read before it and then
    the error, through stream(), sized reads and a read of everything alike, never a short body."""
    response = types.SimpleNamespace(_content=False, _content_consumed=False, raw=_FailOnce(BIG, fail_after=100))
    assert ts._requests_body(response) is None
    chunks = response.raw.stream(1000, decode_content=True)
    assert next(chunks) == BIG[:100]
    with pytest.raises(OSError, match="connection reset"):
        next(chunks)

    response = types.SimpleNamespace(_content=False, _content_consumed=False, raw=_FailOnce(BIG, fail_after=100))
    ts._requests_body(response)
    assert response.raw.read(60) == BIG[:60] and response.raw.read(60) == BIG[60:100]
    with pytest.raises(OSError, match="connection reset"):
        response.raw.read(60)

    response = types.SimpleNamespace(_content=False, _content_consumed=False, raw=_FailOnce(BIG, fail_after=100))
    ts._requests_body(response)
    with pytest.raises(OSError, match="connection reset"):
        response.raw.read()


def test_requests_body_already_in_memory_is_capped():
    assert ts._requests_body(types.SimpleNamespace(content=b'{"e": 1}')) == b'{"e": 1}'
    assert ts._requests_body(types.SimpleNamespace(content=BIG)) is None
    assert ts._requests_body(types.SimpleNamespace(content=None)) is None


@pytest.fixture()
def fake_httpx(monkeypatch):
    module = types.ModuleType("httpx")

    class ResponseNotRead(Exception):
        pass

    class SyncByteStream:
        def __iter__(self):
            raise NotImplementedError

        def close(self):
            pass

    class AsyncByteStream:
        pass

    module.ResponseNotRead, module.SyncByteStream, module.AsyncByteStream = (
        ResponseNotRead, SyncByteStream, AsyncByteStream)
    monkeypatch.setitem(sys.modules, "httpx", module)
    return module


def _httpx_response(httpx, chunks, headers=None, fail=False):
    class _Stream(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            yield from chunks
            if fail:
                raise OSError("connection reset")

        def close(self):
            type(self).closed = True

    class _Response:
        def __init__(self):
            self.headers = headers or {}
            self.stream = _Stream()

        @property
        def content(self):
            raise httpx.ResponseNotRead()

    return _Response()


def test_httpx_body_reads_at_most_the_cap_and_puts_it_back(fake_httpx):
    small = _httpx_response(fake_httpx, [b'{"error": ', b'"use_dpop_nonce"}'])
    assert ts._httpx_body(small) == b'{"error": "use_dpop_nonce"}'
    assert b"".join(small.stream) == b'{"error": "use_dpop_nonce"}'

    pulled = []

    def endless():
        while True:
            pulled.append(1)
            yield b" " * 4096

    big = _httpx_response(fake_httpx, endless())
    assert ts._httpx_body(big) is None
    assert len(pulled) <= CAP // 4096 + 1
    replay = iter(big.stream)
    assert len(next(replay)) > CAP           # the bytes already read come back first ...
    assert next(replay) == b" " * 4096       # ... then the rest of the stream


def test_httpx_body_closes_the_original_stream(fake_httpx):
    response = _httpx_response(fake_httpx, [b"{}"])
    original = response.stream
    ts._httpx_body(response)
    response.stream.close()
    assert type(original).closed


def test_httpx_body_that_fails_mid_read_is_not_a_challenge(fake_httpx):
    response = _httpx_response(fake_httpx, [b'{"error": '], fail=True)
    assert ts._httpx_body(response) is None
    replay = iter(response.stream)
    assert next(replay) == b'{"error": '      # the bytes read before the failure, then the failure
    with pytest.raises(OSError, match="connection reset"):
        next(replay)


def test_httpx_auth_does_not_hide_a_read_error_behind_a_short_body(server):
    """A real httpx client: a 400 + DPoP-Nonce whose body fails part-way. The caller's read raises the
    network error, as it does without the auth, instead of returning the bytes read before it."""
    httpx = pytest.importorskip("httpx")
    ca = _ca(server, pop_method="dpop_combined")

    class _Failing(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"error": "invalid_request", "pad": "' + b"x" * 1000 + b'"'
            raise httpx.ReadError("connection reset")

    def handler(request):
        return httpx.Response(400, headers={"DPoP-Nonce": "rs-n1"}, stream=_Failing())

    with httpx.Client(transport=httpx.MockTransport(handler), timeout=5) as client:
        with pytest.raises(httpx.ReadError):
            client.get("https://rs.example/api", auth=ca.httpx_auth())
        with client.stream("GET", "https://rs.example/api", auth=ca.httpx_auth()) as response:
            assert response.status_code == 400
            with pytest.raises(httpx.ReadError):
                response.read()


def test_httpx_body_decodes_gzip_and_deflate_but_no_other_coding(fake_httpx):
    body = b'{"error": "use_dpop_nonce"}'
    gzipped = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    gz = gzipped.compress(body) + gzipped.flush()
    assert ts._httpx_body(_httpx_response(fake_httpx, [gz], {"Content-Encoding": "gzip"})) == body
    deflated = _httpx_response(fake_httpx, [zlib.compress(body)], {"Content-Encoding": "deflate"})
    assert ts._httpx_body(deflated) == body
    assert ts._httpx_body(_httpx_response(fake_httpx, [b"\x00junk"], {"Content-Encoding": "gzip"})) is None
    assert ts._httpx_body(_httpx_response(fake_httpx, [b"x"], {"Content-Encoding": "br"})) is None
    bomb = zlib.compress(b" " * (10 * CAP))   # small on the wire, larger than the cap once decoded
    assert ts._httpx_body(_httpx_response(fake_httpx, [bomb], {"Content-Encoding": "deflate"})) is None


def test_httpx_body_already_in_memory_or_async_is_not_streamed(fake_httpx):
    assert ts._httpx_body(types.SimpleNamespace(content=b"{}")) == b"{}"
    assert ts._httpx_body(types.SimpleNamespace(content=BIG)) is None

    class _Async:
        stream = fake_httpx.AsyncByteStream()

        @property
        def content(self):
            raise fake_httpx.ResponseNotRead()

    assert ts._httpx_body(_Async()) is None
