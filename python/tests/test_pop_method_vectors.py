"""The one-call client's PoP method setting against the shared vectors (vectors/pop-method.json). Every
port must agree. An accepted value is checked by the header sent at the token endpoint; a refused one
fails the constructor before any request or evidence fetch. Local fake server only."""
import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from client_attestation_sdk import AttesterMetadata, ClientAttestation, ClientAttestationError

VECTORS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "vectors"))


def _cases():
    with open(os.path.join(VECTORS, "pop-method.json"), encoding="utf-8") as fh:
        return json.load(fh)["cases"]


class _Attester(BaseHTTPRequestHandler):
    """A mint and a token endpoint that record every request and the token request's proof headers."""

    requests = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        type(self).requests.append((self.path, self.headers.get("DPoP"),
                                    self.headers.get("OAuth-Client-Attestation-PoP")))
        if self.path == "/mint":
            sub = base64.urlsafe_b64encode(b'{"sub":"c-1"}').rstrip(b"=").decode()
            body = json.dumps({"attestation": "h." + sub + ".s"})
        else:
            body = json.dumps({"access_token": "AT", "token_type": "Bearer", "expires_in": 3600})
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST


class _CountingSource:
    def __init__(self):
        self.fetches = 0

    def fetch(self, audience):
        self.fetches += 1
        return "svid"


@pytest.fixture
def attester():
    _Attester.requests = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Attester)
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield AttesterMetadata(evidence_audience="aud", attestation_endpoint=url + "/mint",
                           token_endpoint=url + "/token")
    httpd.shutdown()
    httpd.server_close()


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_vector(attester, case):
    source = _CountingSource()
    build = lambda: ClientAttestation(metadata=attester, evidence=source, pop_method=case["pop_method"])  # noqa: E731
    if case["expect"] == "refused":
        with pytest.raises(ValueError, match="^pop_method must be ") as err:
            build()
        assert repr(case["pop_method"]) in str(err.value)
        assert _Attester.requests == [] and source.fetches == 0
        return
    build().token()
    token_requests = [r for r in _Attester.requests if r[0] == "/token"]
    assert len(token_requests) == 1
    _, dpop, pop = token_requests[0]
    if case["expect"] == "dpop_combined":
        assert dpop and not pop
    else:
        assert pop and not dpop


def test_leaving_it_out_is_the_default(attester):
    ClientAttestation(metadata=attester, evidence=_CountingSource()).token()
    assert [r[2] is not None for r in _Attester.requests if r[0] == "/token"] == [True]


def test_a_str_subclass_with_the_name_is_accepted(attester):
    class Name(str):
        pass

    ClientAttestation(metadata=attester, evidence=_CountingSource(), pop_method=Name("dpop_combined")).token()
    assert [r[1] is not None for r in _Attester.requests if r[0] == "/token"] == [True]


# JSON can't carry these; they are refused like the vectors' non-strings.
@pytest.mark.parametrize("pop_method", [b"dpop_combined", b"", bytearray(b"attestation_pop_jwt"), 1.5,
                                        ("dpop_combined",)],
                         ids=["bytes", "empty_bytes", "bytearray", "float", "tuple"])
def test_non_json_non_strings_are_refused(attester, pop_method):
    source = _CountingSource()
    with pytest.raises(ValueError, match="^pop_method must be "):
        ClientAttestation(metadata=attester, evidence=source, pop_method=pop_method)
    assert _Attester.requests == [] and source.fetches == 0


def test_the_flow_refuses_an_unexpected_pop_method(attester):
    # Only reachable by bypassing the constructor: the flow fails before any request or evidence fetch
    # rather than sending a PoP JWT.
    source = _CountingSource()
    ca = ClientAttestation(metadata=attester, evidence=source)
    ca._pop_method = "DPOP_COMBINED"
    with pytest.raises(ClientAttestationError, match="unsupported pop_method 'DPOP_COMBINED'"):
        ca.token()
    assert _Attester.requests == [] and source.fetches == 0
