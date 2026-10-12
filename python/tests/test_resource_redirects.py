"""The resource helpers never hand a credential to an origin the caller did not name: a redirect to
another origin carries no token (and, with requests, no proof), a challenge from that origin is not
answered, and a plain-http resource is refused. Real requests and httpx against local servers."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from client_attestation_sdk import ClientAttestationError
from test_dpop_bound_token import _ca, _Server, server  # noqa: F401 - the fake attester and AS


class _Recorder(BaseHTTPRequestHandler):
    """Records each request's credential headers. `redirect_to` set: answer 302 there. Otherwise answer
    a DPoP nonce challenge, which a client must not meet by resending its token here."""
    seen = None
    redirect_to = None

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).seen.append({"Authorization": self.headers.get("Authorization"), "DPoP": self.headers.get("DPoP")})
        if self.redirect_to:
            self.send_response(302)
            self.send_header("Location", self.redirect_to + self.path)
        else:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'DPoP error="use_dpop_nonce"')
            self.send_header("DPoP-Nonce", "attacker-nonce")
        self.send_header("Content-Length", "0")
        self.end_headers()


def _start(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture()
def hop():
    """(resource URL that redirects, what the resource saw, what the other origin saw)."""
    other = type("Other", (_Recorder,), {"seen": []})
    other_srv, other_url = _start(other)
    resource = type("Resource", (_Recorder,), {"seen": [], "redirect_to": other_url})
    resource_srv, resource_url = _start(resource)
    yield resource_url, resource.seen, other.seen
    resource_srv.shutdown()
    other_srv.shutdown()


@pytest.mark.parametrize("token_type", ["DPoP", "Bearer"])
def test_requests_auth_sends_nothing_across_a_redirect(server, hop, token_type):  # noqa: F811
    requests = pytest.importorskip("requests")
    _Server.state["token_type"] = token_type
    resource_url, resource_seen, other_seen = hop
    response = requests.get(resource_url + "/api", auth=_ca(server).requests_auth(), timeout=5)
    assert response.status_code == 401  # the other origin's challenge, handed back as-is
    assert resource_seen[0]["Authorization"].startswith(token_type + " ")
    assert other_seen == [{"Authorization": None, "DPoP": None}]


def test_httpx_auth_withholds_the_token_and_ignores_the_other_origins_nonce(server, hop):  # noqa: F811
    httpx = pytest.importorskip("httpx")
    resource_url, resource_seen, other_seen = hop
    ca = _ca(server)
    with httpx.Client(auth=ca.httpx_auth(), follow_redirects=True, timeout=5) as client:
        response = client.get(resource_url + "/api")
    assert response.status_code == 401
    assert resource_seen[0]["Authorization"].startswith("DPoP ")
    assert len(other_seen) == 1 and other_seen[0]["Authorization"] is None
    assert not ca._dpop_nonces, "a nonce from another origin must not be remembered"


def test_resource_helpers_refuse_plain_http(server):  # noqa: F811
    ca = _ca(server)
    with pytest.raises(ClientAttestationError, match="resource URL must use https"):
        ca.request_headers("GET", "http://api.example.com/thing")
    with pytest.raises(ClientAttestationError, match="resource URL is not a valid URL"):
        ca.request_headers("GET", "https://[bad/x")
    assert ca.request_headers("GET", server + "/api")  # loopback is allowed
    insecure = _ca(server, allow_insecure=True)
    assert insecure.request_headers("GET", "http://api.example.com/thing")
