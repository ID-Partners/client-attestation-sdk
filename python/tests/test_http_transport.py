"""The shared HTTP transport (client_attestation_sdk._http) and the call sites that use it: no redirects,
a body cap, typed errors for non-2xx / malformed JSON / network failure / timeout. Local servers only."""
import base64
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from client_attestation_sdk.authz_challenge import CibaClient, CibaError, urllib_http
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
    assert info.value.body == long_body
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
    ca = ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), timeout=2)
    assert ca.token() == "at-1"
    token_request = [r for r in srv.requests if r[0] == "/token"][0]
    assert token_request[1]["OAuth-Client-Attestation"]


def test_token_endpoint_error_keeps_status_and_body(server):
    error = b'{"error": "invalid_client", "error_description": "use_attestation_challenge"}'
    srv = _attester(server, Route(400, error))
    ca = ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), timeout=2)
    with pytest.raises(ClientAttestationError) as info:
        ca.token()
    assert isinstance(info.value, TransportError)
    assert info.value.status == 400
    assert json.loads(info.value.body)["error"] == "invalid_client"
    assert str(info.value).startswith("token endpoint returned HTTP 400")


def test_token_endpoint_redirect_is_not_followed(server):
    srv = _attester(server, _redirect("/elsewhere", 307))
    ca = ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), timeout=2)
    with pytest.raises(TransportError) as info:
        ca.token()
    assert info.value.status == 307
    assert "/elsewhere" not in srv.hits


def test_token_endpoint_malformed_json_is_typed(server):
    srv = _attester(server, Route(200, b"<html>oops</html>"))
    ca = ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), timeout=2)
    with pytest.raises(TransportError, match="malformed JSON"):
        ca.token()


def test_discovery_without_attestation_endpoint_is_typed(server):
    srv = server({"/.well-known/client-attester": Route(200, b'{"evidence_audience": "aud"}')})
    ca = ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), timeout=2)
    with pytest.raises(TransportError, match="no attestation_endpoint"):
        ca.token()


def test_discovery_network_failure_is_typed(server):
    srv = server({})
    url = srv.url
    srv.close()
    with pytest.raises(TransportError):
        ClientAttestation(url, evidence=StaticSvidSource("svid"), timeout=1).token()


def test_minted_attestation_that_is_not_a_jwt_is_typed(server):
    srv = _attester(server, Route(200, b'{"access_token": "at-1"}'))
    srv.routes["/attest"] = Route(200, b'{"attestation": "garbage"}')
    with pytest.raises(ClientAttestationError, match="not a decodable JWT"):
        ClientAttestation(srv.url, evidence=StaticSvidSource("svid"), timeout=2).token()


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
    srv = server({"/gcp": Route(200, b"  gcp-token \n"), "/gcp-down": Route(503, b"no"),
                  "/azure": Route(200, b'{"token_type": "Bearer"}')})
    monkeypatch.setattr(evidence_mod, "GCP_METADATA_IDENTITY", srv.url + "/gcp")
    assert evidence_mod.GoogleMetadataSvidSource(timeout=2).fetch("aud") == "gcp-token"
    monkeypatch.setattr(evidence_mod, "GCP_METADATA_IDENTITY", srv.url + "/gcp-down")
    with pytest.raises(TransportError) as info:
        evidence_mod.GoogleMetadataSvidSource(timeout=2).fetch("aud")
    assert info.value.status == 503
    monkeypatch.setattr(evidence_mod, "AZURE_IMDS_IDENTITY", srv.url + "/azure")
    with pytest.raises(TransportError, match="no access_token"):
        evidence_mod.AzureImdsSvidSource(timeout=2).fetch("aud")


def test_metadata_probes_answer_false_off_cloud(server, monkeypatch):
    srv = server({"/metadata/instance": Route(200, b"{}")})
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
        discover(srv.url + "/meta")
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
