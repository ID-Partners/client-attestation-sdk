"""Attester profiles: the default PingFederate profile, static metadata (no discovery), and a custom
profile for a made-up attester whose discovery path, proof typ and mint request/response all differ."""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from client_attestation_sdk import (
    AttestationIssuanceClient,
    AttesterMetadata,
    AttesterProfile,
    ClientAttestation,
    ClientAttestationError,
    MintResult,
    PingFederateProfile,
    StaticSvidSource,
)


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _decode(jwt):
    head, payload, _ = jwt.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    return json.loads(base64.urlsafe_b64decode(pad(head))), json.loads(base64.urlsafe_b64decode(pad(payload)))


ATTESTATION = "e30." + _b64({"sub": "client-1"}) + ".sig"


class FakeAttester:
    """A loopback attester + token endpoint that answers both the PingFederate protocol and a made-up one
    ("acme"), and records every request."""

    def __init__(self):
        self.requests = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def paths(self):
        return [path for _, path, _, _ in self.requests]

    def body(self, path):
        return next(json.loads(body) for _, p, _, body in self.requests if p == path)

    def close(self):
        self._server.shutdown()
        self._server.server_close()

    def _handler(srv):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _answer(self, status, obj):
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                srv.requests.append(("GET", self.path, dict(self.headers), b"null"))
                if self.path == "/.well-known/client-attester":
                    return self._answer(200, {"evidence_audience": srv.url,
                                              "attestation_endpoint": srv.url + "/pf/mint",
                                              "token_endpoint": srv.url + "/token"})
                if self.path == "/acme/config":
                    return self._answer(200, {"audience": "acme-aud", "mint_url": srv.url + "/acme/mint",
                                              "token_url": srv.url + "/token"})
                self._answer(404, {"error": "not_found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b"null"
                srv.requests.append(("POST", self.path, dict(self.headers), body))
                if self.path == "/pf/mint":
                    return self._answer(200, {"attestation": ATTESTATION, "expires_in": 600})
                if self.path == "/acme/mint":
                    return self._answer(200, {"client_attestation": ATTESTATION, "ttl": 300})
                if self.path == "/token":
                    ok = self.headers.get("OAuth-Client-Attestation") == ATTESTATION and \
                        self.headers.get("OAuth-Client-Attestation-PoP")
                    return self._answer(200 if ok else 401, {"access_token": "at-1", "expires_in": 60}
                                        if ok else {"error": "invalid_client"})
                self._answer(404, {"error": "not_found"})

        return Handler


class AcmeProfile(AttesterProfile):
    """A non-PingFederate attester: its own discovery path and field names, its own proof typ, and a mint
    request and response of a different shape."""

    PROOF_TYP = "acme-key-proof+jwt"

    def discover(self, transport, attester_url):
        doc = transport.request_json("discover", "GET", attester_url + "/acme/config")
        return AttesterMetadata(evidence_audience=doc["audience"], attestation_endpoint=doc["mint_url"],
                                token_endpoint=doc["token_url"], document=doc)

    def mint(self, transport, metadata, request):
        proof = request.instance_proof(self.PROOF_TYP, "acme")
        body = {"evidence": request.evidence, "key": request.instance_key.public_jwk(), "pop": proof}
        response = transport.request_json("mint", "POST", metadata.attestation_endpoint, body)
        return MintResult(response["client_attestation"], response.get("ttl"))


@pytest.fixture
def attester():
    srv = FakeAttester()
    yield srv
    srv.close()


def test_default_profile_is_pingfederate(attester):
    ca = ClientAttestation(attester.url, evidence=StaticSvidSource("svid"))
    assert ca.token() == "at-1"
    assert attester.paths() == ["/.well-known/client-attester", "/pf/mint", "/token"]
    body = attester.body("/pf/mint")
    assert list(body) == ["instance_key", "svid", "proof"]
    header, claims = _decode(body["proof"])
    assert header["typ"] == PingFederateProfile.INSTANCE_PROOF_TYP == "oauth-attestation-instance-proof+jwt"
    assert claims["aud"] == attester.url


def test_custom_profile_gets_a_token_end_to_end(attester):
    ca = ClientAttestation(attester.url, evidence=StaticSvidSource("svid"), profile=AcmeProfile())
    assert ca.token() == "at-1"
    assert attester.paths() == ["/acme/config", "/acme/mint", "/token"]
    body = attester.body("/acme/mint")
    assert body["evidence"] == "svid" and body["key"]["kty"] == "EC"
    header, claims = _decode(body["pop"])
    assert header["typ"] == "acme-key-proof+jwt" and claims["aud"] == "acme"
    assert ca.discovery() == {"audience": "acme-aud", "mint_url": attester.url + "/acme/mint",
                              "token_url": attester.url + "/token"}


def test_static_metadata_skips_discovery_and_mints_with_the_default_protocol(attester):
    meta = AttesterMetadata(evidence_audience="aud-1", attestation_endpoint=attester.url + "/pf/mint",
                            token_endpoint=attester.url + "/token")
    ca = ClientAttestation(metadata=meta, evidence=StaticSvidSource("svid"))
    assert ca.base_url is None
    assert ca.token() == "at-1"
    assert attester.paths() == ["/pf/mint", "/token"]
    header, claims = _decode(attester.body("/pf/mint")["proof"])
    assert header["typ"] == "oauth-attestation-instance-proof+jwt" and claims["aud"] == "aud-1"
    assert ca.discovery() == {"evidence_audience": "aud-1", "attestation_endpoint": attester.url + "/pf/mint",
                              "token_endpoint": attester.url + "/token"}


def test_static_metadata_with_a_custom_profile_never_discovers(attester):
    meta = AttesterMetadata(evidence_audience="aud-1", attestation_endpoint=attester.url + "/acme/mint",
                            token_endpoint=attester.url + "/token")
    ca = ClientAttestation(attester.url, metadata=meta, evidence=StaticSvidSource("svid"), profile=AcmeProfile())
    assert ca.token() == "at-1"
    assert attester.paths() == ["/acme/mint", "/token"]


def test_static_metadata_must_name_a_token_endpoint(attester):
    meta = AttesterMetadata(evidence_audience="aud-1", attestation_endpoint=attester.url + "/pf/mint")
    with pytest.raises(ClientAttestationError, match="no token_endpoint"):
        ClientAttestation(metadata=meta, evidence=StaticSvidSource("svid")).token()


def test_static_endpoints_still_must_be_https():
    meta = AttesterMetadata(evidence_audience="aud", attestation_endpoint="http://attester.example/mint",
                            token_endpoint="https://as.example/token")
    with pytest.raises(ClientAttestationError, match="attestation_endpoint must use https"):
        ClientAttestation(metadata=meta, evidence=StaticSvidSource("svid")).token()


def test_custom_step_names_get_their_own_https_label():
    class OddProfile(AcmeProfile):
        def discover(self, transport, attester_url):
            transport.request_json("lookup", "GET", "http://attester.example/x")

    with pytest.raises(ClientAttestationError, match="lookup URL must use https"):
        ClientAttestation("https://attester.example", profile=OddProfile()).discovery()


def test_pf_host_keyword_is_gone():
    with pytest.raises(TypeError):
        ClientAttestation(pf_host="https://old.example")


def test_attester_url_is_required_without_metadata_or_profile():
    with pytest.raises(ValueError, match="attester_url is required"):
        ClientAttestation()


def test_pingfederate_discovery_needs_an_attester_url():
    with pytest.raises(ValueError, match="attester_url is required"):
        ClientAttestation(profile=PingFederateProfile()).discovery()


def test_pingfederate_falls_back_to_the_standard_token_path():
    class Doc:
        def request_json(self, step, method, url, body=None):
            return {"evidence_audience": "aud", "attestation_endpoint": "https://pf.example/mint"}

    meta = PingFederateProfile().discover(Doc(), "https://pf.example")
    assert meta.token_endpoint == "https://pf.example/as/token.oauth2"
    assert meta.as_document() == {"evidence_audience": "aud", "attestation_endpoint": "https://pf.example/mint"}


def test_the_base_profile_is_abstract():
    with pytest.raises(NotImplementedError):
        AttesterProfile().discover(None, "https://x")
    with pytest.raises(NotImplementedError):
        AttesterProfile().mint(None, AttesterMetadata(), None)


def test_issuance_client_takes_a_custom_profile(attester):
    client = AttestationIssuanceClient(attester.url + "/acme/mint", "client-1", "https://attester.example",
                                       StaticSvidSource("svid"), profile=AcmeProfile())
    issued = client.bootstrap()
    assert issued.attestation == ATTESTATION and issued.expires_in == 300
    header, _ = _decode(attester.body("/acme/mint")["pop"])
    assert header["typ"] == "acme-key-proof+jwt"


def test_issuance_client_default_profile_sends_client_id_first(attester):
    client = AttestationIssuanceClient(attester.url + "/pf/mint", "client-1", "https://attester.example",
                                       StaticSvidSource("svid"))
    issued = client.bootstrap(authorization_details=[{"type": "x"}], challenge="chal")
    assert issued.expires_in == 600
    body = attester.body("/pf/mint")
    assert list(body) == ["client_id", "instance_key", "svid", "proof", "authorization_details"]
    _, claims = _decode(body["proof"])
    assert claims["aud"] == "https://attester.example" and claims["challenge"] == "chal"
