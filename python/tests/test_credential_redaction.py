"""Credentials stay out of errors, default string forms and the redacted trace: a 2xx body that can't be
used is never kept (it is where tokens, attestations and SVIDs travel), a non-2xx body is kept up to 512
characters, and repr() leaves secrets out. Local fake servers only."""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from client_attestation_sdk import (
    AttestationIssuanceClient, AttesterMetadata, AttesterProfile, ClientAttestation, ClientAttestationError,
    MintRequest, MintResult, SigningKeyPair, StaticSvidSource,
)
from client_attestation_sdk.authz_challenge import CibaClient, CibaError
from client_attestation_sdk.spiffe import JwtSvid

AUD = "https://attester.example.com"  # the evidence_audience the fake attester's discovery document names

# Starts with eyJ like every JWT, and carries a marker that must not show up anywhere.
SECRET = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.SECRET-MARKER"
ATTESTATION = "eyJhbGciOiJFUzI1NiJ9." + base64.urlsafe_b64encode(b'{"sub":"c-1"}').rstrip(b"=").decode() + ".sig"


class _Server(BaseHTTPRequestHandler):
    """Discovery, mint and token; `answers` maps a path to the raw (status, body) it returns."""

    answers = {}

    def log_message(self, *args):
        pass

    def _raw(self, status, body):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        base = f"http://{self.headers['Host']}"
        self._raw(200, json.dumps({"attestation_endpoint": base + "/attest", "token_endpoint": base + "/token",
                                   "evidence_audience": "https://attester.example.com"}))

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        default = {"/attest": (200, json.dumps({"attestation": ATTESTATION})),
                   "/token": (200, json.dumps({"access_token": "AT", "expires_in": 60}))}
        self._raw(*self.answers.get(self.path, default.get(self.path, (404, "{}"))))


@pytest.fixture()
def server():
    _Server.answers = {}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Server)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _assert_no_secret(error):
    """Nothing in the chain (message, attributes, cause or context) carries the marker."""
    seen = error
    while seen is not None:
        assert "SECRET-MARKER" not in str(seen)
        assert "SECRET-MARKER" not in repr(vars(seen))
        seen = seen.__cause__ or seen.__context__


@pytest.mark.parametrize("body", [
    '{"access_token": "%s", "token_type": "Bearer"} trailing' % SECRET,
    "access_token=%s&token_type=Bearer" % SECRET,
    '{"accessToken": "%s", "token_type": "Bearer"}' % SECRET,
])
def test_unusable_2xx_token_response_keeps_no_body(server, body):
    _Server.answers = {"/token": (200, body)}
    ca = ClientAttestation(server, evidence=StaticSvidSource("svid"), evidence_audience=AUD, timeout=2)
    with pytest.raises(ClientAttestationError) as info:
        ca.token()
    assert info.value.body is None
    _assert_no_secret(info.value)


@pytest.mark.parametrize("body", [
    '{"attestation": "%s"} trailing' % SECRET,
    '{"client_attestation": "%s"}' % SECRET,
])
def test_unusable_2xx_mint_response_keeps_no_body(server, body):
    _Server.answers = {"/attest": (200, body)}
    ca = ClientAttestation(server, evidence=StaticSvidSource("svid"), evidence_audience=AUD, timeout=2)
    with pytest.raises(ClientAttestationError) as info:
        ca.token()
    assert info.value.body is None
    _assert_no_secret(info.value)


def test_token_endpoint_error_body_is_capped(server):
    long_body = json.dumps({"error": "invalid_client", "error_description": "d" * 2000})
    _Server.answers = {"/token": (401, long_body)}
    ca = ClientAttestation(server, evidence=StaticSvidSource("svid"), evidence_audience=AUD, timeout=2)
    with pytest.raises(ClientAttestationError) as info:
        ca.token()
    assert info.value.status == 401
    assert info.value.body == long_body[:512]


def test_issuance_error_body_is_capped(server):
    long_body = json.dumps({"error": "denied", "error_description": "d" * 2000})
    _Server.answers = {"/attest": (403, long_body)}
    client = AttestationIssuanceClient(server + "/attest", "c-1", "https://attester.example.com",
                                       StaticSvidSource("svid"))
    with pytest.raises(ClientAttestationError) as info:
        client.bootstrap()
    assert info.value.status == 403
    assert info.value.body == long_body[:512]
    assert len(str(info.value)) <= len("attestation issuance failed: HTTP 403: ") + 512


def test_repr_leaves_credentials_out():
    key = SigningKeyPair.generate("ES256")
    forms = [
        repr(MintRequest(key, SECRET, challenge="CHALLENGE-SECRET-MARKER", client_id="c-1")),
        repr(MintResult(SECRET, 60)),
        repr(JwtSvid("spiffe://td/w", SECRET, {}, "aud", 0, 60)),
    ]
    for form in forms:
        assert "SECRET-MARKER" not in form
    assert "client_id='c-1'" in forms[0]


class _AcmeProfile(AttesterProfile):
    """The docs' custom-profile example: the evidence and the proof go out under its own member names."""

    def discover(self, transport, attester_url):
        return AttesterMetadata(evidence_audience="acme-aud", attestation_endpoint=attester_url + "/attest",
                                token_endpoint=attester_url + "/token")

    def mint(self, transport, metadata, request):
        proof = request.instance_proof("acme-key-proof+jwt", metadata.evidence_audience)
        body = {"evidence": request.evidence, "key": request.instance_key.public_jwk(), "pop": proof}
        response = transport.request_json("mint", "POST", metadata.attestation_endpoint, body)
        return MintResult(response["attestation"], response.get("expires_in"))


def test_trace_redacts_a_custom_profiles_credentials(server):
    trace = []
    ca = ClientAttestation(server, profile=_AcmeProfile(), evidence=StaticSvidSource(SECRET),
                           evidence_audience="acme-aud", trace=trace, timeout=2)
    ca.token()
    mint = next(record["curl"] for record in trace if record["step"] == "mint")
    assert "SECRET-MARKER" not in mint
    assert "eyJ" not in mint             # the proof too
    assert '"kty": "EC"' in mint         # the public key is not a secret


def test_ciba_2xx_errors_keep_no_body():
    for text in ("auth_req_id=REQ-SECRET-MARKER", json.dumps({"id": "REQ-SECRET-MARKER"})):
        ciba = CibaClient(bc_auth_endpoint="https://pf.example/bc", token_endpoint="https://pf.example/token",
                          client_id="c-1", client_auth=_NoAuth(), issuer="https://pf.example",
                          http=lambda *args, text=text: (200, text))
        with pytest.raises(CibaError) as info:
            ciba.request(login_hint="alice", binding_message="ok")
        assert info.value.body is None
        _assert_no_secret(info.value)
    ciba = CibaClient(bc_auth_endpoint="https://pf.example/bc", token_endpoint="https://pf.example/token",
                      client_id="c-1", client_auth=_NoAuth(), issuer="https://pf.example",
                      http=lambda *args: (400, "x" * 2000))
    with pytest.raises(CibaError) as info:
        ciba.request(login_hint="alice", binding_message="ok")
    assert info.value.body == "x" * 512


class _NoAuth:
    def apply(self, endpoint, form):
        pass
