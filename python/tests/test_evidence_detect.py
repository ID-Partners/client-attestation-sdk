"""Positive auto-detect tests for every evidence source, their precedence, and the remaining SVID-source and
issuance paths. Everything runs against local fakes: no real cloud metadata, SPIRE agent, or network."""
import json
import os
import stat
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest

import client_attestation_sdk
from client_attestation_sdk import (
    AttestationIssuanceClient,
    HttpSvidSource,
    IssuanceError,
    SigningKeyPair,
    SpiffeAgent,
    SpiffeAgentSvidSource,
    SpireWorkloadApiSvidSource,
    StaticSvidSource,
)
from client_attestation_sdk import evidence as evidence_mod


def test_draft_revision_constant():
    assert client_attestation_sdk.DRAFT_REVISION == "10"


# ── a tiny programmable local server ────────────────────────────────────────────────────────────────

class _Fake(BaseHTTPRequestHandler):
    routes = {}      # path (no query) -> (status, body bytes)
    requests = []    # (method, path-with-query, headers, body)

    def log_message(self, *args):
        pass

    def _serve(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).requests.append((method, self.path, dict(self.headers), body))
        status, payload = type(self).routes.get(self.path.split("?", 1)[0], (404, b"not found"))
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")


@pytest.fixture()
def fake():
    _Fake.routes = {}
    _Fake.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Fake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _closed_port_url():
    """A loopback URL nothing listens on: connection refused, immediately."""
    import socket
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}/"


@pytest.fixture()
def bare_env(monkeypatch, tmp_path):
    """Nothing detectable: env vars cleared, default paths absent, every metadata probe aimed at a
    refused port, no AWS credentials. Each test then turns on exactly what it wants."""
    for var in (evidence_mod.ENV_SVID, evidence_mod.ENV_TOKEN_FILE, evidence_mod.ENV_SPIFFE_SOCKET,
                "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_ID", "AWS_REGION"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(evidence_mod, "DEFAULT_TOKEN_FILE", str(tmp_path / "no-token"))
    monkeypatch.setattr(evidence_mod, "DEFAULT_SPIFFE_SOCKET", str(tmp_path / "no.sock"))
    closed = _closed_port_url()
    monkeypatch.setattr(evidence_mod, "GCP_METADATA_ROOT", closed)
    monkeypatch.setattr(evidence_mod, "AZURE_IMDS_INSTANCE", closed + "metadata/instance")
    return monkeypatch


# ── each source, positively detected ────────────────────────────────────────────────────────────────

def test_nothing_detectable_raises_with_guidance(bare_env):
    with pytest.raises(evidence_mod.EvidenceNotFound, match=evidence_mod.ENV_SVID):
        evidence_mod.auto_detect_evidence()


def test_env_token_is_detected_and_stripped(bare_env):
    bare_env.setenv(evidence_mod.ENV_SVID, "  env-token\n")
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, StaticSvidSource)
    assert source.fetch("aud") == "env-token"


def test_token_file_from_env_is_detected_and_read_fresh(bare_env, tmp_path):
    path = tmp_path / "tok"
    path.write_text("first\n")
    bare_env.setenv(evidence_mod.ENV_TOKEN_FILE, str(path))
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, evidence_mod.FileTokenSvidSource)
    assert source.fetch("aud") == "first"
    path.write_text("rotated\n")
    assert source.fetch("aud") == "rotated"


def test_default_token_file_is_detected(bare_env, tmp_path):
    path = tmp_path / "attester-token"
    path.write_text("projected")
    bare_env.setattr(evidence_mod, "DEFAULT_TOKEN_FILE", str(path))
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, evidence_mod.FileTokenSvidSource)
    assert source.fetch("aud") == "projected"


def _fake_spire_agent(tmp_path, output):
    script = tmp_path / "spire-agent"
    script.write_text("#!/bin/sh\n"
                      f"echo \"$@\" > {tmp_path / 'argv'}\n"
                      f"cat <<'EOF'\n{output}\nEOF\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spiffe_socket_is_detected_and_fetches_via_the_agent(bare_env, tmp_path):
    sock = tmp_path / "api.sock"
    sock.write_text("")
    bare_env.setenv(evidence_mod.ENV_SPIFFE_SOCKET, "unix://" + str(sock))
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, SpireWorkloadApiSvidSource)
    assert source._socket == str(sock)

    # Drive the detected source against a fake spire-agent binary.
    source._bin = _fake_spire_agent(tmp_path, "token(spiffe://example.org/w): aaa.bbb.ccc")
    assert source.fetch("https://attester.example.com") == "aaa.bbb.ccc"
    argv = (tmp_path / "argv").read_text().split()
    assert argv == ["api", "fetch", "jwt", "-audience", "https://attester.example.com", "-socketPath", str(sock)]


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spire_source_parses_a_bare_jwt_line_and_rejects_garbage(tmp_path):
    bare = SpireWorkloadApiSvidSource(socket_path="/x.sock",
                                      spire_agent=_fake_spire_agent(tmp_path, "header\nxxx.yyy.zzz"))
    assert bare.fetch("aud") == "xxx.yyy.zzz"
    garbage = SpireWorkloadApiSvidSource(socket_path="/x.sock",
                                         spire_agent=_fake_spire_agent(tmp_path, "no token here"))
    with pytest.raises(RuntimeError, match="could not parse SVID"):
        garbage.fetch("aud")


def test_default_spiffe_socket_is_detected(bare_env, tmp_path):
    sock = tmp_path / "default.sock"
    sock.write_text("")
    bare_env.setattr(evidence_mod, "DEFAULT_SPIFFE_SOCKET", str(sock))
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, SpireWorkloadApiSvidSource)
    assert source._socket == str(sock)


def test_gcp_metadata_is_detected_via_a_local_fake_and_fetches_an_id_token(bare_env, fake):
    _Fake.routes = {
        "/computeMetadata/v1/": (200, b"ok"),
        "/computeMetadata/v1/instance/service-accounts/default/identity": (200, b"gcp-id-token\n"),
    }
    root = fake + "/computeMetadata/v1/"
    bare_env.setattr(evidence_mod, "GCP_METADATA_ROOT", root)
    bare_env.setattr(evidence_mod, "GCP_METADATA_IDENTITY", root + "instance/service-accounts/default/identity")
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, evidence_mod.GoogleMetadataSvidSource)
    assert source.fetch("https://attester.example.com/x?y") == "gcp-id-token"
    probe, fetch = _Fake.requests
    assert probe[2].get("Metadata-Flavor") == "Google"
    assert fetch[1].endswith("?audience=https%3A%2F%2Fattester.example.com%2Fx%3Fy&format=full")


def test_gcp_probe_answering_non_2xx_is_not_detected(bare_env, fake):
    _Fake.routes = {"/computeMetadata/v1/": (404, b"")}
    bare_env.setattr(evidence_mod, "GCP_METADATA_ROOT", fake + "/computeMetadata/v1/")
    with pytest.raises(evidence_mod.EvidenceNotFound):
        evidence_mod.auto_detect_evidence()


def test_azure_imds_is_detected_via_a_local_fake_with_client_id(bare_env, fake):
    _Fake.routes = {
        "/metadata/instance": (200, b"{}"),
        "/metadata/identity/oauth2/token": (200, json.dumps({"access_token": "azure-tok"}).encode()),
    }
    bare_env.setattr(evidence_mod, "AZURE_IMDS_INSTANCE", fake + "/metadata/instance")
    bare_env.setattr(evidence_mod, "AZURE_IMDS_IDENTITY", fake + "/metadata/identity/oauth2/token")
    bare_env.setenv("AZURE_CLIENT_ID", "uami-1")
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, evidence_mod.AzureImdsSvidSource)
    assert source.client_id == "uami-1"
    assert source.fetch("api://attester") == "azure-tok"
    fetch = _Fake.requests[-1]
    assert "client_id=uami-1" in fetch[1] and "resource=api%3A%2F%2Fattester" in fetch[1]
    assert fetch[2].get("Metadata") == "true"


@pytest.mark.parametrize("env", [
    {"AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/aws/token"},
    {"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/x"},
    {"AWS_ACCESS_KEY_ID": "AKIA", "AWS_SECRET_ACCESS_KEY": "s"},
])
def test_aws_is_detected_from_visible_credentials(bare_env, env):
    for key, value in env.items():
        bare_env.setenv(key, value)
    bare_env.setenv("AWS_REGION", "ap-southeast-2")
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, evidence_mod.AwsWebIdentitySvidSource)
    assert source.region == "ap-southeast-2"


def test_aws_access_key_without_secret_is_not_detected(bare_env):
    bare_env.setenv("AWS_ACCESS_KEY_ID", "AKIA")
    with pytest.raises(evidence_mod.EvidenceNotFound):
        evidence_mod.auto_detect_evidence()


def test_aws_source_calls_sts_through_boto3(monkeypatch):
    calls = {}

    class _Sts:
        def get_web_identity_token(self, **kwargs):
            calls["kwargs"] = kwargs
            return {"WebIdentityToken": "aws-oidc-token"}

    def client(name, region_name=None):
        calls["client"] = (name, region_name)
        return _Sts()

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=client))
    assert evidence_mod.AwsWebIdentitySvidSource(region="us-east-1").fetch("aud-x") == "aws-oidc-token"
    assert calls["client"] == ("sts", "us-east-1")
    assert calls["kwargs"] == {"Audience": ["aud-x"], "SigningAlgorithm": "RS256"}


def test_aws_source_without_boto3_raises_evidence_not_found(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)  # makes `import boto3` raise ImportError
    with pytest.raises(evidence_mod.EvidenceNotFound, match="boto3"):
        evidence_mod.AwsWebIdentitySvidSource().fetch("aud")


# ── precedence: env token > token file > SPIRE socket > GCP > Azure > AWS ───────────────────────────

def test_full_precedence_chain(bare_env, fake, tmp_path):
    # Turn every source on, then peel them off from the top.
    _Fake.routes = {"/gcp/": (200, b"ok"), "/azure": (200, b"{}")}
    bare_env.setattr(evidence_mod, "GCP_METADATA_ROOT", fake + "/gcp/")
    bare_env.setattr(evidence_mod, "AZURE_IMDS_INSTANCE", fake + "/azure")
    bare_env.setenv("AWS_ACCESS_KEY_ID", "AKIA")
    bare_env.setenv("AWS_SECRET_ACCESS_KEY", "s")
    sock = tmp_path / "api.sock"
    sock.write_text("")
    bare_env.setenv(evidence_mod.ENV_SPIFFE_SOCKET, str(sock))
    token_file = tmp_path / "tok"
    token_file.write_text("t")
    bare_env.setenv(evidence_mod.ENV_TOKEN_FILE, str(token_file))
    bare_env.setenv(evidence_mod.ENV_SVID, "env")

    expected = [
        (evidence_mod.ENV_SVID, StaticSvidSource),
        (evidence_mod.ENV_TOKEN_FILE, evidence_mod.FileTokenSvidSource),
        (evidence_mod.ENV_SPIFFE_SOCKET, SpireWorkloadApiSvidSource),
        ("gcp", evidence_mod.GoogleMetadataSvidSource),
        ("azure", evidence_mod.AzureImdsSvidSource),
        (None, evidence_mod.AwsWebIdentitySvidSource),
    ]
    for remove, kind in expected:
        assert isinstance(evidence_mod.auto_detect_evidence(), kind)
        if remove == "gcp":
            _Fake.routes.pop("/gcp/")
        elif remove == "azure":
            _Fake.routes.pop("/azure")
        elif remove:
            bare_env.delenv(remove)


# ── the remaining SVID sources ──────────────────────────────────────────────────────────────────────

def test_http_svid_source_reads_the_svid_field(fake):
    _Fake.routes = {"/dev/svid": (200, json.dumps({"svid": "http-svid"}).encode())}
    assert HttpSvidSource(fake + "/dev/svid").fetch("aud") == "http-svid"


def test_spiffe_agent_svid_source_attests_the_selectors():
    agent = SpiffeAgent("example.org", SigningKeyPair.generate("ES256"))
    agent.register({"docker:label:app": "payments"}, "spiffe://example.org/payments")
    svid = SpiffeAgentSvidSource(agent, {"docker:label:app": "payments"}).fetch("https://attester")
    claims = jwt.decode(svid, options={"verify_signature": False})
    assert claims["sub"] == "spiffe://example.org/payments"
    assert claims["aud"] in ("https://attester", ["https://attester"])


# ── issuance client: challenge, authorization_details, and refusal on the wire ──────────────────────

def test_issuance_sends_challenge_and_authorization_details(fake):
    _Fake.routes = {"/issue": (200, json.dumps({"attestation": "a.b.c", "expires_in": 60}).encode())}
    client = AttestationIssuanceClient(fake + "/issue/", "client-1", "https://attester",
                                       StaticSvidSource("svid-1"))
    details = [{"type": "payment_initiation"}]
    issued = client.bootstrap(authorization_details=details, challenge="chal-9")
    assert issued.attestation == "a.b.c" and issued.expires_in == 60

    body = json.loads(_Fake.requests[-1][3])
    assert body["client_id"] == "client-1" and body["svid"] == "svid-1"
    assert body["authorization_details"] == details
    proof = jwt.decode(body["proof"], options={"verify_signature": False})
    assert proof["challenge"] == "chal-9" and proof["aud"] == "https://attester"


def test_issuance_refusal_raises_issuance_error(fake):
    _Fake.routes = {"/issue": (403, b"svid not trusted")}
    client = AttestationIssuanceClient(fake + "/issue", "client-1", "https://attester",
                                       StaticSvidSource("svid-1"))
    with pytest.raises(IssuanceError) as info:
        client.bootstrap()
    assert info.value.status == 403
    assert "challenge" not in jwt.decode(json.loads(_Fake.requests[-1][3])["proof"],
                                         options={"verify_signature": False})
