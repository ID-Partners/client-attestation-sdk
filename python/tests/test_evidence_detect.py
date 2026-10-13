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
    routes = {}      # path (no query) -> (status, body bytes[, headers])
    requests = []    # (method, path-with-query, headers, body)

    def log_message(self, *args):
        pass

    def _serve(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).requests.append((method, self.path, dict(self.headers), body))
        status, payload, *headers = type(self).routes.get(self.path.split("?", 1)[0], (404, b"not found"))
        self.send_response(status)
        for key, value in (headers[0] if headers else {}).items():
            self.send_header(key, value)
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
                "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_ID", "AWS_REGION"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(evidence_mod, "DEFAULT_TOKEN_FILE", str(tmp_path / "no-token"))
    monkeypatch.setattr(evidence_mod, "DEFAULT_SPIFFE_SOCKET", str(tmp_path / "no.sock"))
    closed = _closed_port_url()
    monkeypatch.setattr(evidence_mod, "GCP_METADATA_ROOT", closed)
    monkeypatch.setattr(evidence_mod, "AZURE_IMDS_INSTANCE", closed + "metadata/instance")
    return monkeypatch


# The real GCP metadata server marks every answer with this header.
GOOGLE = {"Metadata-Flavor": "Google"}
# The documented shape of an Azure IMDS instance-metadata answer.
AZURE_INSTANCE = json.dumps({"compute": {"azEnvironment": "AzurePublicCloud"}, "network": {}}).encode()


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


def _fake_spire_agent(tmp_path, output, stderr="", exit_code=0):
    script = tmp_path / "spire-agent"
    (tmp_path / "stdout").write_text(output)
    (tmp_path / "stderr").write_text(stderr)
    script.write_text("#!/bin/sh\n"
                      f"echo \"$@\" > {tmp_path / 'argv'}\n"
                      f"cat {tmp_path / 'stderr'} >&2\n"
                      f"cat {tmp_path / 'stdout'}\n"
                      f"exit {exit_code}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


# Two JWT-SVIDs shaped like real ones: an ES256 header with a kid, a SPIFFE sub, a 64-byte signature.
SPIRE_SVID = ("eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiaHR0cHM6Ly9hdWQiXSwiZXhwIjo0MTAy"
              "NDQ0ODAwLCJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy93bCJ9.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj"
              "JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw")
SPIRE_OTHER_SVID = ("eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiaHR0cHM6Ly9hdWQiXSwiZXhwIjo0"
                    "MTAyNDQ0ODAwLCJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy9vdGhlciJ9.QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFla"
                    "W1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-fw")
SPIRE_BUNDLE = ('{"keys":[{"kty":"EC","kid":"k1","crv":"P-256","x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",'
                '"y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"}]}')
# What `spire-agent api fetch jwt` prints for two SVIDs, one with a hint, and a bundle: the layout of
# printPrettyResult in SPIRE's cmd/spire-agent/cli/api/fetch_jwt.go (v1.5 to v1.15),
# "token(%s):\n\t%s\n", "hint(%s):\n\t%s\n" and "bundle(%s):\n\t%s\n".
SPIRE_OUTPUT = (f"token(spiffe://example.org/wl):\n\t{SPIRE_SVID}\n"
                "hint(spiffe://example.org/wl):\n\texternal\n"
                f"token(spiffe://example.org/other):\n\t{SPIRE_OTHER_SVID}\n"
                f"bundle(spiffe://example.org):\n\t{SPIRE_BUNDLE}\n")


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spiffe_socket_is_detected_and_fetches_via_the_agent(bare_env, tmp_path):
    sock = tmp_path / "api.sock"
    sock.write_text("")
    bare_env.setenv(evidence_mod.ENV_SPIFFE_SOCKET, "unix://" + str(sock))
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, SpireWorkloadApiSvidSource)
    assert source._socket == str(sock)

    # Drive the detected source against a fake spire-agent binary printing SPIRE's real layout.
    source._bin = _fake_spire_agent(tmp_path, SPIRE_OUTPUT)
    assert source.fetch("https://attester.example.com") == SPIRE_SVID
    argv = (tmp_path / "argv").read_text().split()
    assert argv == ["api", "fetch", "jwt", "-audience", "https://attester.example.com", "-socketPath", str(sock)]


def _spire(tmp_path, output, stderr="", exit_code=0):
    return SpireWorkloadApiSvidSource(socket_path="/x.sock",
                                      spire_agent=_fake_spire_agent(tmp_path, output, stderr, exit_code))


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spire_source_parses_the_single_line_form_and_a_bare_jwt_line(tmp_path):
    assert _spire(tmp_path, f"token(spiffe://example.org/w): {SPIRE_SVID}").fetch("aud") == SPIRE_SVID
    assert _spire(tmp_path, f"header\n  {SPIRE_SVID}  \n").fetch("aud") == SPIRE_SVID


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spire_source_does_not_read_stderr_as_output(tmp_path):
    assert _spire(tmp_path, SPIRE_OUTPUT, stderr="1.9.6\n").fetch("aud") == SPIRE_SVID
    with pytest.raises(evidence_mod.EvidenceNotFound):
        _spire(tmp_path, "", stderr="1.9.6\n").fetch("aud")


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
@pytest.mark.parametrize("output", [
    "1.9.6\n",
    "level=info msg=starting version=v1.9.6\n",
    "a.b.c\n",
    "token(spiffe://example.org/wl):\n\t1.9.6\n",
    "token(spiffe://example.org/wl):\n",
    "eyJ0eXAiOiJKV1QifQ.e30.c2ln\n",   # a JSON header with no alg
    "bnVsbA.e30.c2ln\n",              # a header of null
    "eyJhbGciOiJFUzI1NiJ9.e30.\n",     # no signature
    "no token here",
    "eyJhbGciOiJFUzI1NiIsfQ.e30.c2ln\n",                    # {"alg":"ES256",}: not strict JSON
    "eyJhbGciOiJFUzI1NiIsImFsZyI6IkVTMjU2In0.e30.c2ln\n",   # a duplicate "alg"
    "77u_eyJhbGciOiJFUzI1NiJ9.e30.c2ln\n",                  # a header with a BOM
    f"\ufeff{SPIRE_SVID}\n",                                 # a BOM is not whitespace
    f"\u00a0{SPIRE_SVID}\u00a0\n",                          # nor is an NBSP
    f"token(spiffe://example.org/wl):\n\u00a0{SPIRE_SVID}\n",
    f"token(spiffe://example.org/wl): \ufeff{SPIRE_SVID}\n",
    f"\v{SPIRE_SVID}\f\n",
])
def test_spire_source_refuses_output_without_a_compact_jws(tmp_path, output):
    with pytest.raises(evidence_mod.EvidenceNotFound, match="could not parse a JWT-SVID"):
        _spire(tmp_path, output).fetch("aud")


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spire_source_ignores_only_ascii_space_tab_and_cr_around_a_value(tmp_path):
    output = f"token(spiffe://example.org/wl):\r\n \t{SPIRE_SVID}\t \r\n"
    assert _spire(tmp_path, output).fetch("aud") == SPIRE_SVID


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
@pytest.mark.parametrize("output", [
    f"hint(spiffe://example.org/wl):\ntoken(spiffe://example.org/wl): {SPIRE_SVID}\n",
    f"token(spiffe://example.org/wl):\ntoken(spiffe://example.org/other): {SPIRE_SVID}\n",
    f"bundle(spiffe://example.org):\n\ttoken(spiffe://example.org/wl): {SPIRE_SVID}\n",
])
def test_spire_source_label_with_no_value_does_not_take_the_next_label(tmp_path, output):
    assert _spire(tmp_path, output).fetch("aud") == SPIRE_SVID


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spire_source_caps_stdout_at_1_mib(tmp_path):
    line = f"token(spiffe://example.org/wl): {SPIRE_SVID}\n"
    at_cap = line + "x" * ((1 << 20) - len(line))
    assert _spire(tmp_path, at_cap).fetch("aud") == SPIRE_SVID
    # One byte more while the agent is still running fails the fetch.
    (tmp_path / "over").write_text(at_cap + "x")
    script = tmp_path / "over-agent"
    script.write_text(f"#!/bin/sh\ncat {tmp_path / 'over'}\nexec sleep 5\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    with pytest.raises(RuntimeError) as caught:
        SpireWorkloadApiSvidSource(spire_agent=str(script)).fetch("aud")
    assert str(caught.value) == "spire-agent fetch failed: output is larger than 1048576 bytes"


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spire_source_agent_that_writes_past_the_cap_and_exits_always_fails(tmp_path):
    # The agent itself writes 1 MiB + 1 byte and exits at once, so the last bytes may be read either side of
    # its exit. They were written while it ran, so the fetch fails every time, as in the other ports.
    script = tmp_path / "over-exit-agent"
    script.write_text("#!/bin/sh\nexec head -c 1048577 /dev/zero\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    ok = 0
    for _ in range(50):
        try:
            SpireWorkloadApiSvidSource(spire_agent=str(script)).fetch("aud")
            ok += 1
        except evidence_mod.EvidenceNotFound:   # read as post-exit output: cut at the cap, no token in it
            ok += 1
        except RuntimeError as e:
            assert str(e) == "spire-agent fetch failed: output is larger than 1048576 bytes"
    assert ok == 0, f"{ok} of 50 runs did not fail with the size error"


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spire_source_kills_a_hung_agent(tmp_path, monkeypatch):
    import subprocess
    import time
    from client_attestation_sdk import svid_source
    monkeypatch.setattr(svid_source, "_SPIRE_AGENT_TIMEOUT", 0.3)
    script = tmp_path / "hang"
    script.write_text("#!/bin/sh\nexec sleep 30\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        SpireWorkloadApiSvidSource(spire_agent=str(script)).fetch("aud")
    assert time.monotonic() - start < 10
    assert caught.value.output is None and caught.value.stderr is None


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spire_source_discards_a_flood_of_stderr(tmp_path):
    assert _spire(tmp_path, SPIRE_OUTPUT, stderr="e" * (4 << 20)).fetch("aud") == SPIRE_SVID


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spire_source_error_does_not_show_the_output(tmp_path):
    output = f"secret-not-a-jwt\nbundle(spiffe://example.org):\n\t{SPIRE_BUNDLE}\n"
    with pytest.raises(evidence_mod.EvidenceNotFound) as caught:
        _spire(tmp_path, output, stderr=SPIRE_SVID).fetch("aud")
    message = str(caught.value)
    assert "secret-not-a-jwt" not in message and "WKn-ZIG" not in message and SPIRE_SVID not in message
    assert f"{len(output)} bytes, 3 lines" in message


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spire_source_error_counts_lines_by_lf_alone(tmp_path):
    with pytest.raises(evidence_mod.EvidenceNotFound, match=r"\(4 bytes, 1 lines; not shown\)"):
        _spire(tmp_path, "x\ry\n").fetch("aud")


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_spire_source_fails_when_the_agent_fails(tmp_path):
    with pytest.raises(RuntimeError, match="spire-agent fetch failed: exit status 1") as caught:
        _spire(tmp_path, SPIRE_OUTPUT, stderr="error: no identity issued\n", exit_code=1).fetch("aud")
    assert SPIRE_SVID not in str(caught.value)


def test_default_spiffe_socket_is_detected(bare_env, tmp_path):
    sock = tmp_path / "default.sock"
    sock.write_text("")
    bare_env.setattr(evidence_mod, "DEFAULT_SPIFFE_SOCKET", str(sock))
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, SpireWorkloadApiSvidSource)
    assert source._socket == str(sock)


def test_gcp_metadata_is_detected_via_a_local_fake_and_fetches_an_id_token(bare_env, fake):
    _Fake.routes = {
        "/computeMetadata/v1/": (200, b"ok", GOOGLE),
        "/computeMetadata/v1/instance/service-accounts/default/identity": (200, b"gcp-id-token\n", GOOGLE),
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
    _Fake.routes = {"/computeMetadata/v1/": (404, b"", GOOGLE)}
    bare_env.setattr(evidence_mod, "GCP_METADATA_ROOT", fake + "/computeMetadata/v1/")
    with pytest.raises(evidence_mod.EvidenceNotFound):
        evidence_mod.auto_detect_evidence()


def test_azure_imds_is_detected_via_a_local_fake_with_client_id(bare_env, fake):
    _Fake.routes = {
        "/metadata/instance": (200, AZURE_INSTANCE),
        "/metadata/identity/oauth2/token": (200, json.dumps({"access_token": "azure-tok"}).encode()),
    }
    bare_env.setattr(evidence_mod, "AZURE_IMDS_INSTANCE", fake + "/metadata/instance")
    bare_env.setattr(evidence_mod, "AZURE_IMDS_IDENTITY", fake + "/metadata/identity/oauth2/token")
    bare_env.setenv("AZURE_CLIENT_ID", "uami-1")
    bare_env.setenv(evidence_mod.ENV_AZURE_RESOURCE, "api://attester")
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, evidence_mod.AzureImdsSvidSource)
    assert source.client_id == "uami-1" and source.resource == "api://attester"
    assert source.fetch("api://attester") == "azure-tok"
    fetch = _Fake.requests[-1]
    assert "client_id=uami-1" in fetch[1] and "resource=api%3A%2F%2Fattester" in fetch[1]
    assert fetch[2].get("Metadata") == "true"


def test_azure_imds_never_requests_a_resource_the_caller_did_not_name(bare_env, fake):
    """The audience comes from the attester's discovery document; IMDS would mint a token for any
    resource it is asked for (Azure Resource Manager included). Only the configured one is requested."""
    _Fake.routes = {"/metadata/identity/oauth2/token": (200, json.dumps({"access_token": "arm-tok"}).encode())}
    bare_env.setattr(evidence_mod, "AZURE_IMDS_IDENTITY", fake + "/metadata/identity/oauth2/token")
    _Fake.requests.clear()
    limited = evidence_mod.AzureImdsSvidSource(resource="api://attester")
    with pytest.raises(evidence_mod.ClientAttestationError, match="limited to 'api://attester'"):
        limited.fetch("https://management.azure.com/")
    with pytest.raises(evidence_mod.ClientAttestationError, match=evidence_mod.ENV_AZURE_RESOURCE):
        evidence_mod.AzureImdsSvidSource().fetch("api://attester")
    assert _Fake.requests == []


@pytest.mark.parametrize("env", [
    {"AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/aws/token"},
    {"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/x"},
    # EKS Pod Identity
    {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials",
     "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": "/var/run/eks-pod-identity-token"},
    {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials"},
    {"AWS_ACCESS_KEY_ID": "AKIA", "AWS_SECRET_ACCESS_KEY": "s"},
])
def test_aws_is_detected_from_visible_credentials(bare_env, env):
    for key, value in env.items():
        bare_env.setenv(key, value)
    bare_env.setenv("AWS_REGION", "ap-southeast-2")
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, evidence_mod.AwsWebIdentitySvidSource)
    assert source.region == "ap-southeast-2"


@pytest.mark.parametrize("env", [
    {},
    # Neither of these is a credential on its own, and nothing probes EC2 IMDS.
    {"AWS_REGION": "us-east-1"},
    {"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": "/var/run/token"},
    {"AWS_CONTAINER_CREDENTIALS_FULL_URI": ""},
])
def test_no_aws_signal_falls_through_to_evidence_not_found(bare_env, env):
    for key, value in env.items():
        bare_env.setenv(key, value)
    with pytest.raises(evidence_mod.EvidenceNotFound):
        evidence_mod.auto_detect_evidence()


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
    _Fake.routes = {"/gcp/": (200, b"ok", GOOGLE), "/azure": (200, AZURE_INSTANCE)}
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


# ── who may answer as a metadata server ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("route", [
    (200, b"ok"),                          # no Metadata-Flavor: some other host answering the name
    (200, b"ok", {"Metadata-Flavor": "Other"}),
    (204, b"", GOOGLE),                     # 2xx, but not 200
])
def test_gcp_probe_needs_200_and_the_flavor_header(bare_env, fake, route):
    _Fake.routes = {"/computeMetadata/v1/": route}
    bare_env.setattr(evidence_mod, "GCP_METADATA_ROOT", fake + "/computeMetadata/v1/")
    with pytest.raises(evidence_mod.EvidenceNotFound):
        evidence_mod.auto_detect_evidence()


@pytest.mark.parametrize("route", [(200, b"id-token"), (200, b"id-token", {"Metadata-Flavor": "Other"}),
                                   (203, b"id-token", GOOGLE)])
def test_gcp_identity_needs_200_and_the_flavor_header(bare_env, fake, route):
    _Fake.routes = {"/identity": route}
    bare_env.setattr(evidence_mod, "GCP_METADATA_IDENTITY", fake + "/identity")
    with pytest.raises(client_attestation_sdk.TransportError, match="Metadata-Flavor"):
        evidence_mod.GoogleMetadataSvidSource(timeout=2).fetch("aud")


@pytest.mark.parametrize("route", [(200, b"{}"), (200, b"not json"), (200, b'{"compute": "x"}'),
                                   (201, AZURE_INSTANCE)])
def test_azure_probe_needs_200_and_instance_metadata(bare_env, fake, route):
    _Fake.routes = {"/metadata/instance": route}
    bare_env.setattr(evidence_mod, "AZURE_IMDS_INSTANCE", fake + "/metadata/instance")
    with pytest.raises(evidence_mod.EvidenceNotFound):
        evidence_mod.auto_detect_evidence()


# ── token file limits ──────────────────────────────────────────────────────────────────────────────

def test_token_file_over_64_kib_is_refused(tmp_path):
    big = tmp_path / "big"
    big.write_bytes(b"a" * (64 * 1024 + 1))
    with pytest.raises(evidence_mod.EvidenceNotFound, match="larger than"):
        evidence_mod.FileTokenSvidSource(str(big)).fetch("aud")
    exact = tmp_path / "exact"
    exact.write_bytes(b"b" * (64 * 1024))
    assert len(evidence_mod.FileTokenSvidSource(str(exact)).fetch("aud")) == 64 * 1024


@pytest.mark.skipif(os.name != "posix", reason="FIFOs and /dev/zero are POSIX")
def test_token_file_that_is_not_a_regular_file_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    for path in (str(fifo), "/dev/zero"):
        with pytest.raises(evidence_mod.EvidenceNotFound, match="not a regular file"):
            evidence_mod.FileTokenSvidSource(path).fetch("aud")


def test_missing_token_file_still_raises_os_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        evidence_mod.FileTokenSvidSource(str(tmp_path / "nope")).fetch("aud")


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


# ── metadata requests never go through a proxy from the environment ────────────────────────────────

_PROXY_CHILD = r"""
import json, sys
from client_attestation_sdk import _http, evidence as ev
fake = sys.argv[1]
ev.GCP_METADATA_ROOT = fake + "/computeMetadata/v1/"
ev.GCP_METADATA_IDENTITY = ev.GCP_METADATA_ROOT + "instance/service-accounts/default/identity"
ev.AZURE_IMDS_INSTANCE = fake + "/metadata/instance"
ev.AZURE_IMDS_IDENTITY = fake + "/metadata/identity/oauth2/token"
out = {
    "gcp_probe": ev._gcp_metadata_available(timeout=5),
    "gcp_token": ev.GoogleMetadataSvidSource(timeout=5).fetch("https://attester.example"),
    "azure_probe": ev._azure_imds_available(timeout=5),
    "azure_token": ev.AzureImdsSvidSource(resource="api://attester", timeout=5).fetch("api://attester"),
}
# An ordinary plain-http SDK request goes direct too: the SDK never sends plain http to a proxy.
out["plain"] = _http.request("GET", fake + "/plain", timeout=5).status
# Control: urllib's own opener in the same process does use the proxy, so the setup is sound.
import urllib.request
out["control"] = urllib.request.urlopen(fake + "/control", timeout=5).status
print(json.dumps(out))
"""


def test_metadata_requests_ignore_http_proxy(fake):
    """GCP metadata and Azure IMDS calls, probe and fetch, go straight to the metadata server even with
    HTTP_PROXY set: the identity request is plain HTTP, so a proxy would see the token. urllib reads the
    proxy environment when an opener is built, so this runs in a child process."""
    import subprocess

    proxied = []

    class _Proxy(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            proxied.append(self.path)
            # Answer as the metadata server would, so a proxied request would succeed and be used.
            body = b'{"compute": {}, "access_token": "proxy-token"}'
            self.send_response(200)
            self.send_header("Metadata-Flavor", "Google")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), _Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    _Fake.routes = {
        "/computeMetadata/v1/": (200, b"ok", GOOGLE),
        "/computeMetadata/v1/instance/service-accounts/default/identity": (200, b"gcp-id-token\n", GOOGLE),
        "/metadata/instance": (200, AZURE_INSTANCE),
        "/metadata/identity/oauth2/token": (200, json.dumps({"access_token": "azure-tok"}).encode()),
    }
    proxy_url = f"http://127.0.0.1:{proxy.server_address[1]}"
    env = {k: v for k, v in os.environ.items() if k.lower() not in ("no_proxy", "http_proxy", "all_proxy")}
    env.update(HTTP_PROXY=proxy_url, http_proxy=proxy_url)
    try:
        result = subprocess.run([sys.executable, "-c", _PROXY_CHILD, fake], env=env, capture_output=True,
                                text=True, timeout=60)
    finally:
        proxy.shutdown()
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    assert out["gcp_probe"] is True and out["gcp_token"] == "gcp-id-token"
    assert out["azure_probe"] is True and out["azure_token"] == "azure-tok"
    assert [path for path in proxied if "/control" not in path] == [], "an SDK request went via the proxy"
    assert any("/control" in path for path in proxied), "control: HTTP_PROXY was not in effect"
    assert len(_Fake.requests) == 5 and _Fake.requests[-1][1] == "/plain"
