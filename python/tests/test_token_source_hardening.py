"""ClientAttestation hardening: fail closed on a missing challenge, on a missing explicitly configured
evidence source and on plain-http endpoints; trace records redacted by default and curl strings that a
POSIX shell parses back to the exact arguments. Local fake servers only."""
import json
import shlex
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest

from client_attestation_sdk import ClientAttestation, ClientAttestationError, StaticSvidSource
from client_attestation_sdk import evidence as evidence_mod
from client_attestation_sdk.svid_source import SpireWorkloadApiSvidSource


def _seg(obj):
    import base64
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


class _Attester(BaseHTTPRequestHandler):
    """Discovery + challenge + mint + token. `config` (class-level) steers the failure modes."""

    config = {}
    mint_bodies = []

    def log_message(self, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode() if not isinstance(obj, bytes) else obj
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        base = f"http://{self.headers['Host']}"
        doc = {
            "attestation_endpoint": base + "/attest",
            "challenge_endpoint": base + "/challenge",
            "token_endpoint": base + "/token",
            "evidence_audience": "https://attester.example.com",
        }
        doc.update(self.config.get("discovery", {}))
        doc = {k: v for k, v in doc.items() if v is not None}
        self._json(200, doc)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if self.path == "/challenge":
            status, body = self.config.get("challenge", (200, {"attestation_challenge": "chal-1"}))
            return self._json(status, body)
        if self.path == "/attest":
            type(self).mint_bodies.append(json.loads(raw))
            return self._json(200, {"attestation": "eyJhbGciOiJFUzI1NiJ9." + _seg({"sub": "c-1"}) + ".sig"})
        if self.path == "/token":
            return self._json(200, {"access_token": "eyJ.at." + "x" * 8, "expires_in": 300})
        return self._json(404, {"error": "not_found"})


@pytest.fixture()
def attester():
    _Attester.config = {}
    _Attester.mint_bodies = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Attester)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


# ── 11a: challenge fails closed ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("challenge", [
    (500, {"error": "server_error"}),
    (200, {"something_else": "x"}),
    (200, b"<html>not json</html>"),
])
def test_advertised_challenge_that_cannot_be_fetched_fails_the_flow(attester, challenge):
    _Attester.config = {"challenge": challenge}
    ca = ClientAttestation(attester, evidence=StaticSvidSource("svid"), timeout=2)
    with pytest.raises(ClientAttestationError, match="could not get an attestation challenge"):
        ca.token()
    assert _Attester.mint_bodies == []  # never minted without the advertised challenge


def test_require_challenge_false_keeps_minting_without_one(attester):
    _Attester.config = {"challenge": (500, {"error": "server_error"})}
    ca = ClientAttestation(attester, evidence=StaticSvidSource("svid"), timeout=2, require_challenge=False)
    assert ca.token().startswith("eyJ")
    proof = jwt.decode(_Attester.mint_bodies[0]["proof"], options={"verify_signature": False})
    assert "challenge" not in proof


def test_no_advertised_challenge_endpoint_is_not_an_error(attester):
    _Attester.config = {"discovery": {"challenge_endpoint": None}}
    ca = ClientAttestation(attester, evidence=StaticSvidSource("svid"), timeout=2)
    assert ca.token()


# ── 11b: an explicitly configured evidence source that is missing never falls through ─────────────

@pytest.fixture()
def clean_env(monkeypatch):
    for var in (evidence_mod.ENV_SVID, evidence_mod.ENV_TOKEN_FILE, evidence_mod.ENV_SPIFFE_SOCKET):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(evidence_mod, "DEFAULT_TOKEN_FILE", "/nonexistent/attester-token")
    monkeypatch.setattr(evidence_mod, "DEFAULT_SPIFFE_SOCKET", "/nonexistent/spire.sock")
    # If anything did fall through, it would land here - make that loud.
    monkeypatch.setattr(evidence_mod, "_gcp_metadata_available", lambda timeout=0.3: True)
    return monkeypatch


def test_missing_token_file_names_the_variable(clean_env, tmp_path):
    clean_env.setenv(evidence_mod.ENV_TOKEN_FILE, str(tmp_path / "absent"))
    with pytest.raises(evidence_mod.EvidenceNotFound, match=evidence_mod.ENV_TOKEN_FILE):
        evidence_mod.auto_detect_evidence()


def test_missing_spiffe_socket_names_the_variable(clean_env, tmp_path):
    clean_env.setenv(evidence_mod.ENV_SPIFFE_SOCKET, "unix://" + str(tmp_path / "absent.sock"))
    with pytest.raises(evidence_mod.EvidenceNotFound, match=evidence_mod.ENV_SPIFFE_SOCKET):
        evidence_mod.auto_detect_evidence()


def test_present_spiffe_socket_and_unset_vars_keep_auto_detect(clean_env, tmp_path):
    sock = tmp_path / "api.sock"
    sock.write_text("")
    clean_env.setenv(evidence_mod.ENV_SPIFFE_SOCKET, "unix://" + str(sock))
    assert isinstance(evidence_mod.auto_detect_evidence(), SpireWorkloadApiSvidSource)

    clean_env.delenv(evidence_mod.ENV_SPIFFE_SOCKET)
    clean_env.setattr(evidence_mod, "DEFAULT_SPIFFE_SOCKET", str(sock))
    assert isinstance(evidence_mod.auto_detect_evidence(), SpireWorkloadApiSvidSource)

    clean_env.setattr(evidence_mod, "DEFAULT_SPIFFE_SOCKET", "/nonexistent/spire.sock")
    assert isinstance(evidence_mod.auto_detect_evidence(), evidence_mod.GoogleMetadataSvidSource)


# ── 11c: https everywhere except loopback or an explicit opt-out ─────────────────────────────────

@pytest.mark.parametrize("host", ["http://pf.example.com", "http://10.0.0.5:9031", "http://127.0.0.2"])
def test_plain_http_attester_url_is_refused(host):
    with pytest.raises(ClientAttestationError, match="attester_url must use https") as info:
        ClientAttestation(host)
    assert host in str(info.value)


@pytest.mark.parametrize("host", ["pf.example.com", "https://pf.example.com", "http://localhost:9031",
                                  "http://127.0.0.1:9031", "http://[::1]:9031", "http://LOCALHOST"])
def test_https_and_loopback_hosts_are_accepted(host):
    ClientAttestation(host)


def test_allow_insecure_accepts_plain_http():
    ClientAttestation("http://pingfederate.pf:9080", allow_insecure=True)


@pytest.mark.parametrize("field", ["challenge_endpoint", "attestation_endpoint", "token_endpoint"])
def test_plain_http_discovery_endpoint_is_refused(attester, field):
    insecure = "http://attester.example.com/" + field
    _Attester.config = {"discovery": {field: insecure}}
    ca = ClientAttestation(attester, evidence=StaticSvidSource("svid"), timeout=2)
    with pytest.raises(ClientAttestationError, match=f"{field} must use https") as info:
        ca.token()
    assert insecure in str(info.value)


# ── 12: trace redaction and shell quoting ────────────────────────────────────────────────────────

def _args(curl):
    # A trailing backslash-newline is a shell line continuation; shlex yields it as a bare "\n" token.
    return [arg for arg in shlex.split(curl) if arg != "\n"]


def _data_arg(curl):
    args = _args(curl)
    return args[args.index("-d") + 1]


def test_trace_is_redacted_by_default(attester):
    trace = []
    ca = ClientAttestation(attester, evidence=StaticSvidSource("eyJ.the-svid.sig"), trace=trace, timeout=2)
    ca.token()
    assert [r["step"] for r in trace] == ["discover", "challenge", "mint", "token"]
    dumped = json.dumps(trace)
    assert "eyJ" not in dumped
    assert "chal-1" not in dumped
    assert trace[1]["value"] == "<redacted:6 bytes>"
    assert trace[2]["jwt"].startswith("<redacted:")
    assert trace[3]["jwt"] == "<redacted:15 bytes>"
    mint = json.loads(_data_arg(trace[2]["curl"]))
    assert mint["svid"] == "<redacted:16 bytes>"
    assert mint["proof"].startswith("<redacted:")
    assert mint["instance_key"]["kty"] == "EC"  # the public key is not a secret
    token_args = _args(trace[3]["curl"])
    assert "OAuth-Client-Attestation: <redacted:" in " ".join(token_args)
    assert "grant_type=client_credentials" in token_args


def test_trace_redact_false_records_credentials_verbatim(attester):
    trace = []
    ca = ClientAttestation(attester, evidence=StaticSvidSource("eyJ.the-svid.sig"), trace=trace,
                           trace_redact=False, timeout=2)
    ca.token()
    assert trace[1]["value"] == "chal-1"
    assert trace[2]["jwt"].startswith("eyJ")
    assert trace[3]["jwt"].startswith("eyJ")
    assert json.loads(_data_arg(trace[2]["curl"]))["svid"] == "eyJ.the-svid.sig"


@pytest.mark.parametrize("redact", [True, False])
def test_curl_arguments_survive_a_single_quote(attester, redact):
    svid = "it's'a'svid"
    details = [{"type": "o'brien's \"quoted\" $(rm -rf /) `x`"}]
    trace = []
    ca = ClientAttestation(attester, evidence=StaticSvidSource(svid), trace=trace, trace_redact=redact,
                           authorization_details=details, timeout=2)
    ca.token()
    body = json.loads(_data_arg(trace[2]["curl"]))
    assert body["authorization_details"] == details
    assert body["svid"] == (svid if not redact else "<redacted:11 bytes>")
    # Every record is a well-formed command line: curl, method, URL, then -H/-d pairs.
    for record in trace:
        args = _args(record["curl"])
        assert args[:3] == ["curl", "-s", "-X"]
        assert args[4].startswith(attester)


def test_private_jwk_members_are_redacted():
    from client_attestation_sdk.token_source import _redact_json
    body = {"instance_key": {"kty": "EC", "crv": "P-256", "x": "X", "y": "Y", "d": "secret"},
            "assertion": "a", "nested": [{"client_secret": "s", "plain": 1}]}
    assert _redact_json(body) == {
        "instance_key": {"kty": "EC", "crv": "P-256", "x": "X", "y": "Y", "d": "<redacted:6 bytes>"},
        "assertion": "<redacted:1 bytes>", "nested": [{"client_secret": "<redacted:1 bytes>", "plain": 1}]}
