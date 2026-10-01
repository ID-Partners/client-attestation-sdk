"""Offline tests for the one-call token source: the full flow against a fake attester + token endpoint,
plus evidence auto-detection precedence and the small pure helpers. No live PingFederate needed."""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest

from client_attestation_sdk import ClientAttestation, StaticSvidSource
from client_attestation_sdk import evidence as evidence_mod
from client_attestation_sdk.token_source import _jwt_sub, _normalize_base_url


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def test_normalize_base_url_adds_https_and_strips_slash():
    assert _normalize_base_url("pf.example.com") == "https://pf.example.com"
    assert _normalize_base_url("https://pf.example.com/") == "https://pf.example.com"
    assert _normalize_base_url("http://pf.pf:9080") == "http://pf.pf:9080"
    with pytest.raises(ValueError):
        _normalize_base_url("   ")


def test_jwt_sub_reads_the_client_id():
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "demo-client"}).encode()).rstrip(b"=").decode()
    assert _jwt_sub("h." + payload + ".sig") == "demo-client"


def test_auto_detect_precedence(monkeypatch, tmp_path):
    # Explicit env token wins over everything.
    monkeypatch.setenv(evidence_mod.ENV_SVID, "the-token")
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, StaticSvidSource)
    assert source.fetch("aud") == "the-token"

    # Next: a token file.
    monkeypatch.delenv(evidence_mod.ENV_SVID, raising=False)
    token_file = tmp_path / "tok"
    token_file.write_text("file-token\n")
    monkeypatch.setenv(evidence_mod.ENV_TOKEN_FILE, str(token_file))
    source = evidence_mod.auto_detect_evidence()
    assert source.fetch("aud") == "file-token"


def test_auto_detect_raises_when_nothing_found(monkeypatch):
    monkeypatch.delenv(evidence_mod.ENV_SVID, raising=False)
    monkeypatch.delenv(evidence_mod.ENV_TOKEN_FILE, raising=False)
    monkeypatch.delenv(evidence_mod.ENV_SPIFFE_SOCKET, raising=False)
    monkeypatch.setattr(evidence_mod, "DEFAULT_TOKEN_FILE", "/nonexistent/attester-token")
    monkeypatch.setattr(evidence_mod, "DEFAULT_SPIFFE_SOCKET", "/nonexistent/spire.sock")
    monkeypatch.setattr(evidence_mod, "_gcp_metadata_available", lambda timeout=0.3: False)
    monkeypatch.setattr(evidence_mod, "_azure_imds_available", lambda timeout=0.3: False)
    monkeypatch.setattr(evidence_mod, "_aws_credentials_available", lambda: False)
    with pytest.raises(evidence_mod.EvidenceNotFound):
        evidence_mod.auto_detect_evidence()


def test_auto_detect_falls_through_to_azure_imds(monkeypatch):
    """Azure IMDS is tried after GCP metadata and before AWS credentials."""
    monkeypatch.delenv(evidence_mod.ENV_SVID, raising=False)
    monkeypatch.delenv(evidence_mod.ENV_TOKEN_FILE, raising=False)
    monkeypatch.delenv(evidence_mod.ENV_SPIFFE_SOCKET, raising=False)
    monkeypatch.setattr(evidence_mod, "DEFAULT_TOKEN_FILE", "/nonexistent/attester-token")
    monkeypatch.setattr(evidence_mod, "DEFAULT_SPIFFE_SOCKET", "/nonexistent/spire.sock")
    monkeypatch.setattr(evidence_mod, "_gcp_metadata_available", lambda timeout=0.3: False)
    monkeypatch.setattr(evidence_mod, "_azure_imds_available", lambda timeout=0.3: True)
    monkeypatch.setattr(evidence_mod, "_aws_credentials_available", lambda: True)
    source = evidence_mod.auto_detect_evidence()
    assert isinstance(source, evidence_mod.AzureImdsSvidSource)


def test_azure_imds_source_extracts_access_token_from_json_envelope(monkeypatch):
    """IMDS returns a JSON envelope ({"access_token": "...", ...}), unlike GCP's raw-JWT body — the
    source must extract, not return the raw response."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeImds)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        monkeypatch.setattr(evidence_mod, "AZURE_IMDS_IDENTITY", base + "/metadata/identity/oauth2/token")
        source = evidence_mod.AzureImdsSvidSource(timeout=2.0)
        token = source.fetch("https://attester.example.com")
        assert token == "azure-mi-jwt-xyz"
    finally:
        server.shutdown()


class _FakeImds(BaseHTTPRequestHandler):
    """Serves the Azure IMDS identity endpoint's JSON-envelope response shape."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        assert self.headers.get("Metadata") == "true"
        body = json.dumps({
            "access_token": "azure-mi-jwt-xyz",
            "client_id": "00000000-0000-0000-0000-000000000000",
            "expires_on": "1700000000",
            "resource": "https://attester.example.com",
            "token_type": "Bearer",
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ── full flow against a fake attester that mirrors what the real one does ───────────────────────────

class _FakeAttester(BaseHTTPRequestHandler):
    """Serves discovery, a challenge, a mint that echoes an attestation with sub=demo-client, and a
    token endpoint that requires the two attestation headers."""

    mint_bodies = []  # class-level; a test resets it via the fake_attester fixture
    token_request_headers = []  # class-level; a test resets it via the fake_attester fixture
    token_forms = []  # class-level; raw form bodies the token endpoint received

    def log_message(self, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        base = f"http://{self.headers['Host']}"
        self._json(200, {
            "attestation_endpoint": base + "/federation/attestation",
            "challenge_endpoint": base + "/federation/attestation-challenge",
            "token_endpoint": base + "/as/token.oauth2",
            "evidence_audience": "https://attester.example.com",
            "pop_audience": "https://pf.issuer.example",
        })

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if self.path.endswith("/attestation-challenge"):
            return self._json(200, {"attestation_challenge": "chal-123", "expires_in": 300})
        if self.path.endswith("/federation/attestation"):
            body = json.loads(raw)
            assert "instance_key" in body and "svid" in body and "proof" in body
            assert "client_id" not in body  # evidence-first: the workload sends no client_id
            type(self).mint_bodies.append(body)
            sub = base64.urlsafe_b64encode(json.dumps({"sub": "demo-client"}).encode()).rstrip(b"=").decode()
            return self._json(200, {"attestation": "h." + sub + ".sig", "expires_in": 300})
        if self.path.endswith("/as/token.oauth2"):
            if not self.headers.get("OAuth-Client-Attestation") or (
                    not self.headers.get("OAuth-Client-Attestation-PoP") and not self.headers.get("DPoP")):
                return self._json(401, {"error": "invalid_client"})
            assert b"grant_type=client_credentials" in raw
            assert b"client_secret" not in raw and b"client_id" not in raw
            type(self).token_forms.append(raw.decode())
            # http.client.HTTPMessage's .get() is case-insensitive, unlike a plain dict — and urllib's
            # own header-casing normalization (e.g. "DPoP" -> "Dpop") makes that the only sane read.
            type(self).token_request_headers.append({
                "pop": self.headers.get("OAuth-Client-Attestation-PoP"),
                "dpop": self.headers.get("DPoP"),
            })
            return self._json(200, {"access_token": "AT-xyz", "expires_in": 3600, "token_type": "Bearer"})
        return self._json(404, {"error": "not_found"})


@pytest.fixture()
def fake_attester():
    _FakeAttester.mint_bodies = []
    _FakeAttester.token_request_headers = []
    _FakeAttester.token_forms = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeAttester)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_full_flow_returns_and_caches_a_token(fake_attester):
    ca = ClientAttestation(fake_attester, evidence=StaticSvidSource("fake-svid"))
    token = ca.token()
    assert token == "AT-xyz"
    assert ca.authorization_header()["Authorization"] == "Bearer AT-xyz"
    # Cached: a second call returns the same token without re-minting.
    assert ca.token() == "AT-xyz"
    assert len(_FakeAttester.mint_bodies) == 1

    # Default mode sends the PoP JWT (not DPoP), and the PoP JWT carries the attester-issued
    # challenge — this is the bug fix: `_fetch_challenge`'s result must actually reach the
    # PopBuilder, not just the mint-time instance-key proof.
    headers = _FakeAttester.token_request_headers[0]
    assert headers["dpop"] is None
    assert _claims(headers["pop"])["challenge"] == "chal-123"


def test_dpop_combined_mode_sends_dpop_header_with_challenge_as_nonce(fake_attester):
    ca = ClientAttestation(fake_attester, evidence=StaticSvidSource("fake-svid"),
                            pop_method="dpop_combined")
    token = ca.token()
    assert token == "AT-xyz"

    headers = _FakeAttester.token_request_headers[0]
    assert headers["pop"] is None
    claims = _claims(headers["dpop"])
    assert claims["nonce"] == "chal-123"
    assert claims["htm"] == "POST"


def test_asserted_context_is_sent_and_never_cached(fake_attester):
    # A directory-hosted gateway threading an Entra-asserted Copilot-agent oid through: sent on the mint
    # body, and each call mints fresh (a different asserted discriminator can resolve to a different
    # ceiling, so reusing a cached token across discriminators would be wrong).
    ca = ClientAttestation(fake_attester, evidence=StaticSvidSource("fake-svid"))
    ca.token()  # warms the plain (no-asserted-context) cache
    assert len(_FakeAttester.mint_bodies) == 1

    asserted = {"type": "entra-copilot-agent-oid", "value": "d7c5a2b1-0000-4000-8000-copilot0demo"}
    ca.token(asserted_context=asserted)
    assert len(_FakeAttester.mint_bodies) == 2
    assert _FakeAttester.mint_bodies[-1]["asserted_context"] == asserted

    ca.token(asserted_context=asserted)  # again: still mints fresh, not served from any cache
    assert len(_FakeAttester.mint_bodies) == 3

    # The plain (no asserted_context) cache from the first call is untouched by any of the above.
    assert ca.token() == "AT-xyz"
    assert len(_FakeAttester.mint_bodies) == 3


def test_trace_records_every_wire_call_as_runnable_curl(fake_attester):
    """Opt-in `trace=` gets one {"step", "curl"} record per call, in order — the shape demo consoles
    render as "show the exact request". Absent (default None) costs nothing, per the other tests."""
    trace = []
    # trace_redact=False: this test reads the raw artifacts back (local-debugging mode).
    ca = ClientAttestation(fake_attester, evidence=StaticSvidSource("fake-svid"), trace=trace,
                           trace_redact=False)
    ca.token()

    steps = [c["step"] for c in trace]
    assert steps == ["discover", "challenge", "mint", "token"]
    for call in trace:
        assert call["curl"].startswith("curl -s -X ")
    # The mint step's curl actually carries the instance key + evidence, not just the verb/URL.
    mint_curl = trace[2]["curl"]
    assert "/federation/attestation " in mint_curl
    assert "fake-svid" in mint_curl
    # The token step sends form-encoded grant_type, not JSON.
    assert "grant_type=client_credentials" in trace[3]["curl"]
    assert "OAuth-Client-Attestation:" in trace[3]["curl"]

    # A caller that wants the actual artifacts (to decode-and-display, not just replay the request)
    # gets them without a second round trip: the issued challenge, the attestation, the access token.
    # (The fake attester's attestation is a bare "h.<payload>.sig", not a signed JWS — use _jwt_sub,
    # the same manual-decode helper the SDK itself uses, rather than jwt.decode's stricter parsing.)
    assert trace[1]["value"] == "chal-123"
    assert _jwt_sub(trace[2]["jwt"]) == "demo-client"
    assert trace[3]["jwt"] == "AT-xyz"


def test_challenge_at_token_false_omits_it_from_the_pop(fake_attester):
    """Some attesters consume the challenge the moment the mint's instance proof uses it, then reject
    a token request presenting the same value as unknown/expired. challenge_at_token=False keeps the
    mint-time protection (the challenge still reaches the instance proof) but drops the PoP's copy."""
    ca = ClientAttestation(fake_attester, evidence=StaticSvidSource("fake-svid"), challenge_at_token=False)
    token = ca.token()
    assert token == "AT-xyz"

    headers = _FakeAttester.token_request_headers[0]
    assert "challenge" not in _claims(headers["pop"])
    # The mint-time instance proof still carries it — only the token-endpoint copy was dropped.
    assert _claims(_FakeAttester.mint_bodies[0]["proof"])["challenge"] == "chal-123"


def test_challenge_at_token_false_omits_the_dpop_nonce(fake_attester):
    ca = ClientAttestation(fake_attester, evidence=StaticSvidSource("fake-svid"), challenge_at_token=False,
                           pop_method="dpop_combined")
    assert ca.token() == "AT-xyz"
    assert "nonce" not in _claims(_FakeAttester.token_request_headers[0]["dpop"])
    assert _claims(_FakeAttester.mint_bodies[0]["proof"])["challenge"] == "chal-123"


def test_operator_rides_the_mint_body_and_the_token_form_as_sorted_compact_json(fake_attester):
    from urllib.parse import parse_qs
    operator = {"sub": "ops-team@example.com", "iss": "https://op.example.com"}
    ca = ClientAttestation(fake_attester, evidence=StaticSvidSource("fake-svid"), operator=operator)
    assert ca.token() == "AT-xyz"
    assert _FakeAttester.mint_bodies[0]["operator"] == operator
    form = parse_qs(_FakeAttester.token_forms[0])
    assert form["operator"] == ['{"iss":"https://op.example.com","sub":"ops-team@example.com"}']


def test_no_operator_sends_nothing(fake_attester):
    ClientAttestation(fake_attester, evidence=StaticSvidSource("fake-svid")).token()
    assert "operator" not in _FakeAttester.mint_bodies[0]
    assert "operator" not in _FakeAttester.token_forms[0]
