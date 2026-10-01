import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from client_attestation_sdk import (
    ClientAttestationBuilder,
    ClientAttestationCredential,
    OpenBaoTransitSigner,
    SigningKeyPair,
)

KEY_NAME = "attestation-es256"
TOKEN = "unit-test-token"


class FakeBao:
    """In-process fake of the OpenBao transit API surface OpenBaoTransitSigner uses
    (GET /v1/transit/keys/<name>, POST /v1/transit/sign/<name> with marshaling_algorithm=jws). Holds a real
    P-256 key so produced signatures genuinely verify."""

    def __init__(self, token=TOKEN):
        self.token = token
        self.key = ec.generate_private_key(ec.SECP256R1())
        self._server = HTTPServer(("127.0.0.1", 0), self._handler())
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def close(self):
        self._server.shutdown()

    def _handler(fake):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _send(self, status, body):
                data = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _bad_token(self):
                if self.headers.get("X-Vault-Token") != fake.token:
                    self._send(403, '{"errors":["permission denied"]}')
                    return True
                return False

            def do_GET(self):
                if self._bad_token():
                    return
                pem = fake.key.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                self._send(200, json.dumps({"data": {
                    "type": "ecdsa-p256", "latest_version": 1, "keys": {"1": {"public_key": pem}}}}))

            def do_POST(self):
                if self._bad_token():
                    return
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                if body.get("marshaling_algorithm") != "jws":
                    self._send(400, '{"errors":["expected marshaling_algorithm=jws"]}')
                    return
                signed = fake.key.sign(base64.b64decode(body["input"]), ec.ECDSA(hashes.SHA256()))
                r, s = decode_dss_signature(signed)
                raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
                envelope = "vault:v1:" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
                self._send(200, json.dumps({"data": {"signature": envelope, "key_version": 1}}))

        return Handler


def test_derives_public_jwk_and_kid():
    bao = FakeBao()
    try:
        signer = OpenBaoTransitSigner(bao.url, TOKEN, KEY_NAME)
        jwk = signer.public_jwk()
        assert signer.algorithm == "ES256"
        assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
        assert "x" in jwk and "y" in jwk
        assert jwk["kid"] == signer.key_id and jwk["alg"] == "ES256"
    finally:
        bao.close()


def test_vault_signed_attestation_verifies_with_the_vault_key():
    bao = FakeBao()
    try:
        signer = OpenBaoTransitSigner(bao.url, TOKEN, KEY_NAME)
        instance = SigningKeyPair.generate("ES256")
        attestation = (
            ClientAttestationBuilder(signer, "https://attester.example.com")
            .client_id("https://rp.example.com")
            .confirmation_key(instance)
            .expires_in(300)
            .build()
        )
        # the signature produced inside the (fake) vault verifies against the vault's public key
        public = jwt.get_algorithm_by_name("ES256").from_jwk(json.dumps(signer.public_jwk()))
        claims = jwt.decode(attestation, public, algorithms=["ES256"])
        assert claims["iss"] == "https://attester.example.com"
        assert claims["sub"] == "https://rp.example.com"
        assert claims["cnf"]["jwk"]["x"] == instance.public_jwk()["x"]
        header = jwt.get_unverified_header(attestation)
        assert header["typ"] == "oauth-client-attestation+jwt"
        assert header["kid"] == signer.key_id
        # the local instance key still signs the PoP headers
        headers = ClientAttestationCredential(attestation, instance).pop_headers(
            "https://rp.example.com", "https://as.example.com")
        assert headers["OAuth-Client-Attestation"] == attestation
    finally:
        bao.close()


def test_wrong_token_fails_closed():
    bao = FakeBao()
    try:
        raised = False
        try:
            OpenBaoTransitSigner(bao.url, "wrong-token", KEY_NAME)
        except Exception:
            raised = True
        assert raised, "a wrong token must fail closed"
    finally:
        bao.close()


def test_vault_down_fails_closed():
    bao = FakeBao()
    signer = OpenBaoTransitSigner(bao.url, TOKEN, KEY_NAME)
    bao.close()
    raised = False
    try:
        signer.sign(b"header.payload")
    except Exception:
        raised = True
    assert raised, "an unreachable vault must fail closed"
