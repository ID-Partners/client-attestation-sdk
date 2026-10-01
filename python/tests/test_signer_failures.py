import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from client_attestation_sdk import OpenBaoTransitSigner

KEY_NAME = "attestation-es256"
TOKEN = "unit-test-token"


def _pem(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _key_metadata(pem, key_type="ecdsa-p256"):
    return json.dumps({"data": {"type": key_type, "latest_version": 1, "keys": {"1": {"public_key": pem}}}})


class StubBao:
    """Serves one canned response per method for the two transit endpoints OpenBaoTransitSigner calls,
    so each failure mode of the vault protocol can be exercised."""

    def __init__(self, get_response, post_response=(200, "{}")):
        self._responses = {"GET": get_response, "POST": post_response}
        self._server = HTTPServer(("127.0.0.1", 0), self._handler())
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def close(self):
        self._server.shutdown()

    def _handler(stub):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _reply(self, method):
                status, body = stub._responses[method]
                data = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._reply("GET")

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self._reply("POST")

        return Handler


def test_unsupported_transit_key_type_fails():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bao = StubBao((200, _key_metadata(_pem(rsa_key), key_type="rsa-2048")))
    try:
        with pytest.raises(ValueError, match="unsupported type"):
            OpenBaoTransitSigner(bao.url, TOKEN, KEY_NAME)
    finally:
        bao.close()


def test_non_ec_public_key_pem_fails():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bao = StubBao((200, _key_metadata(_pem(rsa_key))))  # claims ecdsa-p256 but serves an RSA key
    try:
        with pytest.raises(ValueError, match="unsupported transit public key"):
            OpenBaoTransitSigner(bao.url, TOKEN, KEY_NAME)
    finally:
        bao.close()


def test_non_200_success_status_fails_closed():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    bao = StubBao((201, _key_metadata(_pem(ec_key))))
    try:
        with pytest.raises(RuntimeError, match="HTTP 201"):
            OpenBaoTransitSigner(bao.url, TOKEN, KEY_NAME)
    finally:
        bao.close()


def test_response_without_data_fails():
    bao = StubBao((200, '{"errors": []}'))
    try:
        with pytest.raises(RuntimeError, match="no data"):
            OpenBaoTransitSigner(bao.url, TOKEN, KEY_NAME)
    finally:
        bao.close()


def test_sign_response_without_signature_fails():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    bao = StubBao((200, _key_metadata(_pem(ec_key))),
                  post_response=(200, '{"data": {"key_version": 1}}'))
    try:
        signer = OpenBaoTransitSigner(bao.url, TOKEN, KEY_NAME)
        with pytest.raises(RuntimeError, match="no signature"):
            signer.sign(b"header.payload")
    finally:
        bao.close()
