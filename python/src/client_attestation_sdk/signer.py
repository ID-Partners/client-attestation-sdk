"""External JWS signing — keys that live outside the process (a vault, HSM, or KMS)."""
from __future__ import annotations

import base64
import json
from typing import Protocol, runtime_checkable

from . import _http
from .errors import TransportError
from .keys import _b64url, _thumbprint


@runtime_checkable
class JwsSigner(Protocol):
    """A JWS signing capability whose private key may live outside the process. ``sign`` returns the raw
    JWS signature over the signing input — for ECDSA the fixed-width ``r||s`` concatenation RFC 7515
    requires, not ASN.1/DER. :class:`~client_attestation_sdk.SigningKeyPair` covers the local-key case;
    :class:`OpenBaoTransitSigner` signs inside a vault."""

    algorithm: str
    key_id: str

    def public_jwk(self) -> dict: ...

    def sign(self, signing_input: bytes) -> bytes: ...


def sign_external(claims: dict, signer: "JwsSigner", typ: str) -> str:
    """Assemble a compact JWS whose signature is produced by an external signer. The header carries the
    signer's ``kid`` (external signers hold issuing keys, referenced by id, never an embedded jwk)."""
    header = {"alg": signer.algorithm, "typ": typ, "kid": signer.key_id}
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    )
    signature = signer.sign(signing_input.encode("ascii"))
    return signing_input + "." + _b64url(signature)


_KEY_TYPE_ALG = {"ecdsa-p256": "ES256", "ecdsa-p384": "ES384", "ecdsa-p521": "ES512"}
_ALG_HASH = {"ES256": "sha2-256", "ES384": "sha2-384", "ES512": "sha2-512"}
_CURVE = {"secp256r1": ("P-256", 32), "secp384r1": ("P-384", 48), "secp521r1": ("P-521", 66)}


class OpenBaoTransitSigner:
    """A :class:`JwsSigner` backed by an OpenBao / HashiCorp Vault transit engine: the attestation is signed
    inside the vault (``POST /v1/transit/sign/<key>`` with ``marshaling_algorithm=jws``, which returns the
    fixed-width ``r||s`` signature RFC 7515 requires) and the private key never leaves it.

    On construction it reads the key metadata (``GET /v1/transit/keys/<key>``) to pin the latest version,
    derive the public JWK, and compute its RFC 7638 thumbprint ``kid`` — so a concurrent rotation cannot
    make the emitted ``kid`` lie. Dependency-free (stdlib ``urllib``); fail-closed (vault errors raise)."""

    _TIMEOUT = 5

    def __init__(self, bao_addr: str, token: str, key_name: str):
        self._base = bao_addr.rstrip("/")
        self._token = token
        self._key_name = key_name
        data = self._data(self._request("GET", "/v1/transit/keys/" + key_name))
        key_type = data.get("type")
        if key_type not in _KEY_TYPE_ALG:
            raise ValueError(f"transit key '{key_name}' has unsupported type for JWS signing: {key_type}")
        self.algorithm = _KEY_TYPE_ALG[key_type]
        self._hash = _ALG_HASH[self.algorithm]
        try:
            self._key_version = int(data["latest_version"])
            public_key_pem = data["keys"][str(self._key_version)]["public_key"]
        except (KeyError, TypeError, ValueError) as exc:
            raise TransportError(f"OpenBao key metadata for '{key_name}' is malformed") from exc
        self._public_jwk = _ec_jwk_from_pem(public_key_pem)
        self.key_id = _thumbprint(self._public_jwk)
        self._public_jwk["kid"] = self.key_id
        self._public_jwk["alg"] = self.algorithm

    def public_jwk(self) -> dict:
        return dict(self._public_jwk)

    def sign(self, signing_input: bytes) -> bytes:
        body = json.dumps({
            "input": base64.b64encode(signing_input).decode("ascii"),
            "marshaling_algorithm": "jws",
            "hash_algorithm": self._hash,
            "key_version": self._key_version,
        })
        data = self._data(self._request("POST", "/v1/transit/sign/" + self._key_name, body))
        signature = data.get("signature")
        if not signature or not isinstance(signature, str):
            raise TransportError("transit sign response carried no signature")
        raw = signature.rsplit(":", 1)[-1]  # envelope: vault:v<n>:<base64url(r||s)>
        try:
            return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except ValueError as exc:
            raise TransportError("transit sign response carried a malformed signature") from exc

    def _request(self, method: str, path: str, body: str = None) -> str:
        headers = {"X-Vault-Token": self._token}
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            resp = _http.request(method, self._base + path, headers=headers,
                                 body=body.encode("utf-8") if body is not None else None,
                                 timeout=self._TIMEOUT)
        except TransportError as exc:
            if exc.status is None:
                raise TransportError(f"OpenBao unreachable at {self._base}: {exc}") from exc
            raise TransportError(f"OpenBao request for {path} failed: {exc}", status=exc.status) from exc
        if resp.status != 200:
            raise TransportError(f"OpenBao returned HTTP {resp.status} for {path}", status=resp.status)
        return resp.text()

    @staticmethod
    def _data(response_json: str) -> dict:
        parsed = _http.parse_json_object(response_json, "OpenBao")
        data = parsed.get("data")
        if not isinstance(data, dict):
            raise TransportError("OpenBao response carried no data")
        return data


def _ec_jwk_from_pem(pem: str) -> dict:
    """Convert a transit ``public_key`` PEM (SubjectPublicKeyInfo) into an EC public JWK."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    key = load_pem_public_key(pem.encode("utf-8"))
    curve = getattr(key, "curve", None)
    if curve is None or curve.name not in _CURVE:
        raise ValueError(f"unsupported transit public key: {getattr(curve, 'name', key)}")
    crv, size = _CURVE[curve.name]
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": crv,
        "x": _b64url(numbers.x.to_bytes(size, "big")),
        "y": _b64url(numbers.y.to_bytes(size, "big")),
    }
