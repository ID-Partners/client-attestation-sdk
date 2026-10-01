"""Signing keys for attestation-based client authentication."""
from __future__ import annotations

import base64
import hashlib
import json

import jwt

_EC_CURVES = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _thumbprint(public_jwk: dict) -> str:
    """RFC 7638 JWK thumbprint (SHA-256) over the required members only."""
    kty = public_jwk["kty"]
    if kty == "EC":
        members = {"crv": public_jwk["crv"], "kty": "EC", "x": public_jwk["x"], "y": public_jwk["y"]}
    elif kty == "RSA":
        members = {"e": public_jwk["e"], "kty": "RSA", "n": public_jwk["n"]}
    else:
        raise ValueError(f"unsupported key type: {kty}")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url(hashlib.sha256(canonical).digest())


class SigningKeyPair:
    """A signing key pair (public + private) with its JWS ``alg`` and RFC 7638 thumbprint ``kid``.

    Used both as the client instance key — which signs PoP / DPoP proofs and is bound into an
    attestation's ``cnf`` — and as a Client Attester's issuing key.
    """

    def __init__(self, private_key, algorithm: str, public_jwk: dict):
        self._private_key = private_key
        self.algorithm = algorithm
        self._public_jwk = dict(public_jwk)
        self.key_id = _thumbprint(self._public_jwk)
        self._public_jwk["kid"] = self.key_id

    @classmethod
    def generate(cls, algorithm: str) -> "SigningKeyPair":
        """Generate a fresh key for ES256/384/512 (EC) or RS256/384/512 / PS256/384/512 (RSA 2048)."""
        alg = jwt.get_algorithm_by_name(algorithm)
        if algorithm in _EC_CURVES:
            from cryptography.hazmat.primitives.asymmetric import ec

            curve = {"ES256": ec.SECP256R1, "ES384": ec.SECP384R1, "ES512": ec.SECP521R1}[algorithm]()
            private_key = ec.generate_private_key(curve)
        elif algorithm.startswith(("RS", "PS")):
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise ValueError(f"unsupported signing algorithm: {algorithm}")
        public_jwk = json.loads(alg.to_jwk(private_key.public_key()))
        return cls(private_key, algorithm, public_jwk)

    @classmethod
    def from_jwk(cls, jwk: dict, algorithm: str) -> "SigningKeyPair":
        """Wrap an existing JWK dict (which must contain the private component ``d``)."""
        if "d" not in jwk:
            raise ValueError("JWK does not contain a private key")
        alg = jwt.get_algorithm_by_name(algorithm)
        private_key = alg.from_jwk(json.dumps(jwk))
        public_jwk = json.loads(alg.to_jwk(private_key.public_key()))
        return cls(private_key, algorithm, public_jwk)

    @property
    def private_key(self):
        return self._private_key

    def public_jwk(self) -> dict:
        """The public-only JWK (including ``kid``) as a dict — an attestation ``cnf.jwk`` or DPoP header."""
        return dict(self._public_jwk)


def sign_compact(claims: dict, key: SigningKeyPair, typ: str, embed_jwk: bool) -> str:
    """Sign claims into a compact JWS with an explicit ``typ`` header, keyed by ``key``.

    When ``embed_jwk`` is set the public key travels in a ``jwk`` header (as DPoP requires); otherwise the
    key's thumbprint ``kid`` is set.
    """
    headers = {"typ": typ}
    if embed_jwk:
        public_jwk = key.public_jwk()
        public_jwk.pop("kid", None)
        headers["jwk"] = public_jwk
    else:
        headers["kid"] = key.key_id
    return jwt.encode(claims, key.private_key, algorithm=key.algorithm, headers=headers)


def require_text(value, field: str) -> str:
    if not value or not str(value).strip():
        raise ValueError(f"{field} is required")
    return value
