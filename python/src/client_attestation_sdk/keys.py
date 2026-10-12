"""Signing keys for attestation-based client authentication."""
from __future__ import annotations

import base64
import hashlib
import json
import re

import jwt

_EC_CURVES = {"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}
_RSA_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
# The JWS algorithms the SDK signs with, locally or through an external signer.
_SIGNING_ALGORITHMS = (*_EC_CURVES, *_RSA_ALGORITHMS)
_MIN_RSA_BITS = 2048
# JWK crv -> (cryptography curve name, coordinate width in bytes).
_EC_SIZES = {"P-256": ("secp256r1", 32), "P-384": ("secp384r1", 48), "P-521": ("secp521r1", 66)}
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value, member: str) -> bytes:
    """Strict base64url (no padding, no other characters); the error names the member, never its value."""
    if not isinstance(value, str) or not _BASE64URL.fullmatch(value):
        raise ValueError(f"JWK member '{member}' is missing or not base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _check_algorithm(algorithm: str) -> None:
    if algorithm not in _SIGNING_ALGORITHMS:
        raise ValueError(f"unsupported signing algorithm: {algorithm}")


def _canonical_private_jwk(jwk: dict, algorithm: str) -> dict:
    """The key members of a private JWK, checked against ``algorithm`` and re-encoded canonically: EC
    coordinates and ``d`` at the curve's full width, RSA ``n`` and ``e`` in their minimal octets
    (RFC 7518 section 6). Every other member (``kid``, ``alg``, ``use``, ...) is dropped."""
    kty = jwk.get("kty")
    if algorithm in _EC_CURVES:
        if kty != "EC":
            raise ValueError(f"{algorithm} needs an EC key, not kty {kty!r}")
        crv = _EC_CURVES[algorithm]
        if jwk.get("crv") != crv:
            raise ValueError(f"{algorithm} needs an EC key on {crv}")
        size = _EC_SIZES[crv][1]
        out = {"kty": "EC", "crv": crv}
        for member in ("x", "y", "d"):
            value = _b64url_decode(jwk.get(member), member).lstrip(b"\0")
            if len(value) > size:
                raise ValueError(f"JWK member '{member}' is too long for {crv}")
            out[member] = _b64url(value.rjust(size, b"\0"))
        return out
    if kty != "RSA":
        raise ValueError(f"{algorithm} needs an RSA key, not kty {kty!r}")
    out = {m: jwk[m] for m in ("kty", "n", "e", "d", "p", "q", "dp", "dq", "qi", "oth") if m in jwk}
    for member in ("n", "e"):
        out[member] = _b64url(_b64url_decode(jwk.get(member), member).lstrip(b"\0") or b"\0")
    return out


def _public_jwk(public_key) -> dict:
    """The canonical public JWK of a key: EC ``kty, crv, x, y`` with full-width coordinates, RSA
    ``kty, n, e`` in minimal octets. The same key gives the same JWK, and kid, in every port."""
    from cryptography.hazmat.primitives.asymmetric import ec

    numbers = public_key.public_numbers()
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        crv = next(c for c, (name, _) in _EC_SIZES.items() if name == public_key.curve.name)
        size = _EC_SIZES[crv][1]
        return {"kty": "EC", "crv": crv, "x": _b64url(numbers.x.to_bytes(size, "big")),
                "y": _b64url(numbers.y.to_bytes(size, "big"))}
    return {"kty": "RSA", "n": _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))}


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
        if algorithm in _EC_CURVES:
            from cryptography.hazmat.primitives.asymmetric import ec

            curve = {"ES256": ec.SECP256R1, "ES384": ec.SECP384R1, "ES512": ec.SECP521R1}[algorithm]()
            private_key = ec.generate_private_key(curve)
        elif algorithm in _RSA_ALGORITHMS:
            from cryptography.hazmat.primitives.asymmetric import rsa

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise ValueError(f"unsupported signing algorithm: {algorithm}")
        return cls(private_key, algorithm, _public_jwk(private_key.public_key()))

    @classmethod
    def from_jwk(cls, jwk: dict, algorithm: str) -> "SigningKeyPair":
        """Wrap an existing JWK dict (which must contain the private component ``d``).

        The key must suit ``algorithm``: an EC key on its curve for ES256/384/512 (P-256/384/521), an RSA
        key of at least 2048 bits for RS256/384/512 and PS256/384/512, and its public members must belong
        to its private key. Only the key material is kept: the published JWK is re-encoded canonically and
        its ``kid`` is the RFC 7638 thumbprint, whatever ``kid`` or other members the input had."""
        if "d" not in jwk:
            raise ValueError("JWK does not contain a private key")
        _check_algorithm(algorithm)
        canonical = _canonical_private_jwk(jwk, algorithm)
        try:
            private_key = jwt.get_algorithm_by_name(algorithm).from_jwk(json.dumps(canonical))
        except ValueError as exc:  # cryptography refuses a public half that is not the private key's
            raise ValueError("the JWK's public key does not match its private key") from exc
        if algorithm in _RSA_ALGORITHMS and private_key.key_size < _MIN_RSA_BITS:
            raise ValueError(f"RSA keys must be at least {_MIN_RSA_BITS} bits")
        return cls(private_key, algorithm, _public_jwk(private_key.public_key()))

    @property
    def private_key(self):
        return self._private_key

    def public_jwk(self) -> dict:
        """The public-only JWK (including ``kid``) as a dict — an attestation ``cnf.jwk`` or DPoP header."""
        return dict(self._public_jwk)


def _sign_compact(claims: dict, key: SigningKeyPair, typ: str, embed_jwk: bool) -> str:
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


def _require_text(value, field: str) -> str:
    if not value or not str(value).strip():
        raise ValueError(f"{field} is required")
    return value
