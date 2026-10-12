"""Builders for the attestation, PoP and DPoP JWTs (draft-ietf-oauth-attestation-based-client-auth)."""
from __future__ import annotations

import base64
import hashlib
import time
import uuid

from .keys import SigningKeyPair, _require_text, _sign_compact
from .signer import JwsSigner, _sign_external

ATTESTATION_TYP = "oauth-client-attestation+jwt"
POP_TYP = "oauth-client-attestation-pop+jwt"
DPOP_TYP = "dpop+jwt"


class ClientAttestationBuilder:
    """Builds a Client Attestation JWT — the credential a Client Attester issues to name a client
    (``sub``) and bind its instance key via ``cnf.jwk``. Attester side; sign with the attester's key."""

    def __init__(self, attester_key: "SigningKeyPair | JwsSigner", issuer: str):
        self._attester_key = attester_key
        self._issuer = _require_text(issuer, "issuer")
        self._client_id = None
        self._cnf_jwk = None
        self._issued_at = None
        self._expires_at = None
        self._ttl = None
        self._authorization_details = None
        self._workload = None
        self._operator = None

    def client_id(self, client_id: str) -> "ClientAttestationBuilder":
        self._client_id = client_id
        return self

    def confirmation_jwk(self, public_instance_jwk: dict) -> "ClientAttestationBuilder":
        """Bind a public instance JWK as ``cnf.jwk``: an EC (``crv`` P-256, P-384 or P-521, ``x``, ``y``) or
        RSA (``n``, ``e``) public key. Raises ``ValueError`` for one carrying private or secret members
        (``d``, ``p``, ``q``, ``dp``, ``dq``, ``qi``, ``oth``, ``k``) or another ``kty``. Only those members and
        an optional ``kid`` are copied into the attestation."""
        self._cnf_jwk = _confirmation_jwk(public_instance_jwk)
        return self

    def confirmation_key(self, instance_key: SigningKeyPair) -> "ClientAttestationBuilder":
        return self.confirmation_jwk(instance_key.public_jwk())

    def issued_at(self, epoch_seconds: int) -> "ClientAttestationBuilder":
        self._issued_at = epoch_seconds
        return self

    def expires_at(self, epoch_seconds: int) -> "ClientAttestationBuilder":
        self._expires_at = epoch_seconds
        return self

    def expires_in(self, seconds: int) -> "ClientAttestationBuilder":
        self._ttl = seconds
        return self

    def authorization_details(self, details: list) -> "ClientAttestationBuilder":
        self._authorization_details = details
        return self

    def workload(self, workload: dict) -> "ClientAttestationBuilder":
        self._workload = workload
        return self

    def operator(self, sub: str, issuer: str = None) -> "ClientAttestationBuilder":
        """Name the client's OPERATOR — the human or organisation accountable for running this
        client, as distinct from the client itself (``sub``) and from the principal it acts for.

        Deliberately a top-level claim rather than a member of ``workload``: ``workload``
        describes the running software, whereas the operator is an accountability statement
        about who answers for it. It is per-client and static, so it does not affect how far an
        attestation can be cached.

        The shape mirrors RFC 8693 ``may_act`` (``{"sub": ..., "iss": ...}``) on purpose. An AS
        that wants the operator to become the party authorised to act for the subject can lift
        this straight into ``may_act``; ``iss`` names the OP the operator's ``sub`` is
        meaningful in, so the identifier is not ambiguous across directories.

        This is an ASSERTION by the attester, not proof the operator authorised anything. A
        relying AS should treat it as it treats the rest of the attestation: trusted exactly as
        far as the attester is."""
        self._operator = {"sub": _require_text(sub, "operator sub")}
        if issuer:
            self._operator["iss"] = issuer
        return self

    def build(self) -> str:
        sub = _require_text(self._client_id, "client_id")
        if self._cnf_jwk is None:
            raise ValueError("confirmation key (cnf.jwk) is required")
        iat = self._issued_at if self._issued_at is not None else int(time.time())
        exp = self._resolve_expiry(iat)
        claims = {"iss": self._issuer, "sub": sub, "iat": iat, "exp": exp, "cnf": {"jwk": self._cnf_jwk}}
        if self._authorization_details:
            claims["authorization_details"] = self._authorization_details
        if self._workload:
            claims["workload"] = self._workload
        if self._operator:
            claims["operator"] = self._operator
        if isinstance(self._attester_key, SigningKeyPair):
            return _sign_compact(claims, self._attester_key, ATTESTATION_TYP, embed_jwk=False)
        return _sign_external(claims, self._attester_key, ATTESTATION_TYP)

    def _resolve_expiry(self, iat: int) -> int:
        if self._expires_at is not None:
            exp = self._expires_at
        elif self._ttl is not None:
            exp = iat + self._ttl
        else:
            raise ValueError("expiry is required: call expires_at(...) or expires_in(...)")
        if exp <= iat:
            raise ValueError(f"attestation exp ({exp}) must be after iat ({iat})")
        return exp


# JWK members that carry private or secret key material (RFC 7518 section 6).
_PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
# The public members a cnf.jwk of each key type must carry.
_CONFIRMATION_JWK_MEMBERS = {"EC": ("crv", "x", "y"), "RSA": ("n", "e")}


def _confirmation_jwk(jwk: dict) -> dict:
    """The public key to bind as ``cnf.jwk``: ``kty``, the key type's public members and an optional ``kid``,
    in the order ``jwk`` has them. Refuses private or secret members, another ``kty`` or curve, or a missing
    member, so a private key is never signed into an attestation."""
    if not isinstance(jwk, dict):
        raise ValueError("cnf.jwk must be a JWK object")
    for member in _PRIVATE_JWK_MEMBERS:
        if member in jwk:
            raise ValueError(f"cnf.jwk must be a public key: it carries the private member '{member}'")
    kty = jwk.get("kty")
    required = _CONFIRMATION_JWK_MEMBERS.get(kty) if isinstance(kty, str) else None
    if required is None:
        raise ValueError(f"cnf.jwk must be an EC or RSA public key, not kty {kty!r}")
    for member in required:
        if not isinstance(jwk.get(member), str) or not jwk[member]:
            raise ValueError(f"cnf.jwk (kty {kty}) is missing '{member}'")
    if kty == "EC" and jwk["crv"] not in ("P-256", "P-384", "P-521"):
        raise ValueError(f"cnf.jwk curve must be P-256, P-384 or P-521, not {jwk['crv']!r}")
    if "kid" in jwk and (not isinstance(jwk["kid"], str) or not jwk["kid"]):
        raise ValueError("cnf.jwk kid must be a non-empty string")
    return {k: v for k, v in jwk.items() if k in ("kty", "kid", *required)}


class PopBuilder:
    """Builds a Client Attestation PoP JWT proving possession of the instance key. Client side of
    ``attest_jwt_client_auth``; mint a fresh one per token request."""

    def __init__(self, instance_key: SigningKeyPair):
        self._instance_key = instance_key
        self._client_id = None
        self._audience = None
        self._challenge = None
        self._jwt_id = None
        self._issued_at = None

    def client_id(self, client_id: str) -> "PopBuilder":
        self._client_id = client_id
        return self

    def audience(self, audience: str) -> "PopBuilder":
        self._audience = audience
        return self

    def challenge(self, challenge) -> "PopBuilder":
        self._challenge = challenge
        return self

    def jwt_id(self, jwt_id: str) -> "PopBuilder":
        self._jwt_id = jwt_id
        return self

    def issued_at(self, epoch_seconds: int) -> "PopBuilder":
        self._issued_at = epoch_seconds
        return self

    def build(self) -> str:
        if not self._audience:
            raise ValueError("audience (aud) is required")
        claims = {
            "aud": self._audience,
            "jti": self._jwt_id or str(uuid.uuid4()),
            "iat": self._issued_at if self._issued_at is not None else int(time.time()),
        }
        if self._client_id:
            claims["iss"] = self._client_id
        if self._challenge:
            claims["challenge"] = self._challenge
        return _sign_compact(claims, self._instance_key, POP_TYP, embed_jwk=False)


_DEFAULT_PORTS = {"http": "80", "https": "443"}

_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
_IPV6_CHARS = frozenset("0123456789abcdefABCDEF:.")


def _check_htu(url: str) -> None:
    """Refuse a URL whose part before any query or fragment (the part that becomes ``htu``) contains a
    backslash, ASCII whitespace or a control character. Parsers disagree on where such a URL goes:
    ``urllib.parse`` reads ``https://evil.example\\@as.example/t`` as a request to as.example, while
    ``requests`` sends it to evil.example."""
    head = url.split("?", 1)[0].split("#", 1)[0]
    if any(c <= " " or c == "\x7f" or c == "\\" for c in head):
        raise ValueError("uri (htu) must not contain a backslash, whitespace or control character")


def _htu_parts(url: str) -> "tuple[str, str]":
    """``(origin, path)`` of a request URL by the rule in vectors/README.md, which every port applies
    alike: an absolute http(s) URL with a host; scheme and host lower-cased (ASCII only, an IPv6 literal
    as written); no userinfo; the port as a plain number and dropped when it is the scheme's default; the
    path as written with non-ASCII characters percent-encoded (UTF-8); no query or fragment. Anything else
    raises ``ValueError``."""
    _check_htu(url)
    bare = url.split("?", 1)[0].split("#", 1)[0]
    scheme, sep, rest = bare.partition("://")
    scheme = scheme.lower() if scheme.isascii() else ""
    if not sep or scheme not in _DEFAULT_PORTS:
        raise ValueError("uri (htu) must be an absolute http or https URL with a host")
    authority, slash, path = rest.partition("/")
    path = slash + path
    hostport = authority.rpartition("@")[2]
    port = None
    if hostport.startswith("["):
        literal, close, after = hostport[1:].partition("]")
        if not close or ":" not in literal or not set(literal) <= _IPV6_CHARS or after[:1] not in ("", ":"):
            raise ValueError("uri (htu) has an invalid host")
        host = "[" + literal.lower() + "]"
        if after:
            port = after[1:]
    else:
        host, colon, port_text = hostport.partition(":")
        if not host:
            raise ValueError("uri (htu) must be an absolute http or https URL with a host")
        if not set(host) <= _HOST_CHARS:
            raise ValueError("uri (htu) has an invalid host")
        host = host.lower()
        if colon:
            port = port_text
    if port:
        digits = port.lstrip("0")
        if not (port.isascii() and port.isdigit()) or len(digits) > 5 or int(digits or "0") > 65535:
            raise ValueError("uri (htu) has an invalid port")
        if str(int(digits or "0")) != _DEFAULT_PORTS[scheme]:
            host += ":" + str(int(digits or "0"))
    return scheme + "://" + host, _encode_path(path)


def _encode_path(path: str) -> str:
    """``path`` with every non-ASCII character percent-encoded as UTF-8 (upper-case hex) and every ASCII
    character kept as written, ``%XX`` escapes, a lone ``%`` and characters outside RFC 3986 ``pchar``
    included: those are what the HTTP client sends, and a server compares ``htu`` after RFC 3986 section
    6.2.2 normalisation, which decodes only unreserved characters. (:func:`_check_htu` has already refused
    controls, whitespace and backslash.) A lone surrogate is refused."""
    try:
        return "".join(c if c.isascii() else "".join(f"%{b:02X}" for b in c.encode("utf-8")) for c in path)
    except UnicodeEncodeError:   # a lone surrogate
        raise ValueError("uri (htu) has an invalid path") from None


def _url_origin(url: str) -> str:
    """The origin part of :func:`_htu_parts` (``scheme://host[:port]``), the key a DPoP nonce is
    remembered under; a URL that rule refuses is its own key."""
    try:
        return _htu_parts(url)[0]
    except ValueError:
        return url


def _normalize_htu(url: str) -> str:
    """The RFC 9449 ``htu`` form of a request URL: origin plus path by :func:`_htu_parts`, with no query
    and no fragment. A bare origin gets no trailing ``/`` (``https://as.example`` stays as it is). A URL
    that rule refuses raises ``ValueError``."""
    origin, path = _htu_parts(url)
    return origin + path


def _access_token_hash(access_token: str) -> str:
    """RFC 9449 section 4.2 ``ath``: base64url (unpadded) of SHA-256 over the ASCII access token."""
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class DpopProofBuilder:
    """Builds a DPoP proof JWT (RFC 9449) for attestation combined mode
    (PoP method ``dpop_combined``): the embedded ``jwk`` header MUST be the attestation's ``cnf`` key.

    ``htm`` is upper-cased and ``htu`` is normalised at build time by the rule in vectors/README.md
    (lower-case scheme and host, no userinfo, query, fragment or default port); a URL that is not an
    absolute http(s) URL with a valid ASCII host, port and path, or that has a backslash, ASCII
    whitespace or a control character before its query or fragment, raises ``ValueError``. Call
    :meth:`access_token` when the proof accompanies a DPoP-bound token at a resource, so it carries
    ``ath``."""

    def __init__(self, instance_key: SigningKeyPair):
        self._instance_key = instance_key
        self._htm = "POST"
        self._htu = None
        self._nonce = None
        self._jwt_id = None
        self._issued_at = None
        self._ath = None

    def method(self, htm: str) -> "DpopProofBuilder":
        if htm:
            self._htm = htm.upper()
        return self

    def access_token(self, access_token: str) -> "DpopProofBuilder":
        """Bind the proof to an access token: sets ``ath`` = base64url(SHA-256(token))."""
        self._ath = _access_token_hash(access_token) if access_token else None
        return self

    def uri(self, htu: str) -> "DpopProofBuilder":
        self._htu = htu
        return self

    def nonce(self, nonce) -> "DpopProofBuilder":
        self._nonce = nonce
        return self

    def jwt_id(self, jwt_id: str) -> "DpopProofBuilder":
        self._jwt_id = jwt_id
        return self

    def issued_at(self, epoch_seconds: int) -> "DpopProofBuilder":
        self._issued_at = epoch_seconds
        return self

    def build(self) -> str:
        if not self._htu:
            raise ValueError("uri (htu) is required")
        claims = {
            "htm": self._htm,
            "htu": _normalize_htu(self._htu),
            "jti": self._jwt_id or str(uuid.uuid4()),
            "iat": self._issued_at if self._issued_at is not None else int(time.time()),
        }
        if self._nonce:
            claims["nonce"] = self._nonce
        if self._ath:
            claims["ath"] = self._ath
        return _sign_compact(claims, self._instance_key, DPOP_TYP, embed_jwk=True)
