"""Builders for the attestation, PoP and DPoP JWTs (draft-ietf-oauth-attestation-based-client-auth)."""
from __future__ import annotations

import base64
import hashlib
import time
import urllib.parse
import uuid

from .keys import SigningKeyPair, require_text, sign_compact
from .signer import JwsSigner, sign_external

ATTESTATION_TYP = "oauth-client-attestation+jwt"
POP_TYP = "oauth-client-attestation-pop+jwt"
DPOP_TYP = "dpop+jwt"


class ClientAttestationBuilder:
    """Builds a Client Attestation JWT — the credential a Client Attester issues to name a client
    (``sub``) and bind its instance key via ``cnf.jwk``. Attester side; sign with the attester's key."""

    def __init__(self, attester_key: "SigningKeyPair | JwsSigner", issuer: str):
        self._attester_key = attester_key
        self._issuer = require_text(issuer, "issuer")
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
        self._cnf_jwk = public_instance_jwk
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
        self._operator = {"sub": require_text(sub, "operator sub")}
        if issuer:
            self._operator["iss"] = issuer
        return self

    def build(self) -> str:
        sub = require_text(self._client_id, "client_id")
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
            return sign_compact(claims, self._attester_key, ATTESTATION_TYP, embed_jwk=False)
        return sign_external(claims, self._attester_key, ATTESTATION_TYP)

    def _resolve_expiry(self, iat: int) -> int:
        if self._expires_at is not None:
            return self._expires_at
        if self._ttl is not None:
            return iat + self._ttl
        raise ValueError("expiry is required: call expires_at(...) or expires_in(...)")


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
        return sign_compact(claims, self._instance_key, POP_TYP, embed_jwk=False)


_DEFAULT_PORTS = {"http": 80, "https": 443}


def url_origin(url: str) -> str:
    """``scheme://host[:port]`` with scheme and host lower-cased and the default port (80 for http,
    443 for https) dropped. No userinfo."""
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        host = f"{host}:{port}"
    return f"{scheme}://{host}"


def normalize_htu(url: str) -> str:
    """The RFC 9449 ``htu`` form of a request URL: :func:`url_origin` plus the path, with no query and
    no fragment. A bare origin gets no trailing ``/`` (``https://as.example`` stays as it is)."""
    return url_origin(url) + urllib.parse.urlsplit(url).path


def access_token_hash(access_token: str) -> str:
    """RFC 9449 section 4.2 ``ath``: base64url (unpadded) of SHA-256 over the ASCII access token."""
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class DpopProofBuilder:
    """Builds a DPoP proof JWT (RFC 9449) for attestation combined mode
    (PoP method ``dpop_combined``): the embedded ``jwk`` header MUST be the attestation's ``cnf`` key.

    ``htm`` is upper-cased and ``htu`` is normalised (query and fragment stripped) at build time. Call
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
        self._ath = access_token_hash(access_token) if access_token else None
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
            "htu": normalize_htu(self._htu),
            "jti": self._jwt_id or str(uuid.uuid4()),
            "iat": self._issued_at if self._issued_at is not None else int(time.time()),
        }
        if self._nonce:
            claims["nonce"] = self._nonce
        if self._ath:
            claims["ath"] = self._ath
        return sign_compact(claims, self._instance_key, DPOP_TYP, embed_jwk=True)
