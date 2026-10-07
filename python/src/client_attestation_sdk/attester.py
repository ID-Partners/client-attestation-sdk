"""Attester profiles: the part of the flow that differs from one attester to the next.

The draft (draft-ietf-oauth-attestation-based-client-auth) says what a Client Attestation, its PoP and the
challenge endpoint look like, and how they are presented at the token endpoint. It does not say how a
workload *gets* an attestation from its attester. That part - where the attester's endpoints are listed,
what the mint request looks like, how the instance key is proven, and what comes back - is an
:class:`AttesterProfile`.

:class:`ClientAttestation` and :class:`AttestationIssuanceClient` use :class:`PingFederateProfile` unless
told otherwise, which is exactly the behaviour of earlier releases. See docs/attester-profiles.md.

    # an attester that publishes no discovery document: give the endpoints directly
    ca = ClientAttestation(metadata=AttesterMetadata(
        evidence_audience="https://attester.example",
        attestation_endpoint="https://attester.example/mint",
        token_endpoint="https://as.example/token"))

    # an attester with its own mint protocol: implement the two methods
    class MyAttester(AttesterProfile):
        def discover(self, transport, attester_url): ...
        def mint(self, transport, metadata, request): ...

    ca = ClientAttestation("https://attester.example", profile=MyAttester())
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from .errors import TransportError
from .keys import SigningKeyPair, _sign_compact

__all__ = [
    "AttesterMetadata",
    "AttesterProfile",
    "AttesterTransport",
    "MintRequest",
    "MintResult",
    "PingFederateProfile",
]


@dataclass(frozen=True)
class AttesterMetadata:
    """Where the attester lives and what it expects.

    Attributes:
        evidence_audience: the audience the workload's platform identity (SVID) is requested for, and the
            ``aud`` of the instance proof. Required.
        attestation_endpoint: where the mint request goes.
        token_endpoint: the authorization server's token endpoint. A profile fills in its own fallback
            when the attester does not name one.
        challenge_endpoint: the draft's challenge endpoint, if the attester issues challenges.
        pop_audience: the ``aud`` of the Client Attestation PoP (the AS issuer). Falls back to the token
            endpoint URL.
        document: the raw discovery document, when there was one; returned by
            :meth:`ClientAttestation.discovery`.
    """

    evidence_audience: Optional[str] = None
    attestation_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    challenge_endpoint: Optional[str] = None
    pop_audience: Optional[str] = None
    document: Optional[dict] = field(default=None, compare=False)

    def as_document(self) -> dict:
        """The raw discovery document, or (for static metadata) the fields that are set."""
        if self.document is not None:
            return self.document
        names = ("evidence_audience", "attestation_endpoint", "challenge_endpoint", "token_endpoint",
                 "pop_audience")
        return {name: getattr(self, name) for name in names if getattr(self, name)}


@dataclass
class MintRequest:
    """Everything a profile needs to mint one attestation.

    Attributes:
        instance_key: the fresh key the attestation will be bound to (its ``cnf``).
        evidence: the workload's platform identity token (a JWT-SVID or equivalent).
        challenge: the attester-issued challenge, or None.
        client_id: set by :class:`AttestationIssuanceClient`, which names its client; None in the
            evidence-first one-call flow, where the attester maps the identity to a client.
        authorization_details: optional RFC 9396 access request.
        operator: optional operator object (who answers for this workload).
        asserted_context: optional unverified discriminator for an attester-side resolver.

    **Experimental** (see docs/api.md): part of the attester-profile interface, new in 0.4.0.
    """

    instance_key: SigningKeyPair
    evidence: str
    challenge: Optional[str] = None
    client_id: Optional[str] = None
    authorization_details: Optional[list] = None
    operator: Optional[dict] = None
    asserted_context: Optional[dict] = None

    def sign(self, claims: dict, typ: str) -> str:
        """Sign ``claims`` as a compact JWS with the instance key, under header ``typ`` (no ``jwk``)."""
        return _sign_compact(claims, self.instance_key, typ, embed_jwk=False)

    def instance_proof(self, typ: str, audience: str) -> str:
        """A proof of possession of the instance key: ``{aud, jti, iat[, challenge]}`` signed with it."""
        claims = {"aud": audience, "jti": str(uuid.uuid4()), "iat": int(time.time())}
        if self.challenge:
            claims["challenge"] = self.challenge
        return self.sign(claims, typ)


@dataclass(frozen=True)
class MintResult:
    """What the attester returned: the attestation, and its lifetime in seconds if it said.

    **Experimental** (see docs/api.md): part of the attester-profile interface, new in 0.4.0.
    """

    attestation: str
    expires_in: Any = None


class AttesterTransport(Protocol):
    """How a profile talks to the attester. The client supplies it, so every call shares the client's
    timeout, redirect and size limits, https rule, logging (``http.failed``) and trace.

    **Experimental** (see docs/api.md): part of the attester-profile interface, new in 0.4.0.
    """

    def request_json(self, step: str, method: str, url: str, body: Optional[dict] = None) -> dict:
        """Send ``body`` (as JSON, if given) and return the JSON object response. ``step`` names the call
        in logs and traces (``discover``, ``mint``). Raises on a non-2xx status or a body that is not a
        JSON object."""
        ...  # pragma: no cover


class AttesterProfile:
    """The attester-specific part of the flow. Subclass it (or match its shape) and pass it as
    ``profile=``. Both methods may make calls through ``transport``.

    **Experimental** (see docs/api.md): new in 0.4.0 and fitted to one real attester so far; a method added
    here would break custom profiles.
    """

    def discover(self, transport: AttesterTransport, attester_url: Optional[str]) -> AttesterMetadata:
        """Find the attester's endpoints. Called once per client; the result is cached. Not called when the
        caller passes static ``metadata``."""
        raise NotImplementedError

    def mint(self, transport: AttesterTransport, metadata: AttesterMetadata,
             request: MintRequest) -> MintResult:
        """Exchange the evidence and a proof of the instance key for an attestation."""
        raise NotImplementedError


class PingFederateProfile(AttesterProfile):
    """The attester this SDK was built against (PingFederate), and the default.

    - Discovery: ``GET {attester_url}/.well-known/client-attester``, a JSON object with
      ``evidence_audience``, ``attestation_endpoint``, ``challenge_endpoint``, ``token_endpoint`` and
      ``pop_audience``. With no ``token_endpoint``, ``{attester_url}/as/token.oauth2``.
    - Mint: ``POST attestation_endpoint`` with JSON ``{[client_id,] instance_key, svid, proof
      [, authorization_details][, asserted_context][, operator]}``, where ``proof`` is
      ``{aud: evidence_audience, jti, iat[, challenge]}`` signed by the instance key with ``typ``
      ``oauth-attestation-instance-proof+jwt``. The response is ``{"attestation": ..., "expires_in": ...}``.
    """

    WELL_KNOWN_PATH = "/.well-known/client-attester"
    INSTANCE_PROOF_TYP = "oauth-attestation-instance-proof+jwt"
    DEFAULT_TOKEN_PATH = "/as/token.oauth2"

    def discover(self, transport: AttesterTransport, attester_url: Optional[str]) -> AttesterMetadata:
        if not attester_url:
            raise ValueError("attester_url is required for discovery")
        doc = transport.request_json("discover", "GET", attester_url + self.WELL_KNOWN_PATH)
        return AttesterMetadata(
            evidence_audience=doc.get("evidence_audience"),
            attestation_endpoint=doc.get("attestation_endpoint"),
            # token_endpoint is advertised by current attesters; fall back to the standard PF path so an
            # older discovery document still works from the host alone.
            token_endpoint=doc.get("token_endpoint") or attester_url + self.DEFAULT_TOKEN_PATH,
            challenge_endpoint=doc.get("challenge_endpoint"),
            pop_audience=doc.get("pop_audience"),
            document=doc,
        )

    def mint(self, transport: AttesterTransport, metadata: AttesterMetadata,
             request: MintRequest) -> MintResult:
        if not metadata.attestation_endpoint:
            raise TransportError("attester discovery document has no attestation_endpoint")
        proof = request.instance_proof(self.INSTANCE_PROOF_TYP, metadata.evidence_audience)
        body = {}
        if request.client_id:
            body["client_id"] = request.client_id
        body.update({"instance_key": request.instance_key.public_jwk(), "svid": request.evidence,
                     "proof": proof})
        if request.authorization_details:
            body["authorization_details"] = request.authorization_details
        if request.asserted_context:
            body["asserted_context"] = request.asserted_context
        if request.operator:
            # The client's OPERATOR - who answers for this workload - asked for at mint time so the
            # ATTESTER is what states it, rather than the client asserting it about itself at the token
            # endpoint. An attester that does not know this key ignores it.
            body["operator"] = request.operator
        response = transport.request_json("mint", "POST", metadata.attestation_endpoint, body)
        attestation = response.get("attestation")
        if not attestation or not isinstance(attestation, str):
            raise TransportError("attester response contained no attestation", body=json.dumps(response))
        return MintResult(attestation, response.get("expires_in"))
