"""Client for the Client Attestation **issuance** endpoint (``POST /federation/attestation``).

The inverse of :class:`~client_attestation_sdk.builders.ClientAttestationBuilder`: instead of building an
attestation locally with an attester key, a workload proves its **SPIFFE identity** (a JWT-SVID) and the
Authorization Server (PingFederate) validates it and **mints** a Client Attestation bound to the workload's
own instance key. Bootstrapping a client credential from infra identity — no pre-shared secret.

    client = AttestationIssuanceClient(
        endpoint="https://pf.example/federation/attestation",
        client_id="https://payment-agent.example",
        attester_issuer="https://attester.example",
        svid_source=SpireWorkloadApiSvidSource(),           # default: real SPIRE
    )
    issued = client.bootstrap(authorization_details=[{"type": "sales_agent", "sales_regions": ["EMEA"]}])
    #   issued.attestation  -> present as the OAuth-Client-Attestation header
    #   issued.pop(aud)      -> a fresh PoP for the OAuth-Client-Attestation-PoP header, signed by the
    #                           same instance key the AS bound into the attestation's cnf
"""
from __future__ import annotations

import json
import time
import uuid

from . import _http
from .builders import DpopProofBuilder, PopBuilder
from .errors import ClientAttestationError
from .keys import SigningKeyPair, sign_compact
from .svid_source import SvidSource

# The instance-key proof presented at the issuance endpoint (matches the server's
# InstanceKeyProofValidator.TYP) — proves possession of instance_key, over the attester issuer as aud.
INSTANCE_PROOF_TYP = "oauth-attestation-instance-proof+jwt"


class IssuanceError(ClientAttestationError):
    """The issuance endpoint rejected the request (non-2xx). Carries the OAuth-style error body. Transport
    failures (network, timeout, redirect, oversized or malformed response) raise
    :class:`~client_attestation_sdk.errors.TransportError` instead."""

    def __init__(self, status: int, body: str):
        super().__init__(f"attestation issuance failed: HTTP {status}: {body}", status=status, body=body)


class IssuedAttestation:
    """A minted Client Attestation plus the instance key it is bound to."""

    def __init__(self, attestation: str, expires_in, instance_key: SigningKeyPair):
        self.attestation = attestation
        self.expires_in = expires_in
        self.instance_key = instance_key

    def pop(self, audience: str, client_id: str = None, challenge: str = None) -> str:
        """A fresh Client Attestation PoP for the token endpoint, signed by the bound instance key."""
        builder = PopBuilder(self.instance_key).audience(audience)
        if client_id:
            builder.client_id(client_id)
        if challenge:
            builder.challenge(challenge)
        return builder.build()

    def dpop(self, method: str, uri: str, challenge: str = None) -> str:
        """A fresh RFC 9449 DPoP proof for the token endpoint (attestation combined mode), signed by
        the same bound instance key — for a token endpoint that wants `dpop_combined` instead of a
        Client Attestation PoP JWT. Any challenge rides as the DPoP `nonce`."""
        builder = DpopProofBuilder(self.instance_key).method(method).uri(uri)
        if challenge:
            builder.nonce(challenge)
        return builder.build()


class AttestationIssuanceClient:
    """Bootstraps a Client Attestation for a workload from its SPIFFE JWT-SVID."""

    def __init__(self, endpoint: str, client_id: str, attester_issuer: str, svid_source: SvidSource,
                 *, instance_key: SigningKeyPair = None, algorithm: str = "ES256"):
        self.endpoint = endpoint.rstrip("/")
        self.client_id = client_id
        self.attester_issuer = attester_issuer      # the SVID audience AND the instance-proof aud
        self._svid_source = svid_source
        # The workload's own key: signs the instance proof, and the AS binds it into the attestation's cnf.
        self.instance_key = instance_key or SigningKeyPair.generate(algorithm)

    def bootstrap(self, authorization_details=None, challenge: str = None) -> IssuedAttestation:
        """Fetch the SVID, prove possession of the instance key, and exchange them for a minted attestation."""
        svid = self._svid_source.fetch(self.attester_issuer)

        proof_claims = {"aud": self.attester_issuer, "jti": str(uuid.uuid4()), "iat": int(time.time())}
        if challenge:
            proof_claims["challenge"] = challenge
        proof = sign_compact(proof_claims, self.instance_key, INSTANCE_PROOF_TYP, embed_jwk=False)

        body = {
            "client_id": self.client_id,
            "instance_key": self.instance_key.public_jwk(),
            "svid": svid,
            "proof": proof,
        }
        if authorization_details:
            body["authorization_details"] = authorization_details

        result = _http.request(
            "POST", self.endpoint, body=json.dumps(body).encode("utf-8"), timeout=20,
            headers={"Content-Type": "application/json", "Accept": "application/json"})
        if not result.ok:
            raise IssuanceError(result.status, result.text())
        response = _http.json_ok(result, "attestation issuance endpoint")
        attestation = _http.require(response, "attestation", "attestation issuance response")
        return IssuedAttestation(attestation, response.get("expires_in"), self.instance_key)
