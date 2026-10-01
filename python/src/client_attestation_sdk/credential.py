"""Assembles the request headers a client sends at the token endpoint."""
from __future__ import annotations

from .builders import DpopProofBuilder, PopBuilder
from .keys import SigningKeyPair, require_text

ATTESTATION_HEADER = "OAuth-Client-Attestation"
POP_HEADER = "OAuth-Client-Attestation-PoP"
DPOP_HEADER = "DPoP"


class ClientAttestationCredential:
    """The Attester-issued attestation JWT plus the instance key it is bound to. Produces the token-request
    headers — PoP-JWT mode or DPoP combined mode — minting a fresh proof each call."""

    def __init__(self, attestation_jwt: str, instance_key: SigningKeyPair):
        self._attestation_jwt = require_text(attestation_jwt, "attestation_jwt")
        self._instance_key = instance_key

    def pop_headers(self, client_id: str, audience: str, challenge: str = None) -> dict:
        pop = (
            PopBuilder(self._instance_key)
            .client_id(client_id)
            .audience(audience)
            .challenge(challenge)
            .build()
        )
        return {ATTESTATION_HEADER: self._attestation_jwt, POP_HEADER: pop}

    def dpop_headers(self, method: str, uri: str, challenge: str = None) -> dict:
        dpop = (
            DpopProofBuilder(self._instance_key)
            .method(method)
            .uri(uri)
            .nonce(challenge)
            .build()
        )
        return {ATTESTATION_HEADER: self._attestation_jwt, DPOP_HEADER: dpop}
