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

from . import _http
from .attester import AttesterMetadata, AttesterProfile, MintRequest, PingFederateProfile
from .builders import DpopProofBuilder, PopBuilder
from .errors import ClientAttestationError
from .keys import SigningKeyPair
from .svid_source import SvidSource

# The instance-key proof presented at the issuance endpoint by the PingFederate profile (matches the
# server's InstanceKeyProofValidator.TYP) — proves possession of instance_key, over the attester issuer as aud.
INSTANCE_PROOF_TYP = PingFederateProfile.INSTANCE_PROOF_TYP


class IssuanceError(ClientAttestationError):
    """The issuance endpoint rejected the request (non-2xx). Carries the OAuth-style error body (at most its
    first 512 bytes). Transport failures (network, timeout, redirect, oversized or malformed response)
    raise :class:`~client_attestation_sdk.errors.TransportError` instead."""

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
    """Bootstraps a Client Attestation for a workload from its SPIFFE JWT-SVID.

    ``profile`` sets the mint protocol (default :class:`~client_attestation_sdk.attester.PingFederateProfile`;
    see docs/attester-profiles.md). The endpoint is given directly, so the profile's discovery is not used.

    The SVID is a bearer credential to the attester, so ``endpoint``, and every URL the profile calls, must be
    https unless its host is loopback (``localhost``, ``127.0.0.1``, ``::1``) or ``allow_insecure=True``.

    **Experimental** (see docs/api.md): it calls a PingFederate demo issuance servlet
    (/federation/attestation) whose protocol is not standardised.
    """

    def __init__(self, endpoint: str, client_id: str, attester_issuer: str, svid_source: SvidSource,
                 *, instance_key: SigningKeyPair = None, algorithm: str = "ES256",
                 profile: AttesterProfile = None, allow_insecure: bool = False):
        self.endpoint = endpoint.rstrip("/")
        _http.require_https(self.endpoint, "endpoint", allow_insecure)
        self._allow_insecure = allow_insecure
        self.client_id = client_id
        self.attester_issuer = attester_issuer      # the SVID audience AND the instance-proof aud
        self._svid_source = svid_source
        # The workload's own key: signs the instance proof, and the AS binds it into the attestation's cnf.
        self.instance_key = instance_key or SigningKeyPair.generate(algorithm)
        self.profile = profile if profile is not None else PingFederateProfile()

    def bootstrap(self, authorization_details=None, challenge: str = None) -> IssuedAttestation:
        """Fetch the SVID, prove possession of the instance key, and exchange them for a minted attestation."""
        svid = self._svid_source.fetch(self.attester_issuer)
        metadata = AttesterMetadata(evidence_audience=self.attester_issuer, attestation_endpoint=self.endpoint)
        minted = self.profile.mint(_IssuanceTransport(self._allow_insecure), metadata, MintRequest(
            instance_key=self.instance_key, evidence=svid, challenge=challenge or None,
            client_id=self.client_id, authorization_details=authorization_details or None))
        if minted is None or not minted.attestation:
            raise ClientAttestationError("attester response contained no attestation")
        return IssuedAttestation(minted.attestation, minted.expires_in, self.instance_key)


class _IssuanceTransport:
    """The issuance endpoint's transport: the https rule, and a non-2xx answer is an :class:`IssuanceError`."""

    def __init__(self, allow_insecure: bool = False):
        self._allow_insecure = allow_insecure

    def request_json(self, step: str, method: str, url: str, body: dict = None) -> dict:
        _http.require_https(url, f"{step} URL", self._allow_insecure)
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
        result = _http.request(method, url, body=data, timeout=20, headers=headers)
        if not result.ok:
            raise IssuanceError(result.status, result.body[:_http.ERROR_BODY_LIMIT].decode("utf-8", "replace"))
        return _http.json_ok(result, "attestation issuance endpoint")
