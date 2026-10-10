"""Client-side builder SDK for OAuth Attestation-Based Client Authentication."""
from .attester import (
    AttesterMetadata,
    AttesterProfile,
    AttesterTransport,
    MintRequest,
    MintResult,
    PingFederateProfile,
)
from .builders import ClientAttestationBuilder, DpopProofBuilder, PopBuilder
from .errors import TransportError
from .credential import (
    ATTESTATION_HEADER,
    DPOP_HEADER,
    POP_HEADER,
    ClientAttestationCredential,
)
from .issuance import (
    AttestationIssuanceClient,
    INSTANCE_PROOF_TYP,
    IssuanceError,
    IssuedAttestation,
)
from .keys import SigningKeyPair
from .signer import JwsSigner, OpenBaoTransitSigner
from .spiffe import (
    JwtSvid,
    RegistrationEntry,
    SpiffeAgent,
    parse_spiffe_id,
    to_workload_claim,
    verify_jwt_svid,
)
from .svid_source import (
    HttpSvidSource,
    SpiffeAgentSvidSource,
    SpireWorkloadApiSvidSource,
    StaticSvidSource,
    SvidSource,
)
from .evidence import (
    AwsWebIdentitySvidSource,
    AzureImdsSvidSource,
    EvidenceNotFound,
    FileTokenSvidSource,
    GoogleMetadataSvidSource,
    auto_detect_evidence,
)
from .token_source import ClientAttestation, ClientAttestationError

#: draft-ietf-oauth-attestation-based-client-auth revision this SDK implements.
DRAFT_REVISION = "10"

__all__ = [
    "DRAFT_REVISION",
    "SigningKeyPair",
    "ClientAttestationBuilder",
    "PopBuilder",
    "DpopProofBuilder",
    "ClientAttestationCredential",
    "JwsSigner",
    "OpenBaoTransitSigner",
    "ATTESTATION_HEADER",
    "POP_HEADER",
    "DPOP_HEADER",
    "SpiffeAgent",
    "RegistrationEntry",
    "JwtSvid",
    "verify_jwt_svid",
    "to_workload_claim",
    "parse_spiffe_id",
    "AttestationIssuanceClient",
    "IssuedAttestation",
    "IssuanceError",
    "INSTANCE_PROOF_TYP",
    "SvidSource",
    "StaticSvidSource",
    "HttpSvidSource",
    "SpireWorkloadApiSvidSource",
    "SpiffeAgentSvidSource",
    "ClientAttestation",
    "ClientAttestationError",
    "AttesterProfile",
    "AttesterMetadata",
    "AttesterTransport",
    "MintRequest",
    "MintResult",
    "PingFederateProfile",
    "TransportError",
    "auto_detect_evidence",
    "EvidenceNotFound",
    "FileTokenSvidSource",
    "GoogleMetadataSvidSource",
    "AzureImdsSvidSource",
    "AwsWebIdentitySvidSource",
]
__version__ = "1.0.1"
