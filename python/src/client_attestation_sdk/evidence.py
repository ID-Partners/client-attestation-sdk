"""Auto-detect the workload's platform identity (the evidence it presents to the attester).

The workload proves *what it is* with a token its runtime already issues. Which token, and where it
comes from, depends on the runtime:

- an explicit token in an environment variable (any runtime that injects one),
- a projected/mounted token file (Kubernetes, GKE, AKS),
- a SPIRE Workload API socket (SPIRE / SPIFFE),
- the GCP metadata server (GCE, GKE, Cloud Run, Vertex AI Agent Engine),
- Azure Instance Metadata Service (Container Apps, VMs, Functions — managed identity),
- AWS `sts:GetWebIdentityToken` (Lambda/ECS/EC2/Bedrock AgentCore).

`auto_detect_evidence()` tries these in order and returns the first that applies, so a developer can
write `ClientAttestation(pf_host)` and have it work without naming the source. Override by passing an
explicit `SvidSource` to `ClientAttestation`.
"""
from __future__ import annotations

import os
import urllib.parse

from . import _http
from .errors import TransportError
from .svid_source import SpireWorkloadApiSvidSource, StaticSvidSource, SvidSource

# Environment variables an operator can set to pin the evidence source explicitly.
ENV_SVID = "CLIENT_ATTESTATION_SVID"            # the token itself (static)
ENV_TOKEN_FILE = "CLIENT_ATTESTATION_TOKEN_FILE"  # path to a projected token file
ENV_SPIFFE_SOCKET = "SPIFFE_ENDPOINT_SOCKET"    # SPIRE Workload API socket (standard SPIFFE var)

# Default projected-token path used by the Kubernetes/GKE/AKS serviceAccountToken volume convention.
DEFAULT_TOKEN_FILE = "/var/run/secrets/tokens/attester-token"
# Default SPIRE agent socket path.
DEFAULT_SPIFFE_SOCKET = "/tmp/spire-agent/public/api.sock"
# GCP metadata server identity endpoint (returns a Google-signed ID token for the runtime SA).
GCP_METADATA_ROOT = "http://metadata.google.internal/computeMetadata/v1/"
GCP_METADATA_IDENTITY = GCP_METADATA_ROOT + "instance/service-accounts/default/identity"
# Azure Instance Metadata Service identity endpoint (returns a JSON envelope, not a raw token).
AZURE_IMDS_IDENTITY = "http://169.254.169.254/metadata/identity/oauth2/token"
AZURE_IMDS_INSTANCE = "http://169.254.169.254/metadata/instance"
AZURE_IMDS_API_VERSION = "2018-02-01"


class FileTokenSvidSource:
    """Reads the evidence token from a file on every fetch.

    Kubernetes and GKE mount a short-lived, auto-rotated service-account token into the pod as a file
    (a projected `serviceAccountToken` volume). Reading it fresh each time picks up the rotation. The
    file's audience must already be the attester's evidence audience — set it when you declare the volume.
    """

    def __init__(self, path: str):
        self.path = path

    def fetch(self, audience: str) -> str:  # noqa: ARG002 - audience is fixed when the volume is declared
        with open(self.path, "r", encoding="utf-8") as handle:
            return handle.read().strip()


class GoogleMetadataSvidSource:
    """Fetches a Google-signed ID token for the runtime service account from the GCP metadata server.

    Works on any Google runtime that exposes the metadata server (GCE, GKE, Cloud Run, Vertex AI Agent
    Engine). The token's `aud` is the attester's evidence audience; `sub` is the service account. No
    google-auth dependency — a plain metadata call.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def fetch(self, audience: str) -> str:
        url = f"{GCP_METADATA_IDENTITY}?audience={urllib.parse.quote(audience, safe='')}&format=full"
        response = _http.request("GET", url, headers={"Metadata-Flavor": "Google"}, timeout=self.timeout)
        return _http.text_ok(response, "GCP metadata server").strip()


class AzureImdsSvidSource:
    """Fetches an Entra-signed managed-identity token from Azure Instance Metadata Service (IMDS).

    Works on any Azure compute that has a managed identity attached (Container Apps, VMs, Functions,
    AKS nodes without Workload Identity Federation). The token's `aud` is the attester's evidence
    audience (passed as IMDS's `resource` parameter); `oid` is the identity's stable object id.

    Unlike GCP's metadata server, IMDS returns a JSON envelope (`{"access_token": "...", ...}`), not a
    raw JWT body — the token is extracted from it. Pass `client_id` to select a specific user-assigned
    identity when more than one is attached; omit it for the system-assigned identity (or the sole
    user-assigned one).

    On AKS with Workload Identity Federation, prefer the projected-token path (`FileTokenSvidSource`)
    instead; this source is for compute whose identity is a managed identity rather than a Kubernetes SA.
    """

    def __init__(self, timeout: float = 5.0, client_id: str = None):
        self.timeout = timeout
        self.client_id = client_id

    def fetch(self, audience: str) -> str:
        params = {"api-version": AZURE_IMDS_API_VERSION, "resource": audience}
        if self.client_id:
            params["client_id"] = self.client_id
        url = f"{AZURE_IMDS_IDENTITY}?{urllib.parse.urlencode(params)}"
        response = _http.request("GET", url, headers={"Metadata": "true"}, timeout=self.timeout)
        envelope = _http.json_ok(response, "Azure IMDS")
        return _http.require(envelope, "access_token", "Azure IMDS response")


class AwsWebIdentitySvidSource:
    """Fetches an AWS-signed OIDC token via `sts:GetWebIdentityToken` (AWS Outbound Identity Federation).

    The evidence for any AWS workload that has ambient IAM credentials, including a Bedrock AgentCore agent.
    The token's `sub` is the caller's IAM role ARN; `aud` is the audience passed here. Requires boto3 and
    the caller's role to have `sts:GetWebIdentityToken` (and the account to have run
    `aws iam enable-outbound-web-identity-federation`).

    On EKS, prefer the projected-token path (`FileTokenSvidSource`) instead; this source is for
    Lambda/ECS/EC2/AgentCore workloads whose identity is an IAM role rather than a Kubernetes SA.
    """

    def __init__(self, region: str = None):
        self.region = region

    def fetch(self, audience: str) -> str:
        try:
            import boto3  # imported lazily so boto3 is not a hard dependency
        except ImportError as error:
            raise EvidenceNotFound("AwsWebIdentitySvidSource needs boto3 installed") from error
        sts = boto3.client("sts", region_name=self.region)
        # Audience is a list; SigningAlgorithm (RS256 or ES384) is required.
        return sts.get_web_identity_token(Audience=[audience], SigningAlgorithm="RS256")["WebIdentityToken"]


def _aws_credentials_available() -> bool:
    if os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE") or os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
        return True
    if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        return True
    return False


def _gcp_metadata_available(timeout: float = 0.3) -> bool:
    try:
        response = _http.request("GET", GCP_METADATA_ROOT,
                                 headers={"Metadata-Flavor": "Google"}, timeout=timeout)
    except TransportError:
        return False
    return response.ok


def _azure_imds_available(timeout: float = 0.3) -> bool:
    try:
        response = _http.request("GET", f"{AZURE_IMDS_INSTANCE}?api-version=2021-02-01",
                                 headers={"Metadata": "true"}, timeout=timeout)
    except TransportError:
        return False
    return response.ok


def auto_detect_evidence() -> SvidSource:
    """Return the first evidence source that applies to this runtime, or raise with guidance.

    Order: explicit env token, projected token file (GKE/EKS/AKS), SPIRE socket, GCP metadata server,
    Azure IMDS, AWS web-identity (Lambda/ECS/EC2/AgentCore).

    If ``CLIENT_ATTESTATION_TOKEN_FILE`` or ``SPIFFE_ENDPOINT_SOCKET`` is set but points at a path that does
    not exist, this raises :class:`EvidenceNotFound` naming the variable instead of trying the next source.
    """
    static = os.environ.get(ENV_SVID)
    if static:
        return StaticSvidSource(static.strip())

    # An explicitly configured source that is missing is a misconfiguration: fail closed and name the
    # variable, rather than falling through and presenting some other identity this runtime happens to have.
    token_file = os.environ.get(ENV_TOKEN_FILE)
    if token_file:
        if not os.path.isfile(token_file):
            raise EvidenceNotFound(f"{ENV_TOKEN_FILE} is set to {token_file!r}, but no such file exists")
        return FileTokenSvidSource(token_file)
    if os.path.isfile(DEFAULT_TOKEN_FILE):
        return FileTokenSvidSource(DEFAULT_TOKEN_FILE)

    socket = os.environ.get(ENV_SPIFFE_SOCKET)
    if socket:
        socket_path = socket.replace("unix://", "")
        if not os.path.exists(socket_path):
            raise EvidenceNotFound(f"{ENV_SPIFFE_SOCKET} is set to {socket!r}, but no such socket exists")
        return SpireWorkloadApiSvidSource(socket_path=socket_path)
    if os.path.exists(DEFAULT_SPIFFE_SOCKET):
        return SpireWorkloadApiSvidSource(socket_path=DEFAULT_SPIFFE_SOCKET)

    if _gcp_metadata_available():
        return GoogleMetadataSvidSource()

    if _azure_imds_available():
        return AzureImdsSvidSource(client_id=os.environ.get("AZURE_CLIENT_ID"))

    # AWS is last: it needs an outbound STS call, so only reach for it when AWS credentials are visible in
    # the environment (Lambda/ECS/EC2/AgentCore). On EKS, prefer a projected token file (handled above).
    if _aws_credentials_available():
        return AwsWebIdentitySvidSource(region=os.environ.get("AWS_REGION"))

    raise EvidenceNotFound(
        "Could not auto-detect the workload's platform identity. Set one of "
        f"{ENV_SVID} (the token), {ENV_TOKEN_FILE} (a token file), or {ENV_SPIFFE_SOCKET} (SPIRE socket), "
        "or pass evidence=<SvidSource> to ClientAttestation explicitly.")


class EvidenceNotFound(RuntimeError):
    """No platform identity could be detected and none was supplied."""
