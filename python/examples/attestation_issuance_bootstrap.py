#!/usr/bin/env python3
"""Bootstrap a Client Attestation from a workload's SPIFFE identity, then use it to get a token.

Point it at any deployment of the issuance servlet:
  ISSUER=http://localhost:9031 python examples/attestation_issuance_bootstrap.py

Plain http is refused for anything but loopback unless you also set ALLOW_INSECURE=1.

Against the demo harness (pf-oidf-modules/demo/spiffe-bootstrap, `run-local.sh workload` server), the SVID
comes from its /dev/svid; in production use SpireWorkloadApiSvidSource() (the default) against a real agent.
"""
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from client_attestation_sdk import (  # noqa: E402
    AttestationIssuanceClient,
    HttpSvidSource,
    SpireWorkloadApiSvidSource,
    StaticSvidSource,
)

ISSUER = os.environ.get("ISSUER", "https://pf.example.com").rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "https://payment-agent.banking.demo")
ATTESTER = os.environ.get("ATTESTER_ISSUER", "https://attester.banking.demo")
OP_ISSUER = os.environ.get("OP_ISSUER", "https://as.banking.demo")
MAX_RESPONSE_BYTES = 1024 * 1024


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """The token request carries the attestation and PoP: never replay them to wherever a 3xx points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None  # urllib then raises HTTPError for the 3xx


def require_secure(url: str) -> None:
    """The SVID, attestation and PoP travel to ISSUER, so it must be https (loopback excepted)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or os.environ.get("ALLOW_INSECURE") == "1":
        return
    if parts.scheme == "http" and (parts.hostname or "").lower() in ("localhost", "127.0.0.1", "::1"):
        return
    sys.exit(f"ISSUER must use https: {url} (plain http is allowed for loopback, or set ALLOW_INSECURE=1)")


def fingerprint(token: str) -> str:
    return f"{len(token)} chars, sha256 {hashlib.sha256(token.encode()).hexdigest()[:12]}"


def svid_source():
    if os.environ.get("SVID_JWT"):
        return StaticSvidSource(os.environ["SVID_JWT"])
    if os.environ.get("USE_DEV_SVID") == "1":
        return HttpSvidSource(ISSUER + "/dev/svid")           # demo harness convenience
    return SpireWorkloadApiSvidSource()                       # default: real SPIRE agent


def main() -> int:
    require_secure(ISSUER)
    client = AttestationIssuanceClient(
        endpoint=ISSUER + "/federation/attestation",
        client_id=CLIENT_ID,
        attester_issuer=ATTESTER,
        svid_source=svid_source(),
        allow_insecure=os.environ.get("ALLOW_INSECURE") == "1",  # require_secure has already vetted the URL
    )
    issued = client.bootstrap(
        authorization_details=[{"type": "sales_agent", "sales_regions": ["EMEA"]}])
    print(f"minted attestation: {issued.attestation[:48]}…  expires_in={issued.expires_in}")
    print(f"instance cnf kid  : {client.instance_key.key_id}")

    # Use it: attestation + a fresh PoP (signed by the bound instance key) at the token endpoint.
    pop = issued.pop(audience=OP_ISSUER, client_id=CLIENT_ID)
    req = urllib.request.Request(
        ISSUER + "/as/token.oauth2", data=b"grant_type=client_credentials", method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "OAuth-Client-Attestation": issued.attestation, "OAuth-Client-Attestation-PoP": pop})
    try:
        r = urllib.request.build_opener(_RefuseRedirects).open(req, timeout=20)
    except urllib.error.HTTPError as e:
        r = e                                                  # a 3xx, 4xx or 5xx answer
    with r:
        status, body = r.status, r.read(MAX_RESPONSE_BYTES + 1)
    if 300 <= status < 400:
        print(f"token endpoint    : HTTP {status} redirect, not followed", file=sys.stderr)
        return 1
    if len(body) > MAX_RESPONSE_BYTES:
        print(f"token endpoint    : response larger than {MAX_RESPONSE_BYTES} bytes", file=sys.stderr)
        return 1
    try:
        tok = json.loads(body)
    except ValueError:
        tok = {}                                               # e.g. an HTML error page
    access_token = tok.get("access_token") if status == 200 else None
    shown = fingerprint(access_token) if access_token else tok.get("error", "no access_token")
    print(f"token endpoint    : HTTP {status}  access_token={shown}")
    print("BOOTSTRAP OK" if access_token else "no token")
    return 0 if access_token else 1


if __name__ == "__main__":
    sys.exit(main())
