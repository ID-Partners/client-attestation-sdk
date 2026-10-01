#!/usr/bin/env python3
"""Bootstrap a Client Attestation from a workload's SPIFFE identity, then use it to get a token.

Point it at any deployment of the issuance servlet:
  ISSUER=http://localhost:9031 python examples/attestation_issuance_bootstrap.py

Against the demo harness (pf-oidf-modules/demo/spiffe-bootstrap, `run-local.sh workload` server), the SVID
comes from its /dev/svid; in production use SpireWorkloadApiSvidSource() (the default) against a real agent.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from client_attestation_sdk import (  # noqa: E402
    AttestationIssuanceClient,
    HttpSvidSource,
    SpireWorkloadApiSvidSource,
    StaticSvidSource,
)

ISSUER = os.environ.get("ISSUER", "http://localhost:9031").rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "https://payment-agent.banking.demo")
ATTESTER = os.environ.get("ATTESTER_ISSUER", "https://attester.banking.demo")
OP_ISSUER = os.environ.get("OP_ISSUER", "https://as.banking.demo")


def svid_source():
    if os.environ.get("SVID_JWT"):
        return StaticSvidSource(os.environ["SVID_JWT"])
    if os.environ.get("USE_DEV_SVID") == "1":
        return HttpSvidSource(ISSUER + "/dev/svid")           # demo harness convenience
    return SpireWorkloadApiSvidSource()                       # default: real SPIRE agent


def main() -> int:
    client = AttestationIssuanceClient(
        endpoint=ISSUER + "/federation/attestation",
        client_id=CLIENT_ID,
        attester_issuer=ATTESTER,
        svid_source=svid_source(),
    )
    issued = client.bootstrap(
        authorization_details=[{"type": "sales_agent", "sales_regions": ["EMEA"]}])
    print(f"minted attestation: {issued.attestation[:48]}…  expires_in={issued.expires_in}")
    print(f"instance cnf kid  : {client.instance_key.key_id}")

    # Use it: attestation + a fresh PoP (signed by the bound instance key) at the token endpoint.
    import json
    import urllib.request

    pop = issued.pop(audience=OP_ISSUER, client_id=CLIENT_ID)
    req = urllib.request.Request(
        ISSUER + "/as/token.oauth2", data=b"grant_type=client_credentials", method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "OAuth-Client-Attestation": issued.attestation, "OAuth-Client-Attestation-PoP": pop})
    with urllib.request.urlopen(req, timeout=20) as r:
        tok = json.loads(r.read())
    print(f"token endpoint    : HTTP {r.status}  access_token={str(tok.get('access_token'))[:32]}…")
    print("BOOTSTRAP OK" if tok.get("access_token") else "no token")
    return 0 if tok.get("access_token") else 1


if __name__ == "__main__":
    sys.exit(main())
