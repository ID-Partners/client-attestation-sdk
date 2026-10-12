"""Get an access token with client attestation in one call.

Point it at a PingFederate host. The SDK auto-detects the workload's platform identity (a projected
token file, a SPIRE socket, the GCP metadata server, or an env token), runs the whole attestation flow,
and returns an access token. No client_id, no client secret.

    EVIDENCE_AUDIENCE=https://attester.example.com python3 one_call_token.py pf.example.com
    ALLOW_INSECURE=1 EVIDENCE_AUDIENCE=... python3 one_call_token.py http://pingfederate.pf.svc.cluster.local:9080

EVIDENCE_AUDIENCE is the audience your attester expects the workload's identity token for; the attester's
discovery document must name the same one.

Plain http is refused for anything but loopback unless you set ALLOW_INSECURE=1.

Use it with an HTTP client:

    import requests
    ca = ClientAttestation("pf.example.com", evidence_audience="https://attester.example.com")
    requests.get("https://api.example.com/things", auth=ca.requests_auth())
"""
import hashlib
import os
import sys

from client_attestation_sdk import ClientAttestation


def main():
    attester_url = sys.argv[1] if len(sys.argv) > 1 else "https://pf.example.com"

    # Optional: ask for a specific entitlement (RFC 9396). The attester grants at most what the
    # workload is allowed. Omit to take the full attested ceiling.
    ca = ClientAttestation(
        attester_url,
        evidence_audience=os.environ.get("EVIDENCE_AUDIENCE", "https://attester.example.com"),
        authorization_details=[{"type": "sales_agent", "sales_regions": ["EMEA"]}],
        # Plain http is refused for non-loopback hosts unless explicitly asked for.
        allow_insecure=os.environ.get("ALLOW_INSECURE") == "1",
    )

    token = ca.token()
    # Never print the token itself: an opaque token is short enough that any prefix may be all of it.
    print(f"access token: {len(token)} chars, sha256 {hashlib.sha256(token.encode()).hexdigest()[:12]}")
    print("Authorization scheme:", ca.authorization_header()["Authorization"].split(" ", 1)[0])

    # A second call returns the cached token until it nears expiry — no new attestation is minted.
    assert ca.token() == token


if __name__ == "__main__":
    main()
