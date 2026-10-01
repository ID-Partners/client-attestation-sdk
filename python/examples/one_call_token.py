"""Get an access token with client attestation in one call.

Point it at a PingFederate host. The SDK auto-detects the workload's platform identity (a projected
token file, a SPIRE socket, the GCP metadata server, or an env token), runs the whole attestation flow,
and returns an access token. No client_id, no client secret.

    python3 one_call_token.py pf.example.com
    python3 one_call_token.py http://pingfederate.pf:9080          # in-cluster, plain HTTP

Use it with an HTTP client:

    import requests
    ca = ClientAttestation("pf.example.com")
    requests.get("https://api.example.com/things", auth=ca.requests_auth())
"""
import sys

from client_attestation_sdk import ClientAttestation


def main():
    pf_host = sys.argv[1] if len(sys.argv) > 1 else "http://pingfederate.pf:9080"

    # Optional: ask for a specific entitlement (RFC 9396). The attester grants at most what the
    # workload is allowed. Omit to take the full attested ceiling.
    ca = ClientAttestation(
        pf_host,
        authorization_details=[{"type": "sales_agent", "sales_regions": ["EMEA"]}],
        # Plain http is refused for non-loopback hosts unless asked for; the in-cluster default needs it.
        allow_insecure=pf_host.startswith("http://"),
    )

    token = ca.token()
    print("access token (first 40 chars):", token[:40], "...")
    print("Authorization header:", ca.authorization_header()["Authorization"][:47], "...")

    # A second call returns the cached token until it nears expiry — no new attestation is minted.
    assert ca.token() == token


if __name__ == "__main__":
    main()
