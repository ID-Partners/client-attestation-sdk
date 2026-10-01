"""SPIFFE → OIDF attestation bridge, end to end.

A SPIFFE agent attests two agent workloads and issues each a JWT-SVID with its attested attributes; a
workload then folds those SPIFFE-sourced attributes into an OIDF Client Attestation. Run:

    PYTHONPATH=src python3 examples/spiffe_bridge.py
"""
import json

import jwt

from client_attestation_sdk import (
    ClientAttestationBuilder,
    SigningKeyPair,
    SpiffeAgent,
    to_workload_claim,
    verify_jwt_svid,
)

TRUST_DOMAIN = "banking.demo"
AS = "https://as.example.com"
ATTESTER = "https://attester.banking.demo"


def main() -> None:
    # 1) Stand up the SPIFFE agent for the trust domain and register the workloads it attests.
    agent = SpiffeAgent(TRUST_DOMAIN, SigningKeyPair.generate("ES256"))
    agent.register(
        {"docker:label:app": "payment-agent", "docker:image": "banking/payment-agent:1.4"},
        "payment-agent",
        {"region": "emea", "workload_type": "agent", "entitlements": ["initiate_payment", "read_accounts"]},
    )
    agent.register(
        {"docker:label:app": "origination-agent"},
        "origination-agent",
        {"region": "emea", "workload_type": "agent", "entitlements": ["create_opportunity"]},
    )

    # 2) A workload presents its selectors; the agent attests it and returns a JWT-SVID + attributes.
    selectors = {"docker:label:app": "payment-agent", "docker:image": "banking/payment-agent:1.4", "unix:uid": "1000"}
    svid = agent.fetch_jwt_svid(selectors, audience=AS)
    print(f"SPIFFE ID : {svid.spiffe_id}")
    print(f"attributes: {json.dumps(svid.attributes)}")

    # 3) Anyone with the trust bundle can verify the JWT-SVID.
    verified = verify_jwt_svid(svid.token, agent.trust_bundle(), audience=AS, trust_domain=TRUST_DOMAIN)
    print(f"SVID verified: sub={verified['sub']} aud={verified['aud']}")

    # 4) Bridge: fold the SPIFFE identity + attested attributes into an OIDF Client Attestation.
    instance = SigningKeyPair.generate("ES256")            # the client's instance key (cnf)
    attester = SigningKeyPair.generate("ES256")            # the Client Attester's key
    attestation = (
        ClientAttestationBuilder(attester, ATTESTER)
        .client_id(svid.spiffe_id)                          # the SPIFFE ID names the client
        .confirmation_key(instance)
        .workload(to_workload_claim(svid))                  # <-- SPIFFE-sourced workload attributes
        .expires_in(300)
        .build()
    )
    claims = jwt.decode(attestation, options={"verify_signature": False})
    print("\nClient Attestation `workload` claim (disclosed by the AS):")
    print(json.dumps(claims["workload"], indent=2))
    print("\nOK — the attestation carries SPIFFE-attested workload attributes.")


if __name__ == "__main__":
    main()
