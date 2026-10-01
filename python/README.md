# client-attestation-sdk (Python)

Client-side builder for **OAuth Attestation-Based Client Authentication**
(draft-ietf-oauth-attestation-based-client-auth). Mints the Client Attestation JWT (attester side) and the
PoP / DPoP proofs + request headers (client side). Depends only on `pyjwt` + `cryptography`.

Part of the [client-attestation-sdk](../README.md) monorepo; wire-compatible with the Java,
TypeScript, and Go ports.

## Install

Not on PyPI yet. Install from a clone of this repository:

```bash
pip install -e '.[test]'
```

## Use

```python
from client_attestation_sdk import (
    SigningKeyPair, ClientAttestationBuilder, ClientAttestationCredential,
)

# Attester issues the attestation, binding the client's public instance key
attester = SigningKeyPair.generate("ES256")
attestation = (
    ClientAttestationBuilder(attester, "https://attester.example.com")
    .client_id("https://rp.example.com")
    .confirmation_jwk(client_instance_public_jwk)
    .expires_in(300)
    # optional: .authorization_details(...) / .workload(...) / .operator(sub, issuer=None) —
    # operator names who's accountable for running the client (RFC 8693 may_act-shaped; an
    # assertion, not proof of authorisation), distinct from client_id and from the principal.
    .build()
)

# Client mints a fresh proof per token request
instance = SigningKeyPair.from_jwk(my_instance_private_jwk, "ES256")
cred = ClientAttestationCredential(attestation, instance)

headers = cred.pop_headers("https://rp.example.com", "https://as.example.com")   # PoP-JWT mode
# or
headers = cred.dpop_headers("POST", "https://as.example.com/as/token.oauth2")    # DPoP combined mode
# -> {"OAuth-Client-Attestation": "...", "OAuth-Client-Attestation-PoP" | "DPoP": "..."}
```

The one-call `ClientAttestation` orchestration class (see the [root README](../README.md#get-a-token-in-one-call))
wraps this: `ClientAttestation(host, pop_method="dpop_combined")` switches it to DPoP mode, and a fetched
challenge is carried through automatically as the PoP JWT's `challenge` claim or the DPoP proof's `nonce`
claim, whichever mode is active.

In DPoP mode the AS can issue a DPoP-bound token (`token_type: DPoP`). Use `ca.request_headers(method, url)`
to get `Authorization: DPoP <token>` plus a fresh `DPoP` proof (with `ath` and any nonce the resource asked
for), or `ca.requests_auth()` / `ca.httpx_auth()`, which also re-send once on a `use_dpop_nonce` challenge.
Bearer tokens get just the `Authorization` header, as before.

Other options on `ClientAttestation`:

- `require_challenge=True` (default) - if the attester advertises a challenge endpoint and it fails, the flow
  fails rather than minting without a challenge. `False` restores the old lenient behaviour.
- `allow_insecure=False` (default) - `pf_host` and the discovered endpoints must be https, except loopback.
- `trace=[...]` with `trace_redact=True` (default) - each wire call is recorded as a shell-quoted curl string
  with every credential replaced by `<redacted:N bytes>`. `trace_redact=False` records them verbatim - for
  local debugging only.

`CLIENT_ATTESTATION_TOKEN_FILE` or `SPIFFE_ENDPOINT_SOCKET` set to a path that does not exist now raises
`EvidenceNotFound` naming the variable, instead of falling through to the next evidence source.

## Token validator

The same distribution ships a resource-server validator (`token_validator`) — the side that *receives* and
checks a token:

```python
from token_validator import AccessTokenValidator, ValidatorConfig

validator = AccessTokenValidator(ValidatorConfig(
    issuer="https://issuer.example.com", audiences=["https://api.example.com"],
    jwks_uri="https://issuer.example.com/jwks", required_scopes=["read"]))

result = validator.validate(access_token)          # signature + iss/exp/nbf + audience + scope
if result.valid:
    print(result.subject, result.scopes)
else:
    print(result.error)                            # e.g. "expired", "insufficient_scope"

# optional RFC 7662 introspection (opaque tokens / revocation):
result = validator.validate_active(access_token)
```

## SPIFFE workload identity → attestation bridge

`client_attestation_sdk.spiffe` is a lightweight, standards-shaped stand-in for a SPIRE **agent**'s
Workload API. It attests a workload by selector match and issues a **JWT-SVID** (`sub` = the SPIFFE ID,
signed by the trust domain), alongside the workload's **attested attributes** — which then become the
`workload` claim of a Client Attestation, so the AS discloses SPIFFE-attested attributes instead of static
metadata. Maps 1:1 onto real SPIRE later; only the transport differs.

```python
from client_attestation_sdk import SpiffeAgent, SigningKeyPair, ClientAttestationBuilder, to_workload_claim

agent = SpiffeAgent("banking.demo", SigningKeyPair.generate("ES256"))
agent.register({"docker:label:app": "payment-agent"}, "payment-agent",
               {"region": "emea", "entitlements": ["initiate_payment"]})

svid = agent.fetch_jwt_svid({"docker:label:app": "payment-agent"}, audience="https://as.example.com")
attestation = (ClientAttestationBuilder(attester, "https://attester.example.com")
               .client_id(svid.spiffe_id).confirmation_key(instance)
               .workload(to_workload_claim(svid))          # SPIFFE ID + attested attributes + the SVID
               .expires_in(300).build())
```

Runnable end to end: `PYTHONPATH=src python3 examples/spiffe_bridge.py`. Verify a JWT-SVID against the
trust bundle with `verify_jwt_svid(token, agent.trust_bundle(), audience, trust_domain)`.

## Test

```bash
pip install -e .[test]
pytest
```
