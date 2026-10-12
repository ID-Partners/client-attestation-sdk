# client-attestation-sdk (Python)

Python SDK for OAuth Attestation-Based Client Authentication. It obtains access tokens,
builds Client Attestation credentials and validates access tokens at a resource server.
The core dependencies are `pyjwt` and `cryptography`. Requires Python 3.11 or later.

Part of the [client-attestation-sdk](../README.md) monorepo; wire-compatible with the Java,
TypeScript, and Go ports.

## Install

```bash
python -m pip install client-attestation-sdk
```

Install the extra for the integration you use:

```bash
python -m pip install 'client-attestation-sdk[requests]'
python -m pip install 'client-attestation-sdk[httpx]'
python -m pip install 'client-attestation-sdk[aws]'
```

The first two extras install HTTP clients. The `aws` extra installs boto3 for the Experimental
AWS evidence source.

To work on the SDK itself, install from a clone with the test extras:

```bash
cd python                         # from the repository root
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
```

## Get a token and call an API

The attester must trust your workload identity and map it to an authorised client.
Set `CLIENT_ATTESTATION_TOKEN_FILE` to a readable identity token file with the attester's
evidence audience. `ATTESTER_URL`, `EVIDENCE_AUDIENCE` and `API_URL` below are application variables.
`EVIDENCE_AUDIENCE` is the audience your identity token carries, and the attester's discovery document must
name it too.

```bash
export ATTESTER_URL=https://attester.example.com
export EVIDENCE_AUDIENCE=https://attester.example.com/evidence
export API_URL=https://api.example.com/data
export CLIENT_ATTESTATION_TOKEN_FILE=/absolute/path/to/identity-token.jwt
```

Save as `call_api.py` after installing the `requests` extra:

```python
import os
import requests
from client_attestation_sdk import ClientAttestation

ca = ClientAttestation(os.environ["ATTESTER_URL"], evidence_audience=os.environ["EVIDENCE_AUDIENCE"])
response = requests.get(os.environ["API_URL"], auth=ca.requests_auth(), timeout=20)
response.raise_for_status()
print(response.status_code)
```

Run `python call_api.py`. Keep `ca` for later requests so it can reuse the cached token.
Use `ca.token()` when you need the token string. Use `ca.request_headers(method, url)` when
your HTTP client needs headers. The auth adapter attaches a DPoP proof when the token is
DPoP-bound. DPoP binds a token to a client key and requires a signed proof for each request.

See [Configuration](../docs/configuration.md) for every shared option and evidence precedence.

## Build a credential offline

This complete example generates temporary keys. It needs no attester or network connection.
The attester issues a Client Attestation for the instance key. The client signs a fresh
proof of possession (PoP) with that instance key.

```python
from client_attestation_sdk import (
    SigningKeyPair, ClientAttestationBuilder, ClientAttestationCredential,
)

# Attester issues the attestation, binding the client's public instance key
attester = SigningKeyPair.generate("ES256")
instance = SigningKeyPair.generate("ES256")
attestation = (
    ClientAttestationBuilder(attester, "https://attester.example.com")
    .client_id("https://rp.example.com")
    .confirmation_key(instance)
    .expires_in(300)
    .build()
)

# Client mints a fresh proof per token request
cred = ClientAttestationCredential(attestation, instance)

headers = cred.pop_headers("https://rp.example.com", "https://as.example.com")   # PoP-JWT mode
dpop_headers = cred.dpop_headers("POST", "https://as.example.com/as/token.oauth2")
assert set(headers) == {"OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP"}
assert set(dpop_headers) == {"OAuth-Client-Attestation", "DPoP"}
print("credential headers built")
```

Save as `build_credential.py` and run `python build_credential.py`. These generated keys are
for the example. A production authorisation server must trust the attester's signing key.

The one-call `ClientAttestation` orchestration class (see the [root README](../README.md#get-a-token-in-one-call))
wraps this: `ClientAttestation(host, evidence_audience=aud, pop_method="dpop_combined")` switches it to DPoP
mode, and a fetched challenge is carried through automatically as the PoP JWT's `challenge` claim or the DPoP
proof's `nonce` claim, whichever mode is active (`challenge_at_token=False` keeps it to the mint only).

In DPoP mode the AS can issue a DPoP-bound token (`token_type: DPoP`). Use `ca.request_headers(method, url)`
to get `Authorization: DPoP <token>` plus a fresh `DPoP` proof (with `ath` and any nonce the resource asked
for), or `ca.requests_auth()` / `ca.httpx_auth()`, which also re-send once on a `use_dpop_nonce` challenge.
Bearer tokens get just the `Authorization` header, as before. Pass `request_headers` the exact URL your HTTP
client sends: the proof is only good for the URL it names, and a URL with a backslash, whitespace or a
control character before its query is refused, since `urllib.parse` and `requests` disagree on its host.
For a DPoP-bound token, `requests_auth()` takes the token and proof off every redirect hop `requests`
builds. httpx follows redirects after the auth has run, so leave `follow_redirects` off (the httpx
default) with `httpx_auth()`.

Other options on `ClientAttestation`:

- `require_challenge=True` (default) - if the attester advertises a challenge endpoint and it fails, the flow
  fails rather than minting without a challenge. `False` restores the old lenient behaviour.
- `allow_insecure=False` (default) - `attester_url` and the discovered endpoints must be https, except loopback.
  `AttestationIssuanceClient` (its endpoint and every call its profile makes) and `OpenBaoTransitSigner`
  (the vault address) follow the same rule and take the same `allow_insecure=` keyword.
- `profile=` and `metadata=` - talk to an attester other than PingFederate: plug in your own
  `AttesterProfile`, or give the endpoints directly with `AttesterMetadata` and skip discovery. See
  [`docs/attester-profiles.md`](../docs/attester-profiles.md). The first argument is `attester_url`
  (it was `pf_host` before 1.0).
- `operator={...}` - asks the attester to name the client's operator. It goes in the mint request and,
  as compact sorted-key JSON, in the token request's `operator` form parameter.
- `algorithm="ES256"`, `expiry_skew_seconds=30` and `timeout=20.0` - the instance-key algorithm, how long
  before expiry a cached token is refreshed, and the per-request timeout in seconds.
- `trace=[...]` with `trace_redact=True` (default) - each wire call is recorded as a shell-quoted curl string
  with every credential replaced by `<redacted:N bytes>`. `trace_redact=False` records them verbatim - for
  local debugging only.

Without `evidence=`, the platform identity is auto-detected on each mint, in this order:
`CLIENT_ATTESTATION_SVID`, `CLIENT_ATTESTATION_TOKEN_FILE` (default `/var/run/secrets/tokens/attester-token`),
`SPIFFE_ENDPOINT_SOCKET` (default `/tmp/spire-agent/public/api.sock`), the GCP metadata server, Azure IMDS
(set `CLIENT_ATTESTATION_AZURE_RESOURCE` to the Entra resource the attester's evidence audience must
equal), and AWS web identity (needs the `[aws]` extra). `CLIENT_ATTESTATION_TOKEN_FILE` or `SPIFFE_ENDPOINT_SOCKET`
set to a path that does not exist raises `EvidenceNotFound` naming the variable, instead of falling through
to the next evidence source. `EvidenceNotFound` is a `RuntimeError`, not a `ClientAttestationError`.

## Token validator

The same distribution ships a resource-server validator (`client_attestation_sdk.token_validator`) - the side that *receives* and
checks a token:

```python
from client_attestation_sdk.token_validator import AccessTokenValidator, ValidatorConfig

validator = AccessTokenValidator(ValidatorConfig(
    issuer="https://issuer.example.com", audiences=["https://api.example.com"],
    jwks_uri="https://issuer.example.com/jwks", required_scopes=["read"]))

result = validator.validate(access_token)          # signature + iss/exp/nbf + audience + scope
if not result.valid:
    print(result.error)                            # e.g. "expired", "insufficient_scope"
elif result.claims.get("cnf") is not None:
    print("sender-constrained token: verify its proof first")   # see below
else:
    print(result.subject, result.scopes)

```

`jwks_uri` and the introspection endpoint must use https, except on loopback hosts; `allow_insecure=True`
overrides that. `discover(metadata_url)` fetches RFC 8414 metadata and refuses a document whose `issuer`
isn't the one the `.well-known` URL was built from (pass `issuer=` for any other URL).

This integration fragment expects `access_token` from an incoming request. `validate` checks
the JWT signature and claims. For RFC 7662 introspection, configure the resource server's
credentials and call `validate_active`:

```python
from client_attestation_sdk.token_validator import IntrospectionConfig

config = ValidatorConfig(
    issuer="https://issuer.example.com",
    audiences=["https://api.example.com"],
    required_scopes=["read"],
    introspection=IntrospectionConfig(
        endpoint="https://issuer.example.com/introspect",
        client_id="resource-server",
        client_secret="<resource-server-secret>",
    ),
)
validator = AccessTokenValidator(config)
# In your request handler: result = validator.validate_active(access_token)
```

Read the introspection secret from your application's secret configuration. `validate_active`
checks the introspection response. It does not first run `validate`. Transport failures raise.
The [protected resource example](../docs/examples.md#protected-resource-examples) shows
Bearer request handling. DPoP proof verification requires a separate authentication layer.

`validate` checks the token only. It doesn't look at `cnf`, so a DPoP- or mTLS-bound token is `valid`
without its sender proof: refuse one unless you verify that proof.

For an HTTP API, MCP server or A2A agent, wrap the validator in `ProtectedResource` for RFC 9728 metadata,
Bearer extraction, `WWW-Authenticate` challenges and a request guard (`authenticate`) that refuses a
token with a `cnf` claim, or `authenticate_active` for tokens checked by introspection; see the
[root README](../README.md#resource-server-for-mcp--a2a) and
[`examples/protected_resource_server.py`](examples/protected_resource_server.py).

## SPIFFE workload identity → attestation bridge

`SpiffeAgent` is an in-process implementation for tests and demonstrations. It matches supplied
selectors to registered workloads and issues a JWT-SVID. A JWT-SVID is a JWT that represents
a SPIFFE identity. The example copies its attributes into the Client Attestation's `workload`
claim. Use a real SPIRE identity source for deployment.

```python
from client_attestation_sdk import SpiffeAgent, SigningKeyPair, ClientAttestationBuilder, to_workload_claim

attester = SigningKeyPair.generate("ES256")
instance = SigningKeyPair.generate("ES256")
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

## Build and test

```bash
# Run from python/ with the environment above active.
python -m pytest --cov
python -m pip install build
python -m build
```

The build writes a wheel and source distribution to `dist/`.
See [Build and test](../docs/building.md#python) for packaged-install checks,
[Examples](../docs/examples.md) for commands and server prerequisites, and
[Deployment](../docs/deployment.md) for runtime identity setup.
