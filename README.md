# client-attestation-sdk

OAuth SDKs for Java, Python, TypeScript and Go. They authenticate workloads with
OAuth Attestation-Based Client Authentication. A workload is an application or service
that calls a protected API.

A JSON Web Token (JWT) carries claims signed by its issuer. A Client Attestation is a JWT
that identifies the client and binds its instance public key.

The SDK runs inside your application. Your deployment supplies an attester, an authorisation
server and a workload identity that the attester accepts.

| Capability | What it does | Languages |
| --- | --- | --- |
| Obtain a token | Discovers the attester, presents workload identity, obtains a Client Attestation and requests an access token. Caches the token. | All four. |
| Build a credential | Builds a Client Attestation JWT and a proof of possession (PoP) for the client's instance key. Produces token-request headers. | All four. |
| Validate a token | Checks JWT signatures and claims, or uses RFC 7662 introspection. Provides a Bearer resource guard and protected-resource metadata. | All four. |
| Handle an authorisation challenge | Parses challenges and supports CIBA or web consent through application-supplied integrations. | Python only. |

The authentication method is `attest_jwt_client_auth`. The PoP methods are
`attestation_pop_jwt` and `dpop_combined`. DPoP binds a token to a client key and requires a
signed proof for each request. Resource-side DPoP proof verification is separate from the
SDK's Bearer guard.

## Documentation

| Task | Guide |
| --- | --- |
| Install and call an API | [Python](python/README.md), [TypeScript](typescript/README.md), [Go](go/README.md), [Java](java/README.md). Each includes a complete offline builder example. |
| Configure the client and validator | [Configuration](docs/configuration.md). Includes a reference for each component, defaults, per-call overrides and port differences. |
| Build and test from a clone | [Build and test](docs/building.md). Includes toolchains, package outputs and cross-language checks. |
| Run a supplied example | [Examples](docs/examples.md). Includes commands, external dependencies and expected results. |
| Deploy an application or protected resource | [Deployment](docs/deployment.md). Includes a Kubernetes projected token example and the package release process. |
| Diagnose a failure | [Troubleshooting](docs/troubleshooting.md) and [Logging](docs/logging.md). |
| Use another attester | [Attester profiles](docs/attester-profiles.md). |
| Check API support and validation rules | [Public API](docs/api.md) and [Validation semantics](validation/SEMANTICS.md). |

The [offline explainer](docs/explainer.html) contains architecture diagrams and the feature table.

## Status and versioning

From 1.0.0 the SDK follows [semver](https://semver.org/). All four ports share one version and release
together. Every public name is in one of three tiers, listed port by port in [`docs/api.md`](docs/api.md):

- **Stable** API follows semver. A breaking change needs a major release. Anything Stable that is to be
  removed or renamed is deprecated for at least one minor release first, and goes in the next major.
  The one exception is security: a minor or patch release may make the SDK refuse something it used to
  accept (a setting it now requires, a token or request it now rejects), with no deprecation period, when
  accepting it lets a credential or token reach a party it shouldn't. Each such change opens its CHANGELOG
  section under "check these before you upgrade", with what to set or change.
- **Experimental** API may change or go in any minor release, with a CHANGELOG entry but no deprecation
  period. Each Experimental item says so in its doc comment, and `docs/api.md` gives the reason: mostly
  it exists in one port only, depends on someone else's API, or is an interface you implement.
- **Internal** code is not API and is not covered, even where the language lets you reach it. Each port
  hides it as far as the language allows.

The rest of the versioning:

- CI checks each port's public API against a snapshot in [`docs/api-surface/`](docs/api-surface/), so an
  API change can't land by accident. See [CONTRIBUTING.md](CONTRIBUTING.md).
- The SDK tracks **draft -10** of draft-ietf-oauth-attestation-based-client-auth. Moving to a new draft
  revision always gets a changelog entry, because it can change what goes on the wire. It is a minor
  release if no Stable API breaks, and a major one if it does.
- Each port exports the revision it implements (`DRAFT_REVISION`, `DraftRevision` in Go), so code can check
  it rather than read this page.
- The draft doesn't say how a workload gets its attestation from the attester, so that part is an
  **attester profile** you can swap. The default profile is PingFederate, the attester this SDK was built
  against: discovery at `/.well-known/client-attester` and an instance proof with the proprietary `typ`
  `oauth-attestation-instance-proof+jwt`. Neither is in the draft. For another attester, give its
  endpoints directly (no discovery) or plug in your own profile – see
  [`docs/attester-profiles.md`](docs/attester-profiles.md).
## Install

Install the SDK in the application that will use it. Runtime requirements are Python 3.11+,
Node.js 20+, Go 1.25+ or JDK 17+, according to the port.

| Language | Package | Install |
| --- | --- | --- |
| Python | [PyPI](https://pypi.org/project/client-attestation-sdk/) | `python -m pip install client-attestation-sdk` |
| TypeScript | [npm](https://www.npmjs.com/package/@idpartners/client-attestation-sdk) | `npm install @idpartners/client-attestation-sdk` |
| Go | [pkg.go.dev](https://pkg.go.dev/github.com/id-partners/client-attestation-sdk/go) | `go get github.com/id-partners/client-attestation-sdk/go` |
| Java | [Maven Central](https://central.sonatype.com/artifact/global.idpartners/client-attestation-sdk) | Add `global.idpartners:client-attestation-sdk` to Maven. See the [Java README](java/README.md#install). |

See [CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Feature support

Generated from [`docs/features.json`](docs/features.json) by `scripts/features.py`; CI fails if this table
or the explainer drifts from it. A dash means the port doesn't have the feature yet.

<!-- features:begin -->
| Capability | Go | Java | Python | TypeScript |
|---|---|---|---|---|
| **Getting a token** | | | | |
| One-call token source | ✓ | ✓ | ✓ | ✓ |
| DPoP-combined mode | ✓ | ✓ | ✓ | ✓ |
| DPoP-bound tokens at a resource | ✓ | ✓ | ✓ | ✓ |
| Fail-closed defaults | ✓ | ✓ | ✓ | ✓ |
| Name the operator on the one-call class | ✓ | ✓ | ✓ | ✓ |
| Drop the token-endpoint challenge | ✓ | ✓ | ✓ | ✓ |
| Logging hooks | ✓ | ✓ | ✓ | ✓ |
| Attester profiles | ✓ | ✓ | ✓ | ✓ |
| Trace every call as curl | — | — | ✓ | — |
| Asserted context at mint | — | — | ✓ | — |
| **Building credentials** | | | | |
| Client Attestation builder | ✓ | ✓ | ✓ | ✓ |
| PoP JWT and DPoP proof builders | ✓ | ✓ | ✓ | ✓ |
| ES, RS and PS keys at 256, 384 and 512 | ✓ | ✓ | ✓ | ✓ |
| `operator` claim on the builder | ✓ | ✓ | ✓ | ✓ |
| `workload` and `authorization_details` claims | ✓ | ✓ | ✓ | ✓ |
| External signer | ✓ | ✓ | ✓ | ✓ |
| **Evidence and bootstrap** | | | | |
| Evidence auto-detect | ✓ | ✓ | ✓ | ✓ |
| Azure IMDS evidence | — | — | ✓ | — |
| AWS web-identity evidence | — | — | ✓ | — |
| SPIFFE issuance bootstrap | ✓ | ✓ | ✓ | ✓ |
| **Resource server** | | | | |
| Token validator | ✓ | ✓ | ✓ | ✓ |
| MCP and A2A protected-resource helper | ✓ | ✓ | ✓ | ✓ |
| Authorization-server metadata discovery | — | ✓ | ✓ | — |
| **Step-up** | | | | |
| Challenge handling | — | — | ✓ | — |
<!-- features:end -->

## Get a token in one call

The attester must already trust the workload's identity issuer and map that identity to a client.
Pass the attester's base URL to the SDK. It discovers endpoints, obtains evidence and requests a
token. It finds the workload's platform identity itself, in this order: a token in
`CLIENT_ATTESTATION_SVID`, a projected token file, a SPIRE socket, the GCP metadata server (and, in Python
only, Azure IMDS and AWS web identity). The Python example below uses the `requests` extra. Replace the hosts and provide an
identity source from [Configuration](docs/configuration.md#workload-identity).

```bash
python -m pip install 'client-attestation-sdk[requests]'
export CLIENT_ATTESTATION_TOKEN_FILE=/absolute/path/to/identity-token.jwt
```

```python
from client_attestation_sdk import ClientAttestation

AUD = "https://attester.example.com"   # the audience your attester expects the identity token for

ca = ClientAttestation("pf.example.com", evidence_audience=AUD)   # auto-detects the platform identity
token = ca.token()                                # access token, cached until it nears expiry

import requests
response = requests.get("https://api.example.com/x", auth=ca.requests_auth(), timeout=20)
response.raise_for_status()

# Ask for a specific entitlement (RFC 9396); the attester grants at most what the workload is allowed:
ca = ClientAttestation("pf.example.com", evidence_audience=AUD,
                       authorization_details=[{"type": "sales_agent", "sales_regions": ["EMEA"]}])

# Present a DPoP proof instead of a dedicated PoP JWT (PoP method dpop_combined):
ca = ClientAttestation("pf.example.com", evidence_audience=AUD, pop_method="dpop_combined")
```

Discovery supplies the endpoints and the PoP audience. You configure the host and `evidence_audience`: the
audience the workload's platform identity token is requested for. The discovery document must name the same
one, so the attester can't choose which service the workload mints an identity token for (Go
`WithEvidenceAudience`, Java `.evidenceAudience(...)`, TypeScript `evidenceAudience`). It is required unless
you give the endpoints yourself as static `metadata`. The workload still needs trusted identity evidence.
Use `ca.request_headers(method, url)` when an agent or HTTP client needs a header map.
This method includes the proof required for a DPoP-bound token.
The same class exists in all four languages, `pop_method` included (Go/Java/TS:
`WithPopMethod("dpop_combined")` / `.popMethod("dpop_combined")` / `popMethod: "dpop_combined"`).

Either way, if the attester advertises a `challenge_endpoint`, the SDK fetches a fresh challenge and carries
it through automatically - as the PoP JWT's `challenge` claim in the default mode, or as the DPoP proof's
`nonce` claim in `dpop_combined` mode. For an attester that consumes the challenge at mint and refuses to
see it again, `challenge_at_token=False` keeps it out of the token request.

To see what the flow is doing, turn on logging. It is off until you configure it, uses each language's own
logging (Python `logging`, Go `log/slog`, Java `System.Logger`, a `logger` option in TypeScript), and
never writes a token, proof, attestation or key. The events and their attributes are the same in every
port: see [`docs/logging.md`](docs/logging.md).

`java/` is the reference builder (formerly the standalone `client-attestation-sdk` repo). The **AS-side
verifier** that accepts these credentials is separate:
[client-attestation](https://github.com/dphhyland/client-attestation).

## Handling a challenge

An authorisation challenge tells the caller what is required before the request can proceed.
The Python parser classifies the response using its headers and body. The status code alone
does not identify the requirement.

Client Initiated Backchannel Authentication (CIBA) requests human approval through an
authorisation server. `CibaResolver` runs that exchange and polls for its result. The
application supplies the device registry, consent records and approval interface through `Hooks`.
This package is Experimental and exists only in Python.

The integration fragment below requires an HTTP response `resp`, the PingFederate base URL
`PF` and issuer `PF_ISSUER`, the registered CIBA `AGENT_ID`, and its signing key `PEM` and `KID`.
`directory` and `approver` are application services implementing the hooks. `principal` identifies
the human. The payment fields come from the request being approved.

```python
from client_attestation_sdk.authz_challenge import (
    parse_challenge, CibaClient, CibaResolver, PrivateKeyJwtAuth, Hooks,
    Pending, Resolved, Unavailable, CHANNEL_DEVICE)

ch = parse_challenge(resp.status_code, resp.headers, resp.text)     # -> Challenge | None
if ch and ch.type == "resource_authorisation":
    resolver = CibaResolver(
        CibaClient(bc_auth_endpoint=PF + "/as/bc-auth.ciba", token_endpoint=PF + "/as/token.oauth2",
                   client_id=AGENT_ID, issuer=PF_ISSUER,
                   # the client assertion's aud is PF_ISSUER, one string (CIBA Core §7.1). For an AS that
                   # accepts only its endpoint URL: audience_mode=AUDIENCE_ENDPOINT; for an array of
                   # audiences: extra_audiences=(...)
                   client_auth=PrivateKeyJwtAuth(client_id=AGENT_ID, private_key_pem=PEM, kid=KID),
                   request_signing_key_pem=PEM, request_signing_kid=KID),
        Hooks(channel_for=directory.channel_for,            # "device" | "web_consent" | "local"
              already_covered=directory.consent_covers,     # the PDP's own question - a stale challenge?
              register_for_device=approver.publish,         # the phone looks the ceremony up by its reference
              persist=directory.save, rehydrate=directory.load,   # survive a restart mid-approval
              on_outcome=directory.record))                 # approved/denied/expired -> where the PDP looks
    res = resolver.resolve(ch, subject=principal, initiator=AGENT_ID,
                           instruction={"amount": amount, "currency": cur, "debtor": src, "creditor": dst})
    # Pending  -> return {code, poll_url, interval, expires_in} to whoever called you; they poll
    #             resolver.poll(code) until approved/denied/expired, then RE-SEND the same call.
    # Resolved -> an authorisation already covers this instruction: just re-send.
    # Unavailable -> no channel to the human from here (fallback: "bubble_up" | "web_consent").
```

What the SDK owns: the challenge vocabulary, the CIBA wire protocol **and its pacing rules** (poll faster
than the AS's `interval` and PingFederate escalates `slow_down` → `invalid_request` → it *invalidates the
grant*, which looks exactly like "expired on device"), dedupe so one instruction never buzzes the phone
twice, a settle window so a stronger out-of-band verdict from the device is not overwritten by the poll,
and `verify_resume` — the re-sent call must hash to the instruction the human approved, byte for byte.
What the deployment owns, via `Hooks`: its device registry, its consent directory, its approver app.
An approval resumes once: `verify_resume` reads the record back through `rehydrate`, records the use through
`persist` (or `consume`, a compare-and-set, if the store has one), and refuses the resume if it can't, so
replicas sharing a store don't each accept the same code.

Use `resolver.poll(code)` at the returned interval. An approved outcome must be written to
the application's authorisation records through `on_outcome`. Before resending the request,
call `verify_resume(code, subject=principal, instruction=instruction)` to check that the subject
and instruction match the approval. Encode decimal amounts as strings so the instruction's
canonical JSON has consistent numeric values.

`Pending` means approval is outstanding. `Resolved` means an existing authorisation covers the
instruction. `Unavailable` means the resolver has no channel that can complete it.
The resolver discards the CIBA access token. The application uses the recorded approval to
decide whether to permit the retried call. The application must provide persistence hooks
when approvals need to survive a process restart.

**Ports.** The parser is pinned by [`validation/challenges.json`](validation/challenges.json) — 20 cases
mirroring the real PEP responses (Kong `authzen-pdp`, `coaz-pep`, the MCP servers' tool results) and two
malformed ones — and only the Python parser runs them today. They are language-neutral on purpose: a port
that adds a parser must return the identical classification for every case. The resolvers are stateful,
long-lived and networked, which is exactly where a four-language SDK drifts, so they are Python-only for
now and the feature matrix says so.
The hook signatures are in
[`Hooks`](python/src/client_attestation_sdk/authz_challenge/resolver.py).

## Proven interoperable

Every port is checked against the **real Java AS-side verifier**. Go, Python and TypeScript each build
credentials from the shared [`vectors/inputs.json`](vectors/inputs.json) (fixed throwaway test keys) into
`vectors/out/<lang>.json`, and [`interop/VerifyInterop.java`](interop/VerifyInterop.java) runs each through
`ClientAttestationVerifier` in both PoP and DPoP modes. Reproduce with
[`./verify-interop.sh`](verify-interop.sh). Java's own credentials go through the same verifier in
`RoundTripTest`, run by `./mvnw verify -Pinterop` in `java/`. A Python-, TypeScript-, or Go-built credential
is accepted by exactly the same AS as a Java-built one. Every port's tests also
run [`vectors/htu.json`](vectors/htu.json), so all four sign the same DPoP `htu` for a URL, or refuse it
with the same message ([the rule](vectors/README.md#the-htu-rule)).

**Validator** - every port validates the shared [`validation/tokens.json`](validation/tokens.json)
(pre-signed tokens, each with one defect: expiry and leeway, issuer, audience, scope, signature, `alg: none`
and HMAC key confusion, malformed and duplicate-keyed JSON, out-of-range dates, wrongly typed claims) and
[`validation/introspection.json`](validation/introspection.json) (canned RFC 7662 responses), and must
return the **identical verdict** for every case. [`validation/check.py`](validation/check.py) confirms all
four agree with the expected verdicts; [`validation/SEMANTICS.md`](validation/SEMANTICS.md) defines every
rule. Reproduce with [`./verify-validation.sh`](verify-validation.sh).

## Test coverage

Two layers, deliberately different in scope:

- **Cross-language agreement** (above) checks that the ports' artifacts are accepted by one shared
  verifier and that their validators agree. `./verify-interop.sh` covers the Go, Python and TypeScript
  credentials (Java's go through `RoundTripTest` under `./mvnw verify -Pinterop`), and
  `./verify-validation.sh` covers all four validators. The artifacts are not byte-identical (signatures,
  `jti` and `iat` differ); each is accepted by the same verifier. Both cover only the **low-level
  builder/credential API** (`ClientAttestationBuilder`, `ClientAttestationCredential`,
  `AccessTokenValidator`) against fixed vectors. It does not exercise the one-call `ClientAttestation`
  orchestration class's own decisions (evidence auto-detection, discovery, challenge fetching, caching).
- **Per-language unit suites** (`go test ./...`, `./mvnw test`, `pytest`, `npm test` — see each language's
  README) cover that orchestration layer directly, including edge cases the shared vectors don't reach:
  malformed/expired tokens, unaccepted algorithms, signer/network failures, evidence auto-detect
  precedence, and that a fetched challenge actually reaches the
  token-endpoint PoP JWT's `challenge` claim in the default mode, and the DPoP proof's `nonce` claim in
  `dpop_combined` mode, in both the one-call flow and the SPIFFE issuance-bootstrap flow.

Run everything before relying on a change: each language's own suite, then both `verify-*.sh` scripts.
CI runs all of it except `verify-interop.sh` on pull requests and pushes to `main`, but only the jobs a
change touches: a port's suite when its files change, the validator agreement when a validator changes,
and every job when shared files change (see [CONTRIBUTING.md](CONTRIBUTING.md#running-everything)).
See [Build and test](docs/building.md).

## Layout

```
java/         builder + one-call client + tokenvalidator  (jose4j)
python/       client_attestation_sdk (+ .token_validator, .authz_challenge)  (PyJWT + cryptography)
typescript/   src/ builder + src/validator/               (panva jose; Node 20+ or edge)
go/           builder package + tokenvalidator/           (lestrrat-go/jwx)
vectors/      client-builder shared vectors + outputs
validation/   token-validator + challenge-parser shared vectors + agreement checker
interop/      Java cross-language verifier (builder side)
```

See each subdirectory's README for language-specific install and usage. Representative flow (Python):

```python
from client_attestation_sdk import SigningKeyPair, ClientAttestationBuilder, ClientAttestationCredential

attester = SigningKeyPair.generate("ES256")
instance = SigningKeyPair.generate("ES256")
attestation = (ClientAttestationBuilder(attester, "https://attester.example.com")
               .client_id("https://rp.example.com").confirmation_key(instance).expires_in(300).build())
headers = ClientAttestationCredential(attestation, instance).pop_headers(
    "https://rp.example.com", "https://as.example.com")
```

## Contract

All ports emit the same shapes (ES256 by default, and ES, RS or PS at 256, 384 or 512 on request; `kid` =
RFC 7638 thumbprint; `iat`/`exp` integer epoch seconds):

| Artifact | `typ` | key in header | key claims |
|---|---|---|---|
| Attestation | `oauth-client-attestation+jwt` | `kid` (attester) | `iss, sub, iat, exp, cnf.jwk` (instance pub, +kid) |
| PoP | `oauth-client-attestation-pop+jwt` | `kid` (instance) | `aud, jti, iat` (+ optional `iss`, `challenge`) |
| DPoP | `dpop+jwt` | `jwk` (instance pub, −kid) | `htm, htu, jti, iat` (+ optional `nonce`, `ath`) |

## Bootstrapping from SPIFFE (attestation issuance)

The inverse of the builder: instead of holding an attester key and building an attestation locally, a
workload proves its **SPIFFE identity** (a JWT-SVID) and the Authorization Server (PingFederate's
`/federation/attestation` servlet) **mints** a Client Attestation bound to the workload's own instance
key. A client credential bootstrapped from infra identity — no pre-shared secret. All four ports ship an
`AttestationIssuanceClient`, which takes the `SvidSource` to use: the SPIRE Workload API source for a real
SPIRE agent (it runs the `spire-agent` CLI; `SpireWorkloadApiSvidSource` in Python and TypeScript,
`SpireWorkloadAPISvidSource` in Go, `SvidSource.SpireWorkloadApi` in Java), or `Static`/`Http` for tests
and the demo harness.

```python
from client_attestation_sdk import AttestationIssuanceClient, SpireWorkloadApiSvidSource

client = AttestationIssuanceClient(
    endpoint="https://pf/federation/attestation", client_id="https://agent.example",
    attester_issuer="https://attester.example", svid_source=SpireWorkloadApiSvidSource())
issued = client.bootstrap(authorization_details=[{"type": "sales_agent", "sales_regions": ["EMEA"]}])
headers = {"OAuth-Client-Attestation": issued.attestation,           # minted by the AS
           "OAuth-Client-Attestation-PoP": issued.pop(token_endpoint_aud)}   # signed by the bound instance key

# ...or DPoP combined mode instead of the dedicated PoP JWT:
headers = {"OAuth-Client-Attestation": issued.attestation,
           "DPoP": issued.dpop("POST", "https://pf/as/token.oauth2")}
```

Both `pop(...)` and `dpop(...)` take an optional trailing `challenge` - pass one through if the AS gave you
one; it lands as the PoP JWT's `challenge` claim or the DPoP proof's `nonce` claim, matching whichever mode
you built.

Python, TypeScript and Go supply bootstrap executables. Java supplies the issuance API and
interop tests. The [example guide](docs/examples.md#spiffe-issuance-bootstrap) lists commands
and the external demo servlet they require.

## Signing keys outside the process (Vault / HSM)

The attester's issuing key doesn't have to live in the client. `OpenBaoTransitSigner` signs the attestation
inside an OpenBao / HashiCorp Vault transit engine (`marshaling_algorithm=jws`), so the private key never
leaves the vault - pass it to the builder in place of a local key:

```python
from client_attestation_sdk import OpenBaoTransitSigner, ClientAttestationBuilder

# Integration fragment: vault_token and instance come from the attester's configuration.
signer = OpenBaoTransitSigner("https://openbao.example.com", vault_token, "attestation-es256")
attestation = (ClientAttestationBuilder(signer, "https://attester.example.com")
               .client_id("https://rp.example.com").confirmation_key(instance).expires_in(300).build())
# a verifier registers signer.public_jwk() (kid = the key's RFC 7638 thumbprint)
```

Same in every language - TS: `await OpenBaoTransitSigner.create(addr, token, key)`; Go:
`NewClientAttestationBuilderWithSigner(signer, issuer)`. The vault token goes on every call, so the vault
address must be https unless it is loopback (`allow_insecure=True` / `allowInsecure` /
`WithOpenBaoAllowInsecure()` lifts that), and the key name may contain only letters, digits, `_`, `.` and
`-`. Any key store fits the `JwsSigner` interface: it names the algorithm, the key id and the public JWK,
and signs a JWS signing input, returning the raw signature (`r‖s` for EC). Implement it and plug it in.
The builder accepts only ES256/384/512, RS256/384/512 and PS256/384/512 from a signer, and refuses an
empty signature or an ES signature that isn't the fixed-width `r‖s`. The signer is for the attestation
builder; the PoP and DPoP proofs are always signed by the instance key the client holds.

## Token validation (resource server)

The validator side mirrors the same config→act shape. Representative flow (Python):

```python
from client_attestation_sdk.token_validator import AccessTokenValidator, ValidatorConfig

validator = AccessTokenValidator(ValidatorConfig(
    issuer="https://issuer.example.com", audiences=["https://api.example.com"],
    jwks_uri="https://issuer.example.com/jwks", required_scopes=["read"]))

result = validator.validate(access_token)          # local: signature + iss/exp/nbf + audience + scope
if result.valid and result.claims.get("cnf") is None:   # see below for sender-constrained tokens
    print(result.subject, result.scopes)
```

This fragment expects `access_token` from a request. To use RFC 7662 introspection, configure
`IntrospectionConfig` and call `validate_active`. That method validates the introspection
response. It does not first run local JWT validation. See the
[Python example](python/README.md#token-validator).

Every port has the same shape (TypeScript `@idpartners/client-attestation-sdk/validator`, Go
`tokenvalidator`, Java `global.idpartners.clientattestation.tokenvalidator`, see the
[Java README](java/README.md#resource-server-validate-an-access-token)). `validate` runs a fixed
error-precedence order - identical across all ports so their verdicts match:
structure → algorithm → key → signature → payload → `typ` → `iss` → `exp` / `nbf` / `iat` → audience →
scope → `sub`, returning the first failure's stable code (`invalid_signature`, `invalid_issuer`, `expired`,
`not_yet_valid`, `invalid_audience`, `insufficient_scope`, …). `alg: none` and the `HS*` algorithms are
refused even if configured, and a failed introspection call raises (Go: returns an error) rather than
returning a verdict. [`validation/SEMANTICS.md`](validation/SEMANTICS.md) is the precise contract.

`validate` (and `validate_active`) is token validation, not an authorization decision. It doesn't look at
`cnf`, so a DPoP- or mTLS-bound token is `valid` without its sender proof. Refuse a token with a `cnf`
claim unless you verify that proof, or use `ProtectedResource.authenticate` (below; `authenticate_active`
for introspected tokens) as the request guard.

## Resource server for MCP / A2A

The validator is protocol-neutral OAuth resource-server validation, so it already does what an **MCP server**
or **A2A agent** must - verify the token and enforce audience + scope. `ProtectedResource` adds the HTTP
conventions on top: RFC 9728 protected-resource metadata, RFC 6750 bearer extraction + `WWW-Authenticate`
challenges, and a request guard that binds the token to this resource (RFC 8707) and maps failures to 401/403.
The guard is for Bearer tokens: it refuses a token carrying a `cnf` claim (DPoP- or mTLS-bound), because
it never sees the sender proof. To accept those, verify the proof yourself and call `validate`.

```python
from client_attestation_sdk.token_validator import AccessTokenValidator, ProtectedResource, ValidatorConfig

validator = AccessTokenValidator(ValidatorConfig(
    issuer="https://as.example.com", audiences=["https://mcp.example.com/mcp"],  # audience = this server
    jwks_uri="https://as.example.com/jwks", required_scopes=["mcp:call"]))
resource = ProtectedResource("https://mcp.example.com/mcp", ["https://as.example.com"], validator)

# Integration fragment: your HTTP server supplies authorization_header, handle and reply.
# serve resource.metadata() at resource.metadata_path() -> /.well-known/oauth-protected-resource/mcp
decision = resource.authenticate(authorization_header)          # or .authenticate(hdr, ["extra:scope"])
if decision.authorized:
    handle(decision.result.subject, decision.result.scopes)
else:
    reply(decision.status, {"WWW-Authenticate": decision.www_authenticate})   # 401 or 403
```

`ProtectedResource` handles Bearer requests. Since 1.0.1 it requires this resource in the token's
audience, even when the validator accepts several, and it refuses a token whose `cnf` claim is non-null (DPoP-bound, mTLS-bound or malformed) with 401, because
it receives no sender proof. To accept sender-constrained tokens, verify the proof in the resource's
authentication layer and call `validate` directly. See the
[resource reference](docs/configuration/resource.md).
The [example guide](docs/examples.md#protected-resource-examples) lists the Python, TypeScript and
Go demonstration servers. Java provides the integration API. These programs demonstrate metadata
and authentication. They implement no MCP tools or A2A methods.

## Not production keys

The fixed keys in `vectors/inputs.json` and `validation/tokens.json` exist **only** so the ports produce
identical, comparable artifacts for the interop checks. They are throwaway test-vector keys - never use them
for anything real.
