# client-attestation-sdk

Agent-side OAuth SDKs in **Java, Python, TypeScript, and Go** — for authenticating agents and workloads on
common runtimes (LangChain, ADK, Node 20+ and edge runtimes, JVM and Go services, and Bedrock AgentCore
from Python). Three capabilities:

For a visual tour — architecture diagrams, the full feature-support matrix across all four languages, and
the standards this SDK implements — open [`docs/explainer.html`](docs/explainer.html), one offline page.

1. **Get a token, in one call** *(all four languages)* — point it at a PingFederate host and get an access
   token. It runs the whole flow (discover → get the workload's platform identity → mint the attestation →
   call the token endpoint) and caches the result. The workload sends no client secret and no client_id;
   its only credential is the attestation. See "Get a token in one call" below.
2. **Client attestation builder** *(all four languages)* — the lower-level pieces, if you want to build the
   credential yourself ([draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)):
   the Client Attestation JWT plus the proof of possession for auth method `attest_jwt_client_auth` —
   a dedicated PoP JWT (PoP method `attestation_pop_jwt`) or a DPoP proof (PoP method `dpop_combined`,
   draft -10 naming; formerly the separate `attest_jwt_client_auth_dpop` method) — and the request
   headers. Any of them can sign with a key held in a vault (`OpenBaoTransitSigner`). The attestation can
   also name an `operator` — the human or org accountable for running the client, distinct from `sub` and
   from the principal it acts for — an RFC 8693 `may_act`-shaped assertion, not proof of authorisation.
3. **Token validator + MCP/A2A resource helper** *(all four ports)* — the resource-server side:
   *validate* a token it receives — JWT signature via the issuer's JWKS, `iss`/`exp`/`nbf`, audience and
   scope — with optional RFC 7662 introspection, AS-metadata discovery, and RFC 9728 protected-resource
   metadata.
4. **Authorization-challenge handling** *(Python; parser vectors shared for the other ports)* — what an
   agent does when a policy enforcement point will not let a call proceed *as presented*. `parse_challenge`
   turns whatever the PEP said (a REST 401 + `WWW-Authenticate` + body, a JSON-RPC error from an MCP edge,
   an MCP tool result) into one typed challenge — **authn**, **resource authorisation** (RFC 9470 step-up),
   **consent**, **identity proofing**, **intent** — and `CibaResolver` runs the ceremony that resolves it:
   an OpenID CIBA push to the human's paired authenticator, polled at the AS's cadence, so the *same call,
   re-sent, is permitted*. `WebConsentResolver` is the no-device fallback (a URL the human completes behind
   the AS's login). See "Handling a challenge" below.

## Status and versioning

From 1.0.0 the SDK follows [semver](https://semver.org/). All four ports share one version and release
together. Every public name is in one of three tiers, listed port by port in [`docs/api.md`](docs/api.md):

- **Stable** API follows semver. A breaking change needs a major release. Anything Stable that is to be
  removed or renamed is deprecated for at least one minor release first, and goes in the next major.
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
- Install:

  | Language | Package | Install |
  |---|---|---|
  | Python | [PyPI](https://pypi.org/project/client-attestation-sdk/) | `pip install client-attestation-sdk` |
  | TypeScript | [npm](https://www.npmjs.com/package/@idpartners/client-attestation-sdk) | `npm install @idpartners/client-attestation-sdk` |
  | Go | [pkg.go.dev](https://pkg.go.dev/github.com/id-partners/client-attestation-sdk/go) | `go get github.com/id-partners/client-attestation-sdk/go` |
  | Java | [Maven Central](https://central.sonatype.com/artifact/global.idpartners/client-attestation-sdk) | `global.idpartners:client-attestation-sdk` – see the [Java README](java/README.md) |

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

Give it the attester's host (PingFederate by default; for another attester, see
[`docs/attester-profiles.md`](docs/attester-profiles.md)). It finds the workload's platform identity by
itself (a projected token file, a SPIRE socket, the GCP metadata server, or an env token — override with
`evidence=`), runs the attestation flow, and returns an access token. Use the token, or hand the SDK to your
HTTP client so every call carries it.

```python
from client_attestation_sdk import ClientAttestation

ca = ClientAttestation("pf.example.com")          # auto-detects the platform identity
token = ca.token()                                # access token, cached until it nears expiry

import requests
requests.get("https://api.example.com/x", auth=ca.requests_auth())   # attaches: Authorization: Bearer <token>

# Ask for a specific entitlement (RFC 9396); the attester grants at most what the workload is allowed:
ca = ClientAttestation("pf.example.com",
                       authorization_details=[{"type": "sales_agent", "sales_regions": ["EMEA"]}])

# Present a DPoP proof instead of a dedicated PoP JWT (PoP method dpop_combined):
ca = ClientAttestation("pf.example.com", pop_method="dpop_combined")
```

The PF host is enough because the attester's `/.well-known/client-attester` advertises the token endpoint
and the PoP audience. Nothing else is configured. Inside an agent (ADK, LangChain, Bedrock AgentCore), get
`ca.authorization_header()` and attach it in a tool's request or an ADK `header_provider` /
`before_tool_callback`. The same class exists in all four languages, `pop_method` included (Go/Java/TS:
`WithPopMethod("dpop_combined")` / `.popMethod("dpop_combined")` / `popMethod: "dpop_combined"`).

Either way, if the attester advertises a `challenge_endpoint`, the SDK fetches a fresh challenge and carries
it through automatically — as the PoP JWT's `challenge` claim in the default mode, or as the DPoP proof's
`nonce` claim in `dpop_combined` mode. You never have to plumb it through yourself.

To see what the flow is doing, turn on logging. It is off until you configure it, uses each language's own
logging (Python `logging`, Go `log/slog`, Java `System.Logger`, a `logger` option in TypeScript), and
never writes a token, proof, attestation or key. The events and their attributes are the same in every
port: see [`docs/logging.md`](docs/logging.md).

`java/` is the reference builder (formerly the standalone `client-attestation-sdk` repo). The **AS-side
verifier** that accepts these credentials is separate:
[client-attestation](https://github.com/dphhyland/client-attestation).

## Handling a challenge

An agent that calls a tool through a gateway will sometimes get, instead of a result, a *challenge*: the
policy needs something more before this call may proceed — a step-up authorisation for THIS payment, a
verified credential, an authenticated user. The status code alone cannot tell you which (this repo's
reference PEPs answer 401 both for "no user at all" and "user present, scope missing"), so the SDK
normalises first and resolves second:

```python
from client_attestation_sdk.authz_challenge import (
    parse_challenge, CibaClient, CibaResolver, PrivateKeyJwtAuth, Hooks,
    Pending, Resolved, Unavailable, CHANNEL_DEVICE)

ch = parse_challenge(resp.status_code, resp.headers, resp.text)     # -> Challenge | None
if ch and ch.type == "resource_authorisation":
    resolver = CibaResolver(
        CibaClient(bc_auth_endpoint=PF + "/as/bc-auth.ciba", token_endpoint=PF + "/as/token.oauth2",
                   client_id=AGENT_ID, issuer=PF_ISSUER,
                   client_auth=PrivateKeyJwtAuth(client_id=AGENT_ID, private_key_pem=PEM, kid=KID,
                                                 extra_audiences=(PF_ISSUER + "/as/token.oauth2", PF_ISSUER)),
                   request_signing_key_pem=PEM, request_signing_kid=KID),
        Hooks(channel_for=directory.channel_for,            # "device" | "web_consent" | "local"
              already_covered=directory.consent_covers,     # the PDP's own question — a stale challenge?
              register_for_device=approver.publish,         # the phone looks the ceremony up by its reference
              persist=directory.save, rehydrate=directory.load,   # survive a restart mid-approval
              on_outcome=directory.record))                 # approved/denied/expired -> where the PDP looks
    res = resolver.resolve(ch, subject=principal, initiator=AGENT_ID,
                           instruction={"amount": amount, "currency": cur, "debtor": src, "creditor": dst})
    # Pending  -> return {code, poll_url, interval, expires_in} to whoever called you; they poll
    #             resolver.poll(code) until approved/denied/expired, then RE-SEND the same call.
    # Resolved -> an authorisation already covers this instruction: just re-send.
    # Unavailable -> no channel to the human from here (fallback: "bubble_up" | "web_consent" | "enrol").
```

What the SDK owns: the challenge vocabulary, the CIBA wire protocol **and its pacing rules** (poll faster
than the AS's `interval` and PingFederate escalates `slow_down` → `invalid_request` → it *invalidates the
grant*, which looks exactly like "expired on device"), dedupe so one instruction never buzzes the phone
twice, a settle window so a stronger out-of-band verdict from the device is not overwritten by the poll,
and `verify_resume` — the re-sent call must hash to the instruction the human approved, byte for byte.
What the deployment owns, via `Hooks`: its device registry, its consent directory, its approver app.

The approval is a **signal, not a credential**: on PingFederate the CIBA grant's subject is fixed by a
default mapping, so the minted token is discarded and the *record* the deployment writes is what turns
the PDP's next answer into a permit. Client authentication is pluggable (`ClientAuth`); `private_key_jwt`
ships because that is what the deployed CIBA clients use — an attestation-based authenticator (capability
2) slots in behind the same interface once the AS accepts it on the backchannel endpoint.

**Ports.** The parser is pinned by [`validation/challenges.json`](validation/challenges.json) — 18 cases
mirroring the real PEP responses (Kong `authzen-pdp`, `coaz-pep`, the MCP servers' tool results) — and
only the Python parser runs them today. They are language-neutral on purpose: a port that adds a parser
must return the identical classification for every case. The resolvers are stateful, long-lived and
networked, which is exactly where a four-language SDK drifts, so they are Python-only for now and the
feature matrix says so.

## Proven interoperable

Every port is checked against the **real Java AS-side verifier**. Each builds credentials from the shared
[`vectors/inputs.json`](vectors/inputs.json) (fixed throwaway test keys) into `vectors/out/<lang>.json`, and
[`interop/VerifyInterop.java`](interop/VerifyInterop.java) runs each through `ClientAttestationVerifier` in
both PoP and DPoP modes. A Python-, TypeScript-, or Go-built credential is accepted by exactly the same AS
as a Java-built one. Reproduce with [`./verify-interop.sh`](verify-interop.sh).

**Validator** — every port validates the shared [`validation/tokens.json`](validation/tokens.json)
(pre-signed tokens, each with one defect: expiry and leeway, issuer, audience, scope, signature, `alg: none`
and HMAC key confusion, malformed and duplicate-keyed JSON, out-of-range dates, wrongly typed claims) and
[`validation/introspection.json`](validation/introspection.json) (canned RFC 7662 responses), and must
return the **identical verdict** for every case. [`validation/check.py`](validation/check.py) confirms all
four agree with the expected verdicts; [`validation/SEMANTICS.md`](validation/SEMANTICS.md) defines every
rule. Reproduce with [`./verify-validation.sh`](verify-validation.sh).

## Test coverage

Two layers, deliberately different in scope:

- **Cross-language agreement** (`./verify-interop.sh`, `./verify-validation.sh`, above) proves the four
  ports produce/accept byte-compatible artifacts against one shared verifier — but only for the
  **low-level builder/credential API** (`ClientAttestationBuilder`, `ClientAttestationCredential`,
  `AccessTokenValidator`) against fixed vectors. It does not exercise the one-call `ClientAttestation`
  orchestration class's own decisions (evidence auto-detection, discovery, challenge fetching, caching).
- **Per-language unit suites** (`go test ./...`, `mvn test`, `pytest`, `npm test` — see each language's
  README) cover that orchestration layer directly, including edge cases the shared vectors don't reach:
  malformed/expired tokens, unaccepted algorithms, signer/network failures, evidence auto-detect
  precedence, and — since the fixes described above — that a fetched challenge actually reaches the
  token-endpoint PoP JWT's `challenge` claim in the default mode, and the DPoP proof's `nonce` claim in
  `dpop_combined` mode, in both the one-call flow and the SPIFFE issuance-bootstrap flow.

Run everything before relying on a change: each language's own suite, then both `verify-*.sh` scripts.
CI runs all of it on every push and pull request except `verify-interop.sh` (see
[CONTRIBUTING.md](CONTRIBUTING.md)).

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
attester = SigningKeyPair.generate("ES256")
attestation = (ClientAttestationBuilder(attester, "https://attester.example.com")
               .client_id("https://rp.example.com").confirmation_jwk(instance_pub).expires_in(300).build())
headers = ClientAttestationCredential(attestation, instance).pop_headers(
    "https://rp.example.com", "https://as.example.com")
```

## Contract

All ports emit the same shapes (ES256; `kid` = RFC 7638 thumbprint; `iat`/`exp` integer epoch seconds):

| Artifact | `typ` | key in header | key claims |
|---|---|---|---|
| Attestation | `oauth-client-attestation+jwt` | `kid` (attester) | `iss, sub, iat, exp, cnf.jwk` (instance pub, +kid) |
| PoP | `oauth-client-attestation-pop+jwt` | `kid` (instance) | `aud, jti, iat` (+ optional `iss`, `challenge`) |
| DPoP | `dpop+jwt` | `jwk` (instance pub, −kid) | `htm, htu, jti, iat` (+ optional `nonce`) |

## Bootstrapping from SPIFFE (attestation issuance)

The inverse of the builder: instead of holding an attester key and building an attestation locally, a
workload proves its **SPIFFE identity** (a JWT-SVID) and the Authorization Server (PingFederate's
`/federation/attestation` servlet) **mints** a Client Attestation bound to the workload's own instance
key. A client credential bootstrapped from infra identity — no pre-shared secret. All four ports ship an
`AttestationIssuanceClient` + a pluggable `SvidSource` (default: a real SPIRE agent's Workload API;
`Static`/`Http` for tests + the demo harness).

```python
client = AttestationIssuanceClient(
    endpoint="https://pf/federation/attestation", client_id="https://agent.example",
    attester_issuer="https://attester.example", svid_source=SpireWorkloadApiSvidSource())
issued = client.bootstrap(authorization_details=[{"type": "sales_agent", "sales_regions": ["EMEA"]}])
headers = {"OAuth-Client-Attestation": issued.attestation,           # minted by the AS
           "OAuth-Client-Attestation-PoP": issued.pop(token_endpoint_aud)}   # signed by the bound instance key

# ...or DPoP combined mode instead of the dedicated PoP JWT:
headers = {"OAuth-Client-Attestation": issued.attestation,
           "DPoP": issued.dpop("POST", token_endpoint_url)}
```

Both `pop(...)` and `dpop(...)` take an optional trailing `challenge` — pass one through if the AS gave you
one; it lands as the PoP JWT's `challenge` claim or the DPoP proof's `nonce` claim, matching whichever mode
you built.

Runnable examples per language (`examples/attestation_issuance_bootstrap.*`, and Go
`cmd/issuance-bootstrap`), each verified end-to-end against the demo issuance servlet
(`pf-oidf-modules/demo/spiffe-bootstrap`): SVID → minted attestation → token.

## Signing keys outside the process (Vault / HSM)

The attester's issuing key doesn't have to live in the client. `OpenBaoTransitSigner` signs the attestation
inside an OpenBao / HashiCorp Vault transit engine (`marshaling_algorithm=jws`), so the private key never
leaves the vault — pass it to the builder in place of a local key:

```python
signer = OpenBaoTransitSigner("http://openbao:8200", vault_token, "attestation-es256")
attestation = (ClientAttestationBuilder(signer, "https://attester.example.com")
               .client_id("https://rp.example.com").confirmation_key(instance).expires_in(300).build())
# a verifier registers signer.public_jwk() (kid = the key's RFC 7638 thumbprint)
```

Same in every language — TS: `await OpenBaoTransitSigner.create(addr, token, key)`; Go:
`NewClientAttestationBuilderWithSigner(signer, issuer)`. Any key store fits the `JwsSigner` interface:
implement `sign(signingInput) → raw r‖s` and plug it in.

## Token validation (resource server)

The validator side mirrors the same config→act shape. Representative flow (Python):

```python
from client_attestation_sdk.token_validator import AccessTokenValidator, ValidatorConfig

validator = AccessTokenValidator(ValidatorConfig(
    issuer="https://issuer.example.com", audiences=["https://api.example.com"],
    jwks_uri="https://issuer.example.com/jwks", required_scopes=["read"]))

result = validator.validate(access_token)          # local: signature + iss/exp/nbf + audience + scope
if result.valid:
    print(result.subject, result.scopes)
# optional RFC 7662 revocation / opaque-token check:
result = validator.validate_active(access_token)   # introspection
```

Java has the same shape (`global.idpartners.clientattestation.tokenvalidator`, see the
[Java README](java/README.md#resource-server-validate-an-access-token)). `validate` runs a fixed
error-precedence order — identical across all ports so their verdicts match:
structure → algorithm → key → signature → payload → `typ` → `iss` → `exp` / `nbf` / `iat` → audience →
scope → `sub`, returning the first failure's stable code (`invalid_signature`, `invalid_issuer`, `expired`,
`not_yet_valid`, `invalid_audience`, `insufficient_scope`, …). `alg: none` and the `HS*` algorithms are
refused even if configured, and a failed introspection call raises (Go: returns an error) rather than
returning a verdict. [`validation/SEMANTICS.md`](validation/SEMANTICS.md) is the precise contract.

## Resource server for MCP / A2A

The validator is protocol-neutral OAuth resource-server validation, so it already does what an **MCP server**
or **A2A agent** must — verify the token and enforce audience + scope. `ProtectedResource` adds the HTTP
conventions on top: RFC 9728 protected-resource metadata, RFC 6750 bearer extraction + `WWW-Authenticate`
challenges, and a request guard that binds the token to this resource (RFC 8707) and maps failures to 401/403.

```python
from client_attestation_sdk.token_validator import AccessTokenValidator, ProtectedResource, ValidatorConfig

validator = AccessTokenValidator(ValidatorConfig(
    issuer="https://as.example.com", audiences=["https://mcp.example.com/mcp"],  # audience = this server
    jwks_uri="https://as.example.com/jwks", required_scopes=["mcp:call"]))
resource = ProtectedResource("https://mcp.example.com/mcp", ["https://as.example.com"], validator)

# serve resource.metadata() at resource.metadata_path()  →  /.well-known/oauth-protected-resource
decision = resource.authenticate(authorization_header)          # or .authenticate(hdr, ["extra:scope"])
if decision.authorized:
    handle(decision.result.subject, decision.result.scopes)
else:
    reply(decision.status, {"WWW-Authenticate": decision.www_authenticate})   # 401 or 403
```

Per the [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
that's the entire resource-server duty (OAuth 2.1 + RFC 9728 / 8414 / 8707); only the last-mile middleware
wiring into a given server framework is platform-specific — a runnable, dependency-free example ships in each
language's `examples/`. The same `ProtectedResource` serves A2A agents, whose Agent Cards just declare an
OAuth2/bearer scheme.

## Not production keys

The fixed keys in `vectors/inputs.json` and `validation/tokens.json` exist **only** so the ports produce
identical, comparable artifacts for the interop checks. They are throwaway test-vector keys — never use them
for anything real.
