# client-attestation-sdk (TypeScript)

Client-side builder SDK for **OAuth Attestation-Based Client Authentication**
(`draft-ietf-oauth-attestation-based-client-auth`). Mints the three artifacts a client
presents at the token endpoint:

- **Client Attestation JWT** (`typ=oauth-client-attestation+jwt`) — issued by a Client Attester,
  names the client (`sub` = `client_id`) and binds its instance key via `cnf.jwk`.
- **Client Attestation PoP JWT** (`typ=oauth-client-attestation-pop+jwt`) — proves possession of
  the instance key (PoP method `attestation_pop_jwt`).
- **DPoP proof JWT** (`typ=dpop+jwt`) — combined mode (PoP method `dpop_combined`); its embedded
  `jwk` header is the instance key bound in the attestation's `cnf`.

This is one port of a polyglot SDK; it emits byte-compatible artifacts with the Java and Python
ports and is judged by a shared Java verifier. Built on [panva `jose`](https://github.com/panva/jose).
`kid` values are RFC 7638 JWK thumbprints (SHA-256, base64url); `iat`/`exp` are integer epoch seconds.

## Install / build

Requires **Node 20+**, or an edge runtime with WebCrypto and `fetch` (Cloudflare Workers, Vercel Edge,
Deno Deploy) with no Node compatibility layer needed. Crypto, encoding and HTTP use web-standard APIs, and
nothing imports a Node built-in at load time, so the builders, the one-call `ClientAttestation` flow, the
issuance client and the token validator all work on the edge.

Evidence gathering is the part that needs Node. Each of these loads the built-in it needs on first use; the
two sources throw a `ClientAttestationError` naming themselves from `fetch` on a runtime without it:

- `SpireWorkloadApiSvidSource` runs the `spire-agent` CLI (`node:child_process`);
- `FileTokenSvidSource` reads a projected token file (`node:fs`);
- `autoDetectEvidence` reads environment variables and probes for token files and the SPIRE socket. On
  the edge those all read as absent, so it falls through to the GCP metadata server and then throws
  `EvidenceNotFound`. Pass an explicit `SvidSource` to `ClientAttestation` there: `StaticSvidSource`,
  your own, or `HttpSvidSource` in development.

```bash
npm install @idpartners/client-attestation-sdk
```

To build from a clone:

```bash
npm install
npm run build   # tsc -> dist/
```

## Usage

jose's crypto is async, so key factories and `build()` return promises.

```ts
import {
  ClientAttestationBuilder,
  ClientAttestationCredential,
  SigningKeyPair,
} from "client-attestation-sdk";

// Attester side: issue the attestation.
const attester = await SigningKeyPair.generate("ES256");     // or SigningKeyPair.fromJwk(jwk, "ES256")
const instance = await SigningKeyPair.generate("ES256");     // the client's instance key
const attestation = await new ClientAttestationBuilder(attester, "https://attester.example.com")
  .clientId("https://rp.example.com")
  .confirmationKey(instance)
  .expiresIn(300)
  // optional: .authorizationDetails(...) / .workload(...) / .operator(sub, issuer?) —
  // operator names who's accountable for running the client (RFC 8693 may_act-shaped; an
  // assertion, not proof of authorisation), distinct from clientId and from the principal.
  .build();

// Client side: produce token-request headers.
const cred = new ClientAttestationCredential(attestation, instance);

const popHeaders = await cred.popHeaders("https://rp.example.com", "https://as.example.com");
// { "OAuth-Client-Attestation": "...", "OAuth-Client-Attestation-PoP": "..." }

const dpopHeaders = await cred.dpopHeaders("POST", "https://as.example.com/as/token.oauth2");
// { "OAuth-Client-Attestation": "...", "DPoP": "..." }
```

The one-call `ClientAttestation` orchestration class (see the [root README](../README.md#get-a-token-in-one-call))
wraps this: `{ popMethod: "dpop_combined" }` in its options switches it to DPoP mode, and a fetched
challenge is carried through automatically as the PoP JWT's `challenge` claim or the DPoP proof's `nonce`
claim, whichever mode is active. `operator: {...}` asks the attester to state the client's operator: it
goes in the mint request and, repeated as compact sorted-key JSON, in the token request's `operator` form
parameter. `DRAFT_REVISION` names the draft revision implemented (`"10"`).

### Presenting the token at a resource

```ts
const ca = new ClientAttestation("pf.example.com", { popMethod: "dpop_combined" });
await ca.fetch("https://api.example.com/things");                     // headers + one nonce retry
const headers = await ca.requestHeaders("GET", "https://api.example.com/things");
```

`requestHeaders(method, url)` returns what to send for one request. For a Bearer token that is just
`Authorization: Bearer <t>`. When the AS answers `token_type: DPoP` (normal in `dpop_combined` mode) the
token is bound to the instance key that minted the attestation, so the SDK keeps that key with the cached
token and returns `Authorization: DPoP <t>` plus a fresh `DPoP` proof (`htm`, `htu` without query or
fragment, `ath`, and the last `DPoP-Nonce` that origin sent). `authorizationHeader()` still works, but for
a DPoP-bound token it returns only the `DPoP` scheme - a resource will also want the proof.

`ca.fetch` resends once when a resource answers with a `use_dpop_nonce` challenge (401
`WWW-Authenticate: DPoP error="use_dpop_nonce"`, or a 400 JSON error) and a `DPoP-Nonce`. String,
`URLSearchParams`, `ArrayBuffer` and `Request` bodies are resent; a one-shot `ReadableStream` body is not,
and the challenge response is returned instead. The token request itself retries once on an AS's
`use_dpop_nonce` demand.

### Failing closed

- If the attester advertises a `challenge_endpoint` and the challenge cannot be fetched, `token()` throws
  `ClientAttestationError`. Pass `requireChallenge: false` to mint without one instead.
- `CLIENT_ATTESTATION_TOKEN_FILE` or `SPIFFE_ENDPOINT_SOCKET` pointing at a missing path throws
  `EvidenceNotFound` naming the variable - it never falls through to another identity source.
- `challengeAtToken: false` keeps the attester challenge in the mint's instance proof but leaves it out
  of the token-endpoint PoP `challenge` claim / DPoP `nonce` - for attesters that consume a challenge at
  mint and reject it when the token request presents it again.
- The PingFederate host and every endpoint the attester advertises must be `https`, except loopback
  (`localhost`, `127.0.0.1`, `::1`). Pass `allowInsecure: true` for, say, an in-cluster plain-http PF.

The validator's `ProtectedResource` strips control characters from every quoted `WWW-Authenticate` value,
and validation failures never echo the token's own `alg`, `kid`, `iss` or `aud` back in
`error_description`.

## Test & interop

```bash
npm test        # vitest — self-verifies each artifact with jose
npm run emit    # writes ../vectors/out/typescript.json for the cross-language Java verifier
```
