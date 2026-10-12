# client-attestation-sdk (TypeScript)

Client-side builder SDK for **OAuth Attestation-Based Client Authentication**
(`draft-ietf-oauth-attestation-based-client-auth`). Mints the three artifacts a client
presents at the token endpoint:

- **Client Attestation JWT** (`typ=oauth-client-attestation+jwt`) - issued by a Client Attester,
  names the client (`sub` = `client_id`) and binds its instance key via `cnf.jwk`.
- **Client Attestation PoP JWT** (`typ=oauth-client-attestation-pop+jwt`) - proves possession of
  the instance key (PoP method `attestation_pop_jwt`).
- **DPoP proof JWT** (`typ=dpop+jwt`) - combined mode (PoP method `dpop_combined`); its embedded
  `jwk` header is the instance key bound in the attestation's `cnf`.

This is one port of a polyglot SDK; it emits wire-compatible artifacts with the Java, Python and Go
ports and is judged by a shared Java verifier. Built on [panva `jose`](https://github.com/panva/jose).
`kid` values are RFC 7638 JWK thumbprints (SHA-256, base64url); `iat`/`exp` are integer epoch seconds.

## Install

Requires **Node 20+**, or an edge runtime with WebCrypto and `fetch` (Cloudflare Workers, Vercel Edge,
Deno Deploy) with no Node compatibility layer needed. Crypto, encoding and HTTP use web-standard APIs, and
nothing imports a Node built-in at load time, so the builders, the one-call `ClientAttestation` flow, the
issuance client and the token validator all work on the edge.

CI tests this in a real Workers runtime: `npm run test:edge` bundles the sources as an edge bundler would
and runs them in [`workerd`](https://github.com/cloudflare/workerd), Cloudflare's open-source Workers runtime
(1.20261007.1, compatibility date 2026-10-01, Node compatibility switched off). It generates keys, builds an
attestation, a PoP and a DPoP proof, runs the token validator against the shared validation vectors, and
checks `autoDetectEvidence` and `HttpSvidSource` there. The one-call flow and the issuance client are not
run in workerd. Vercel Edge and Deno Deploy are not tested directly.

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

The package is ESM only (`"type": "module"`, no `require` export), so load it with `import`.

To build from a clone:

```bash
cd typescript   # from the repository root
npm ci
npm run build   # tsc -> dist/
```

The package exports ESM. Import from `@idpartners/client-attestation-sdk` or
`@idpartners/client-attestation-sdk/validator`.

## Get a token and call an API

The attester must trust the workload identity and map it to an authorised client.
Set `CLIENT_ATTESTATION_TOKEN_FILE` to an identity token file with the attester's evidence
audience. `ATTESTER_URL`, `EVIDENCE_AUDIENCE` and `API_URL` are application variables.
`EVIDENCE_AUDIENCE` is the audience your identity token carries, and the attester's discovery document must
name it too.

```bash
export ATTESTER_URL=https://attester.example.com
export EVIDENCE_AUDIENCE=https://attester.example.com/evidence
export API_URL=https://api.example.com/data
export CLIENT_ATTESTATION_TOKEN_FILE=/absolute/path/to/identity-token.jwt
```

Save as `call-api.mjs` in the application that installed the package:

```js
import { ClientAttestation } from "@idpartners/client-attestation-sdk";

const ca = new ClientAttestation(process.env.ATTESTER_URL, { evidenceAudience: process.env.EVIDENCE_AUDIENCE });
const response = await ca.fetch(process.env.API_URL);
if (!response.ok) throw new Error(`API returned HTTP ${response.status}`);
console.log(response.status);
```

Run `node call-api.mjs`. Retain `ca` for later calls so it reuses the token cache.
`ca.fetch` attaches the access token and a DPoP proof when required. DPoP binds the token to
a client key and requires a signed proof for each request.
See [Configuration](../docs/configuration.md) for the options and evidence sources.

## Build a credential offline

jose's crypto is async, so key factories and `build()` return promises.
This complete example generates temporary keys and needs no server.

```ts
import {
  ClientAttestationBuilder,
  ClientAttestationCredential,
  SigningKeyPair,
} from "@idpartners/client-attestation-sdk";

// Attester side: issue the attestation.
const attester = await SigningKeyPair.generate("ES256");     // or SigningKeyPair.fromJwk(jwk, "ES256")
const instance = await SigningKeyPair.generate("ES256");     // the client's instance key
const attestation = await new ClientAttestationBuilder(attester, "https://attester.example.com")
  .clientId("https://rp.example.com")
  .confirmationKey(instance)
  .expiresIn(300)
  .build();

// Client side: produce token-request headers.
const cred = new ClientAttestationCredential(attestation, instance);

const popHeaders = await cred.popHeaders("https://rp.example.com", "https://as.example.com");
// { "OAuth-Client-Attestation": "...", "OAuth-Client-Attestation-PoP": "..." }

const dpopHeaders = await cred.dpopHeaders("POST", "https://as.example.com/as/token.oauth2");
// { "OAuth-Client-Attestation": "...", "DPoP": "..." }
console.log(Object.keys(popHeaders), Object.keys(dpopHeaders));
```

Save as `build-credential.mjs` and run `node build-credential.mjs` after installing the package.
The code also runs as TypeScript. A production authorisation server must trust the attester's
signing key before it accepts a credential.

The one-call `ClientAttestation` orchestration class (see the [root README](../README.md#get-a-token-in-one-call))
wraps this: `{ popMethod: "dpop_combined" }` in its options switches it to DPoP mode, and a fetched
challenge is carried through automatically as the PoP JWT's `challenge` claim or the DPoP proof's `nonce`
claim, whichever mode is active. `operator: {...}` asks the attester to state the client's operator: it
goes in the mint request and, repeated as compact sorted-key JSON, in the token request's `operator` form
parameter. `DRAFT_REVISION` names the draft revision implemented (`"10"`).

### Presenting the token at a resource

```ts
import { ClientAttestation } from "@idpartners/client-attestation-sdk";

const ca = new ClientAttestation("pf.example.com", {
  evidenceAudience: "https://attester.example.com", // the audience your attester expects the identity token for
  popMethod: "dpop_combined",
});
await ca.fetch("https://api.example.com/things");                     // headers + one nonce retry
const headers = await ca.requestHeaders("GET", "https://api.example.com/things");
```

`requestHeaders(method, url)` returns what to send for one request. For a Bearer token that is just
`Authorization: Bearer <t>`. When the AS answers `token_type: DPoP` (normal in `dpop_combined` mode) the
token is bound to the instance key that minted the attestation, so the SDK keeps that key with the cached
token and returns `Authorization: DPoP <t>` plus a fresh `DPoP` proof (`htm`, `htu` without query or
fragment, `ath`, and the last `DPoP-Nonce` that origin sent). `authorizationHeader()` still works, but for
a DPoP-bound token it returns only the `DPoP` scheme - a resource will also want the proof.

For a DPoP-bound token, `ca.fetch` resends once when a resource answers with a `use_dpop_nonce` challenge (401
`WWW-Authenticate: DPoP error="use_dpop_nonce"`, or a 400 JSON error) and a `DPoP-Nonce`. String,
`URLSearchParams`, `ArrayBuffer` and `Request` bodies are resent; a one-shot `ReadableStream` body is not,
and the challenge response is returned instead. `ca.fetch` uses the global `fetch` with
`redirect: "manual"`, so a redirect comes back to you and credentials are never resent to its target. In
`dpop_combined` mode the token request itself retries once when the AS answers 400 `use_dpop_nonce` with
a `DPoP-Nonce`.

### Failing closed

- If the attester advertises a `challenge_endpoint` and the challenge cannot be fetched, `token()` throws
  `ClientAttestationError`. Pass `requireChallenge: false` to mint without one instead.
- `CLIENT_ATTESTATION_TOKEN_FILE` or `SPIFFE_ENDPOINT_SOCKET` pointing at a missing path throws
  `EvidenceNotFound` naming the variable - it never falls through to another identity source. Auto-detect
  checks `CLIENT_ATTESTATION_SVID` first, then the token file, then the SPIRE socket, so a variable is
  only checked if nothing before it matched. `EvidenceNotFound` extends `Error`, not
  `ClientAttestationError`.
- `challengeAtToken: false` keeps the attester challenge in the mint's instance proof but leaves it out
  of the token-endpoint PoP `challenge` claim / DPoP `nonce` - for attesters that consume a challenge at
  mint and reject it when the token request presents it again.
- The attester URL and every endpoint the attester advertises must be `https`, except loopback
  (`localhost`, `127.0.0.1`, `::1`). Pass `allowInsecure: true` for, say, an in-cluster plain-http PF.
  `AttestationIssuanceClient.create` (its endpoint and every call its profile makes) and
  `OpenBaoTransitSigner.create` (the vault address) follow the same rule and take the same `allowInsecure`
  option.

### Other attesters

`ClientAttestation` speaks PingFederate's discovery and mint protocol by default. For another attester,
pass the `profile` option (your own `AttesterProfile`), or the `metadata` option to give its endpoints
directly and skip discovery: `new ClientAttestation({ metadata: { evidenceAudience, attestationEndpoint,
tokenEndpoint } })`. `AttestationIssuanceClient.create` takes `{ profile }` too. See
[`docs/attester-profiles.md`](../docs/attester-profiles.md).

## Resource server: validate an access token

The validator is the second entry point, `@idpartners/client-attestation-sdk/validator`. The order of
checks and the error codes are shared with the other ports and pinned by
[`validation/SEMANTICS.md`](../validation/SEMANTICS.md).

```ts
import { AccessTokenValidator, ProtectedResource } from "@idpartners/client-attestation-sdk/validator";

const validator = new AccessTokenValidator({
  issuer: "https://issuer.example.com",
  audiences: ["https://api.example.com"],
  jwksUri: "https://issuer.example.com/jwks",
  requiredScopes: ["read"],
});
const result = await validator.validate(accessToken);
if (!result.valid) console.log(result.error);   // e.g. "expired", "insufficient_scope"
// validate() ignores cnf: refuse result.claims.cnf unless you verify the sender proof (see below)

const resource = new ProtectedResource("https://api.example.com", ["https://issuer.example.com"], validator);
const decision = await resource.authenticate(request.headers.get("authorization"));
// decision.status is 401, or 403 for missing scope; send decision.wwwAuthenticate back
```

By default a token's header `typ`, when present, must be `at+jwt`; pass `acceptedTokenTypes: null` for an
issuer that stamps something else. `jwksUri` and the introspection `endpoint` must use https unless their
host is loopback (`localhost`, `127.0.0.1`, `::1`); `allowInsecure: true` lifts that.

`validate` checks the token only. It doesn't look at `cnf`, so a DPoP- or mTLS-bound token is `valid`
without its sender proof: refuse one unless you verify that proof. `ProtectedResource.authenticate` is the
request guard, and it refuses a token with a `cnf` claim with 401, because it never sees the sender proof.
A runnable server is in
[`examples/protected-resource-server.ts`](examples/protected-resource-server.ts).

The validator's `ProtectedResource` strips control characters from every quoted `WWW-Authenticate` value,
and validation failures never echo the token's own `alg`, `kid`, `iss` or `aud` back in
`error_description`.

## Token validator

This fragment runs inside a resource-server request handler that supplies `accessToken`:

```ts
import { AccessTokenValidator } from "@idpartners/client-attestation-sdk/validator";

const validator = new AccessTokenValidator({
  issuer: "https://issuer.example.com",
  audiences: ["https://api.example.com"],
  jwksUri: "https://issuer.example.com/jwks",
  requiredScopes: ["read"],
});

// In the handler:
// const result = await validator.validate(accessToken);
// if (!result.valid) reject(result.error);
```

`validate` checks the JWT signature and claims. `validateActive` uses RFC 7662 introspection
with configured resource-server credentials. It does not first run `validate`.
See [resource configuration](../docs/configuration.md#resource-server-configuration) and the
[resource-server example](../docs/examples.md#protected-resource-examples).
`ProtectedResource.authenticate` handles Bearer requests. It does not verify DPoP proofs.

## Build, test and package

```bash
npm test        # vitest - self-verifies each artifact with jose
npm run coverage
npm run test:edge   # the same SDK in workerd, Cloudflare's Workers runtime, with no Node compatibility
npm run build
npm pack        # builds and creates a local .tgz archive; does not publish
npm run emit    # writes ../vectors/out/typescript.json for the cross-language Java verifier
```

Run these from `typescript/`. See [Build and test](../docs/building.md#typescript) for outputs
and cross-language checks, [Examples](../docs/examples.md) for server prerequisites, and
[Deployment](../docs/deployment.md) for deploying an application with the SDK.
