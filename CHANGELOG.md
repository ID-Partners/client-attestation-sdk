# Changelog

All four ports share one version number. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [semver](https://semver.org/) as described under "Status and versioning" in the README.

## [Unreleased]

## [1.0.1] - 2026-10-10

A security release. Upgrade from 1.0.0. Two fixes change what some callers see - check these before you
upgrade:

- A resource that accepts DPoP-bound or mTLS-bound access tokens through `ProtectedResource.authenticate`
  now gets HTTP 401 for them. That guard receives no sender proof, so it can't accept them safely. Verify
  the proof yourself and call `validate` directly.
- Java: a credential request on an `HttpClient` built with `Redirect.NORMAL` or `Redirect.ALWAYS` now
  throws `IllegalArgumentException`. Build the client with `HttpClient.Redirect.NEVER`, which is the
  `HttpClient` default.

### Fixed

- All four ports: `ProtectedResource.authenticate` checks this resource's audience when its validator
  accepts multiple audiences. Tokens naming only another resource return HTTP 401.
- All four ports: the Bearer `ProtectedResource.authenticate` guard refuses tokens with a non-null `cnf`
  claim. Sender-constrained tokens require separate proof verification before a resource grants access.
- Go: SDK HTTP calls refuse redirects even when an injected client's redirect policy permits them.
- TypeScript: `ClientAttestation.fetch` returns redirects without resending credentials to the target.
- Java: credential send helpers require `HttpClient.Redirect.NEVER` before obtaining or sending credentials.

## [1.0.0] - 2026-10-08

The first stable release. The public API of every port is frozen under semver: [`docs/api.md`](docs/api.md)
says what is Stable, what is Experimental and what is internal, and CI fails on any change to it that isn't
deliberate. Coming from 0.3.0, read Changed and Removed below; every break is listed there.

### Added

- **The 1.0 API, frozen and written down.** [`docs/api.md`](docs/api.md) puts every public name in each
  port into one of three tiers: Stable (semver from 1.0.0), Experimental (may change in any minor
  release; each item is marked in its doc comment and listed with the reason) and Internal (not API). See
  "Status and versioning" in the README for the policy.
- **API snapshots that CI checks.** `scripts/api_surface.py` writes each port's public API from the real
  build to `docs/api-surface/{python,typescript,go,java}.txt`, and each port's CI job runs it with
  `--check`, which fails and prints the diff if the build no longer matches. An intended API change
  regenerates the snapshot in the same pull request (see CONTRIBUTING.md).
- Java: a `module-info.java` (module `global.idpartners.clientattestation`) that exports the API packages
  and not `internal`. It `requires transitive org.jose4j` and `java.net.http`.
- Java: `SigningKeyPair.fromJwk(Map<String, Object>, String)`, so a key can be loaded without jose4j types.
- Java: `ClientAttestation.LOGGER_NAME`. Go: `tokenvalidator.HTTPGetFunc` and `HTTPPostFunc`, the types
  `WithHTTPGet` and `WithHTTPPost` already took. TypeScript: the `AttesterDiscovery` type that
  `discovery()` returns.
- **Attester profiles in all four ports.** The attester-specific steps – discovering the attester's
  endpoints and building, sending and reading the mint request (including the instance proof and its
  `typ`) – now belong to an `AttesterProfile`. The built-in `PingFederateProfile` is the default and is
  exactly the previous behaviour, byte for byte on the wire. The draft-defined parts (challenge, PoP or DPoP
  proof, token request, nonce retry, caching, https rule) stay in the client, and the log events keep their
  names. See [`docs/attester-profiles.md`](docs/attester-profiles.md).
  - Static endpoints for an attester with no discovery document: `metadata=AttesterMetadata(...)` (Python),
    the `metadata` option (TypeScript), `WithAttesterMetadata` (Go), `.metadata(...)` (Java). No discovery
    request is made, and the attester URL becomes optional.
  - A custom profile: `profile=` (Python), the `profile` option (TypeScript), `WithAttesterProfile` (Go),
    `.profile(...)` (Java). `AttestationIssuanceClient` takes one too.
  - New types in each port: `AttesterProfile`, `PingFederateProfile`, `AttesterMetadata`, `AttesterTransport`,
    `MintRequest` (with `instance_proof` / `sign` helpers) and `MintResult`; and `attester_metadata()` /
    `attesterMetadata()` on the one-call client (Go's `Discovery` now returns `*AttesterMetadata`).
- TypeScript: `new ClientAttestation(options)` with the URL as `options.attesterUrl`, or none at all with
  static `metadata`. Java: `ClientAttestation.builder()` with no URL, and `Builder.attesterUrl(...)`.
- **Java: the resource-server token validator**, closing the last gap between the ports.
  `global.idpartners.clientattestation.tokenvalidator` has `AccessTokenValidator` (JWT validation with the
  same check order, stable error codes and defaults as Python, TypeScript and Go, plus RFC 7662
  introspection), JWKS caching with the same refetch cooldown, single flight, max age and size cap,
  `Discovery.discover` for AS metadata, and `ProtectedResource` for RFC 9728 metadata, bearer extraction
  and `WWW-Authenticate` challenges. It logs the same validator events through a `System.Logger` passed to
  `AccessTokenValidator.builder(config).logger(...)`. `./verify-validation.sh` now checks all four ports
  agree on the shared vectors, and CI's validation job has a JDK for it.
- **[`validation/SEMANTICS.md`](validation/SEMANTICS.md)**, the precise contract every port's validator
  implements, and 101 new shared vectors that pin it: 93 token cases (up from 11) and 19 introspection
  cases. `./verify-validation.sh` now also runs each port's `validate_active` against canned RFC 7662
  responses.
- **An injectable validator clock in every port**: Python `AccessTokenValidator(config, clock=...)` (epoch
  seconds), TypeScript `{ clock }` (epoch milliseconds), Go `WithClock(func() time.Time)` and Java
  `AccessTokenValidator.Builder.clock(...)` (now public).
- **Go: `Config.ZeroLeeway`**, because `LeewaySeconds: 0` still means the 60-second default.

### Changed

- **Go: `ClientAttestation.Discovery(ctx)` is renamed `AttesterMetadata(ctx)`**, the name every other port
  uses for the same thing. Breaking: there is no alias, because the next release is 1.0.
- **Go: `tokenvalidator.DefaultAlgorithms` and `DefaultTokenTypes` are functions** that return a new
  slice each call. They were exported slices that any importer could change to widen what a default
  validator accepted. Breaking: `DefaultAlgorithms` becomes `DefaultAlgorithms()`.
- **Go: `DefaultTokenFile` and `DefaultSpiffeSocket` are constants.** They were variables, so any importer
  could change where evidence auto-detection looked. Breaking only for code that assigned to them.
- **Java: `HttpTransport` and `SdkLogging` moved to `global.idpartners.clientattestation.internal`** (as
  `HttpTransport` and `SdkLog`), which the module doesn't export. They were public only so the SDK's own
  packages could share them, and were never API. Breaking for code that imported them: use
  `ClientAttestation.LOGGER_NAME` for the logger name. `TransportException`'s constructors are now public.
- TypeScript: `DEFAULT_ALGORITHMS` and `DEFAULT_TOKEN_TYPES` are frozen arrays, so they can't be widened at
  run time. `autoDetectEvidence()` no longer shows its test-only options parameter in the types.
- Python: `ValidationResult.success` and `.failure` are now private (`_success`, `_failure`); the
  validator builds results and the other ports never exposed them.
- Marked **Experimental** (see docs/api.md for why): the attester-profile interface (`AttesterProfile`,
  `AttesterTransport`, `MintRequest`, `MintResult`), `OpenBaoTransitSigner`, the issuance client
  (`AttestationIssuanceClient`, `IssuedAttestation`, `IssuanceError`, `INSTANCE_PROOF_TYP`), the SPIRE CLI
  and HTTP SVID sources, the log event vocabulary, Java's jose4j-typed `SigningKeyPair` methods, and the
  Python-only `authz_challenge`, `spiffe` helpers, Azure and AWS sources, `trace` and `asserted_context`.
- **The four validators now agree on every malformed or hostile token.** Before this, the shared vectors
  only covered well-formed tokens, and the ports disagreed on 32 of the new shared-config cases. The verdicts
  users will see change:
  - A signed payload that isn't a JSON object (not JSON at all, or an array, string or `null`) is
    `invalid_token` everywhere. Python, TypeScript and Java said `invalid_signature` for some of these.
  - `alg: none` (any case) and every `HS*` algorithm are `unsupported_algorithm` even when listed in the
    accepted algorithms, and refused before any key lookup. A configured `none` used to get
    `invalid_token` or `invalid_signature` depending on the port.
  - Headers and payloads are parsed as strict JSON in every port: invalid UTF-8, a byte-order mark, `NaN`,
    trailing commas, leading zeros, raw control characters, trailing data and nesting deeper than 64 levels
    are `invalid_token`. jose4j (Java) took trailing commas, leading zeros and raw control characters;
    TypeScript, Go and Java took invalid UTF-8; Python took `NaN` and a BOM.
  - **Duplicate member names are rejected** (`invalid_token`) at any depth in the header and payload, and
    in introspection responses. Python, TypeScript and Go used to keep the last value.
  - A header with `crit`, a padded or non-canonical base64url segment, or the wrong number of segments is
    `invalid_token`. Go accepted a padded segment and a `crit` header.
  - `exp`, `nbf` and `iat` must be finite numbers within ±(2^53 − 1), else `invalid_token`. Python, Java
    and TypeScript accepted `exp: 1e20`; Go overflowed it into `expired`.
  - Non-string entries in `aud` or `scp`, a non-string `scope`, and a non-string `sub` make the token
    `invalid_token` instead of being dropped.
  - A string `scp` (as Microsoft Entra ID issues it) is now read as space-delimited scopes, like `scope`.
    Every port used to ignore it and grant no scopes.
  - `scope` is split on spaces only (RFC 6749 section 3.3), so a tab or no-break space no longer separates
    scopes.
  - A non-string `typ` is always `invalid_token_type`; a non-string or empty `kid` is `key_not_found`; a
    token without `kid` only matches a key set holding exactly one key.
- **Introspection: only `"active": true` is active** in Python and TypeScript, as RFC 7662 says and Go and
  Java already did. `"true"`, `1` and other truthy values are now `inactive`.
- **Go: `ValidateActive` returns `(Result, error)`.** A failed introspection call (no endpoint, transport
  failure, non-2xx, oversized or malformed body) is now an error in every port, never an `invalid_token`
  verdict; Go was the odd one out. This is a breaking change to the Go signature.
- **Go: an explicitly empty `AcceptedAlgorithms` or `AcceptedTokenTypes` accepts nothing**, as in the other
  ports. `nil` still means the defaults.
- **Go: the introspection response cap is 1 MiB**, the same as the other ports (it was 64 KiB), and a
  larger response is an error rather than silently truncated.
- The PingFederate mint now rejects a response whose `attestation` is missing or not a string in every
  port and both clients. Before, the TypeScript and Go issuance clients returned an empty attestation.
- The https error for the attester URL names `attester_url` (Python, Java) or `attesterUrl` (TypeScript)
  instead of `pf_host` / `pfHost`.
- **TypeScript is tested in a real Workers runtime.** CI runs the bundled package in `workerd`,
  Cloudflare's open-source Workers runtime, with Node compatibility switched off (`npm run test:edge`):
  key generation, the attestation, PoP and DPoP builders, and the token validator against the shared
  validation vectors.
- Coverage floors raised to today's measured coverage: Python 95%, Go 84%, TypeScript lines 99% and
  statements 98%, Java 95% lines and 91% branches.

### Removed

- **Python: `ClientAttestation(pf_host=...)`.** Pass the attester URL positionally or as `attester_url=`.
  It was briefly a deprecated alias during this release's development; with the next release being 1.0
  it is removed instead. The other ports only ever took the URL positionally.
- Python: `urllib_http(insecure_tls=...)` (deprecated in 0.3.0); use
  `dangerously_disable_tls_verification=`. `urllib_http`, `new_code` and `new_handle` are also no longer
  exported from `client_attestation_sdk.authz_challenge` (they are internal; tests import them from
  their modules).
- Python: internal helpers that were importable without an underscore are renamed with one:
  `keys.sign_compact`, `keys.require_text`, `signer.sign_external`, `builders.url_origin`,
  `builders.normalize_htu`, `builders.access_token_hash`, `token_validator.config.is_forbidden_algorithm`
  and `normalise_type`. None was in an `__all__`.
- TypeScript: `normalizeBaseUrl` and `jwtSub` (main entry point) and `resolveConfig` (`/validator`),
  internal helpers exported by mistake; and the top-level `WELL_KNOWN_PATH`, which is
  `PingFederateProfile.WELL_KNOWN_PATH` as in the other ports.
- Go: `NormalizeHTU`, an internal helper exported by mistake.
- **Python: the top-level `token_validator` and `authz_challenge` packages**, deprecated in 0.3.0. Import
  `client_attestation_sdk.token_validator` and `client_attestation_sdk.authz_challenge` instead; the
  module contents are unchanged.

### Fixed

- **Python: the validator no longer crashes on a hostile token.** A signed token with `exp`, `nbf` or `iat`
  of `1e400` raised an unhandled `OverflowError`, and a numeric `aud` raised `TypeError`, out of
  `validate()` instead of returning a verdict. Both are now `invalid_token`.
- **Java: the Maven Central publish.** The 0.3.0 upload was rejected because the runner's Maven 3.10 put
  `maven-metadata-local.xml` and `_remote.repositories` into the bundle. `java/mvnw` now pins Maven 3.9.16
  (checked by SHA-256), and CI, the release and the verify scripts all build with it.

## [0.3.0] - 2026-10-08

### Added

- **Logging hooks in all four ports**, off by default. Python logs through the standard `logging`
  module under `client_attestation_sdk` (with a `NullHandler`); Go takes a `*slog.Logger`
  (`WithLogger`, for the token source and the validator); TypeScript takes a `logger` option with
  `debug`/`info`/`warn`/`error`; Java takes a `System.Logger` (`.logger(...)`, no SLF4J dependency). Every
  port emits the same events with the same attribute keys: discovery, evidence, challenge, mint, token
  obtained / cached / refreshed (with expiry), DPoP nonce retries, HTTP failures (host and path, never a
  query string), JWKS fetches and throttling, validation verdicts, and in Python the CIBA and challenge
  resolver steps. No token, attestation, proof, SVID, challenge, secret or key is ever logged, and each port
  has a test that runs a full flow at the most verbose level to prove it. See
  [`docs/logging.md`](docs/logging.md).

### Changed

- **Go: the module now needs Go 1.25 or later** (it was 1.23, which is out of support). It comes with
  `lestrrat-go/jwx/v2` 2.1.7 and `golang.org/x/crypto` 0.53, which need 1.25.
- **TypeScript: `jose` 6.2.12 or later.**
- **Python: the package now needs Python 3.11 or later** (it was 3.10, which reaches end of life this
  month). CI runs 3.11 to 3.14, and a separate job tests the declared minimum `pyjwt` and `cryptography`.
- **Python: `token_validator` and `authz_challenge` now live under `client_attestation_sdk`.** Import
  `client_attestation_sdk.token_validator` and `client_attestation_sdk.authz_challenge` instead. The old
  top-level names were generic enough to collide with other packages in the same environment.
- **Java publishes to Maven Central** from this release, at the same coordinates
  (`global.idpartners:client-attestation-sdk`) and signed with GPG, so installing it no longer needs the
  GitHub Packages repository or a token. GitHub Packages gets this release as well, and is then dropped.
- **TypeScript: `SigningKeyPair.generate` makes a non-extractable private key.** Nothing in the SDK needs
  to export it, so it can no longer leak through `exportJWK`. Pass `{ extractable: true }` if you persist
  the key yourself.
- **`HttpSvidSource` is documented as development-only** in all four ports. It has no caller
  authentication, so anyone who can reach its URL can get the workload's SVID.

### Deprecated

- **Python: the top-level `token_validator` and `authz_challenge` packages.** They are now thin aliases
  that re-export the new modules (submodule imports such as `from token_validator.jwks import ...` still
  work) and raise a `DeprecationWarning`. They will be removed in 0.4.0.

### Fixed

- **Python: PyJWT 2.10 or later** (it was 2.8). Before 2.10, PyJWT's `to_jwk` sometimes dropped a leading
  zero byte from an EC `x` or `y`, so about one generated key in 170 had a public JWK that RFC 7518
  §6.2.1.2 says is invalid. That JWK also changed the key's RFC 7638 thumbprint (`kid`), and a strict
  verifier would refuse it.
- **TypeScript: the package loads on edge runtimes** (Cloudflare Workers, Vercel Edge, Deno Deploy without
  Node compatibility). It used to import `node:child_process`, `node:fs` and `node:crypto` at load time and
  use `Buffer` and `process.env`, so importing anything from it failed there. Crypto, encoding and HTTP now
  use WebCrypto, `TextEncoder`/`TextDecoder`, `btoa` and `fetch`. The three evidence sources that need Node
  (`SpireWorkloadApiSvidSource`, `FileTokenSvidSource`, and the file and socket probes in
  `autoDetectEvidence`) load the built-in on first use, and throw a `ClientAttestationError` naming the
  source when the runtime has none. The public API is unchanged. A new test bundles the package for a
  neutral platform with esbuild and runs it with `process`, `Buffer` and `require` removed.

## [0.2.0] - 2026-10-02

### Changed

- **Java coordinates and package.** `com.pingidentity.ps.oidf:client-attestation-sdk` is now
  `global.idpartners:client-attestation-sdk`, and the package `com.pingidentity.ps.oidf.client` is now
  `global.idpartners.clientattestation`. Update your imports.
- **npm scope.** The TypeScript package publishes as `@idpartners/client-attestation-sdk`.
- **New home and Go module path.** The SDK lives at
  [ID-Partners/client-attestation-sdk](https://github.com/ID-Partners/client-attestation-sdk). The Go
  module is now `github.com/id-partners/client-attestation-sdk/go`; update your imports. The old path
  stops at `v0.1.0`.
- **Java no longer depends on `oidf-jose`.** It needs only jose4j, so it builds from a clean clone.
- **The token validators are stricter** (Python, TypeScript, Go, identical verdicts):
  - a token with no `exp` is refused (`missing_expiry`), and one whose `iat` is in the future beyond the
    leeway is refused (`issued_in_future`);
  - a token whose `typ` header is present and isn't `at+jwt` is refused (`invalid_token_type`), so an ID
    token can't stand in for an access token. Turn it off with `accepted_token_types=None` /
    `acceptedTokenTypes: null` / `DisableTokenTypeCheck` if your issuer stamps something else;
  - a non-numeric `exp`, `nbf` or `iat` is `invalid_token` rather than ignored;
  - a JWK that declares an `alg` only verifies tokens with that `alg`.
- **Issuer and audience are required** when you build a validator. Before, leaving either out silently
  skipped that check. `ProtectedResource` now refuses a validator that doesn't accept its resource as an
  audience, and in Go `NewProtectedResource` returns an error.
- **JWKS fetching can't be used to hammer the issuer.** A `jwks_uri` is fetched at most once every 30
  seconds however many unknown `kid` values arrive, concurrent misses share one fetch, keys are refreshed
  after an hour, and a failed refresh keeps the keys already held. Fetches time out after 10 seconds,
  refuse redirects, non-2xx responses and bodies over 512 KiB. A fetch failure is now `key_not_found`
  (so a 401) instead of an exception. Introspection gets the same timeout and redirect refusal in Go and
  TypeScript.
- **Every HTTP call the SDK makes goes through one transport per port** with the same rules: a timeout
  on every call, redirects never followed (requests carry credentials, and a redirect would replay them
  to a host you didn't name), responses capped at 1 MiB, and network, status and JSON failures raised as
  the SDK's own error type (`TransportError` in Python and TypeScript, `ClientAttestationError` in Go,
  `TransportException` as the cause in Java) instead of raw library exceptions. Python also refuses
  non-http(s) URLs. The SPIRE subprocess in Java has a 30 second timeout and can't deadlock on its output.
- **Go: `TokenWithOptions(ctx, WithForceRefresh())`** bypasses the cached token, and a caller waiting
  for the token lock now gives up when its context is cancelled.
- **The one-call client fails closed** (all four ports):
  - if the attester advertises a `challenge_endpoint` and the challenge can't be fetched, no token is
    minted. `require_challenge=False` / `requireChallenge(false)` / `WithRequireChallenge(false)` restores
    the old "carry on without one";
  - `CLIENT_ATTESTATION_TOKEN_FILE` or `SPIFFE_ENDPOINT_SOCKET` set to a path that doesn't exist is an
    error naming the variable, instead of quietly trying the next evidence source;
  - `pf_host` and the attestation, challenge and token endpoints must be https unless the host is
    loopback or you pass `allow_insecure` / `allowInsecure` / `WithAllowInsecure()`. **A plain-http
    in-cluster host such as `http://pf:9031` now needs that flag.**
- **`dpop_combined` works end to end.** The instance key now lives as long as the token it bound,
  `token_type` is read from the token response, and a new `request_headers(method, url)` (each port's
  idiom) returns `Authorization: DPoP <token>` plus a fresh DPoP proof with `ath` and the server's nonce.
  The SDK's own request helpers (`requests_auth`/`httpx_auth`, `ca.fetch`, Go's `RoundTripper`, Java's
  `send`) retry once on `use_dpop_nonce`, and so does the token endpoint. `authorization_header()`
  returns the `DPoP` scheme for a DPoP-bound token. DPoP proofs normalise `htu` (no query or fragment,
  default port dropped) and upper-case `htm`.
- **Python `trace=` is redacted by default.** Credentials in trace records become `<redacted:N bytes>`
  and every curl argument is shell-quoted. `trace_redact=False` brings the raw values back, for local
  debugging only.
- **Validator error text no longer echoes token data** (`alg`, parser output), and `WWW-Authenticate`
  values have control characters stripped.
- **Python `authz_challenge`** (these change what an approver app or BFF must do):
  - a ceremony `code` is now a 128-bit handle. The short code shown to the human is a separate,
    display-only `reference`, and it is what the CIBA `binding_message` carries, so a device-side lookup
    must key on `reference`;
  - `verify_resume` is single-use and refuses an approval older than `max_approval_age` (300 s default);
  - `transaction_hash` hashes canonical JSON (sorted keys, no whitespace, UTF-8), so it can be reproduced
    in any language. **Hashes differ from 0.1, and any other component computing the same hash must
    switch to the same canonical form**;
  - an instruction may not carry a `subject` key;
  - the duplicate check and the insert are atomic;
  - `insecure_tls` is now `dangerously_disable_tls_verification` (the old name warns and still works);
  - keys, tokens and codes no longer appear in dataclass `repr`.

### Added
- **Parity:** `operator` and `challenge_at_token` on the one-call class in TypeScript, Go and Java (the
  `operator` form parameter is byte-identical across all four), and ES, RS and PS keys at 256, 384 and
  512 in TypeScript.
- **`DRAFT_REVISION`** (`DraftRevision` in Go) in every port: the draft revision the SDK implements.
- **One feature matrix**, `docs/features.json`, rendered into the README and the explainer by
  `scripts/features.py`; CI fails if they drift.
- **One version**, the `VERSION` file; `scripts/version.py set X.Y.Z` writes every copy and CI checks them.
- **Packaging:** Python requires 3.10+ and `cryptography>=42`, ships `py.typed`, and has `httpx`,
  `requests` and `aws` extras; TypeScript declares `engines: node>=20` (it uses Node built-ins, so it
  isn't for edge runtimes); Java builds `-sources` and `-javadoc` jars.

- CI on every push and pull request: all four suites with coverage floors, plus the cross-language
  validation gate.
- One release workflow that publishes all four ports from a `vX.Y.Z` release, after CI passes and only
  if every manifest carries that version.

### Removed
- **`site/` and `spire/`.** This repo is the SDK only. The microsite and the demo SPIRE server/agent
  deployment are gone; `docs/explainer.html` is the visual overview. The SDK's SPIFFE support (reading a
  JWT-SVID from the Workload API) is unchanged.

## [0.1.0] - 2026-07-06

First tag: Python, TypeScript and Go ports, with the Java builder as the interop reference. It predates
the one-call `ClientAttestation` API.
