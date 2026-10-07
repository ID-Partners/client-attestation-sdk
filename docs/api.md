# Public API

This page says what each port's public API is from 1.0.0, and how much each part of it is promised.
Every exported name is in one of three tiers:

- **Stable.** Follows semver from 1.0.0. A breaking change needs a major release. Before something
  Stable is removed or renamed, it is deprecated for at least one minor release, and it goes in the next
  major. New Stable API can arrive in any minor release.
- **Experimental.** Public and supported, but it may change or go in any minor release, with a CHANGELOG
  entry and no deprecation period. Each item is marked in its own doc comment and listed below with the
  reason. It is here because it exists in one port only, depends on someone else's API, or is an
  interface you implement (where an added method would break your code).
- **Internal.** Not API, whatever the language lets you reach. It can change in any release, patch
  releases included. Each port hides as much of it as the language allows.

The exact surface of each port is in [`api-surface/`](api-surface/), generated from the real build by
[`scripts/api_surface.py`](../scripts/api_surface.py). CI fails a pull request whose build no longer
matches the committed snapshot, so an API change is always a decision, with a CHANGELOG line (see
[CONTRIBUTING.md](../CONTRIBUTING.md)).

## Where the API is

| Port | The API is | Snapshot |
| --- | --- | --- |
| Python | the `__all__` of `client_attestation_sdk`, `client_attestation_sdk.token_validator` and `client_attestation_sdk.authz_challenge`. Import from those three packages. | [`python.txt`](api-surface/python.txt) |
| TypeScript | what the two `package.json` entry points export: `@idpartners/client-attestation-sdk` and `@idpartners/client-attestation-sdk/validator`. Nothing else under `dist/` can be imported. | [`typescript.txt`](api-surface/typescript.txt) |
| Go | the exported identifiers of `github.com/id-partners/client-attestation-sdk/go` and its `tokenvalidator` package. | [`go.txt`](api-surface/go.txt) |
| Java | the public types and members of `global.idpartners.clientattestation` and `global.idpartners.clientattestation.tokenvalidator`, the two packages the `global.idpartners.clientattestation` module exports. | [`java.txt`](api-surface/java.txt) |

## Stable

Everything in the places above that is not listed under Experimental or Internal is Stable. By area:

- **Version marker**: `DRAFT_REVISION` (`DraftRevision` in Go), and `VERSION` / `VALIDATOR_VERSION` in
  TypeScript. Moving to a new draft revision is a minor release if nothing Stable breaks, and a major one
  if it does.
- **Keys and building credentials**: `SigningKeyPair` (Java: `generate`, `fromJwk(Map, String)`,
  `publicJwk()`); `ClientAttestationBuilder`, `PopBuilder`, `DpopProofBuilder`;
  `ClientAttestationCredential`; the header and `typ` constants; the `JwsSigner` interface.
- **The one-call client**: `ClientAttestation` with its options (`pop_method`, `authorization_details`,
  `operator`, `evidence`, `challenge_at_token`, `require_challenge`, `allow_insecure`, `metadata`,
  `profile`, `algorithm`, expiry skew, timeouts, the logger), its token and header methods and its
  HTTP-client adapters, `discovery()` and `attester_metadata()`; `ClientAttestationError` and
  `TransportError` (`ClientAttestationException`, `TransportException` in Java).
- **Choosing an attester**: `AttesterMetadata` and the `metadata` option; `PingFederateProfile` as the
  value you pass to `profile` (it is the default), with its path constants.
- **Evidence**: the `SvidSource` interface; the static, file-token and GCP metadata sources; evidence
  auto-detection and the `ENV_*` / `DEFAULT_*` names it reads.
- **Resource server**: `AccessTokenValidator`, `ValidatorConfig`, `IntrospectionConfig`,
  `ValidationResult`, the error codes, `DEFAULT_ALGORITHMS` and the other defaults, `ProtectedResource`,
  `ProtectedResourceMetadata`, `AuthDecision`, `bearer_token`, and AS-metadata `discover` (Python, Java).
  The verdicts are pinned separately by [`validation/SEMANTICS.md`](../validation/SEMANTICS.md) and the
  shared vectors.
- **Logging hooks**: the logger option in each port, the TypeScript `Logger` type and `NOOP_LOGGER`, and
  `ClientAttestation.LOGGER_NAME` (Java). The hook is Stable and nothing secret will ever be logged; the
  events themselves are Experimental (below).

## Experimental

| Item | Ports | Why it is Experimental |
| --- | --- | --- |
| `AttesterProfile`, `AttesterTransport`, `MintRequest`, `MintResult` (writing a profile, or calling a profile's `discover` / `mint` yourself) | all four | New just before 1.0 and fitted to one real attester so far. You implement them, so a method added to them would break your profile. Choosing `PingFederateProfile` or passing static `metadata` is Stable. |
| `OpenBaoTransitSigner` | all four | A client for a third-party API (OpenBao / Vault transit) that authenticates with a static token only. Its constructor will change when other auth methods are added. The `JwsSigner` interface it implements is Stable. |
| `AttestationIssuanceClient`, `IssuedAttestation`, `IssuanceError` / `IssuanceException`, `INSTANCE_PROOF_TYP` | all four | They call a PingFederate demo issuance servlet (`/federation/attestation`) whose protocol is not standardised. |
| `SpireWorkloadApiSvidSource` (`SpireWorkloadAPISvidSource`, `SvidSource.SpireWorkloadApi`) | all four | It shells out to the `spire-agent` CLI, and its constructor will change when it talks to the Workload API socket directly. Auto-detection returning it is Stable. |
| `HttpSvidSource` (`HTTPSvidSource`, `SvidSource.Http`) | all four | A development and test source: the endpoint has no caller authentication. |
| `SigningKeyPair.fromJwk(PublicJsonWebKey, String)`, `SigningKeyPair.publicJsonWebKey()` | Java | They take and return jose4j types, which would tie 1.x to jose4j. `fromJwk(Map, String)` and `publicJwk()` are the Stable equivalents. |
| Log event names and attributes ([`logging.md`](logging.md)) | all four | Events may be added, split or renamed in a minor release while operators tell us what they need. |
| `client_attestation_sdk.authz_challenge` (the whole package) | Python | Exists only in Python. The resolvers are stateful and long-lived, and their shape will change when they are ported. The challenge vocabulary is pinned by `validation/challenges.json`; the Python names are not. |
| `SpiffeAgent`, `RegistrationEntry`, `JwtSvid`, `verify_jwt_svid`, `to_workload_claim`, `parse_spiffe_id`, `SpiffeAgentSvidSource` | Python | Exists only in Python. An in-process stand-in for a SPIRE agent, for tests and demos, not a SPIFFE implementation for production. |
| `AzureImdsSvidSource`, `AwsWebIdentitySvidSource` | Python | Exists only in Python, and not yet run against a real attester. |
| `ClientAttestation(trace=..., trace_redact=...)`, `token(asserted_context=...)`, `MintRequest.asserted_context` | Python | Exists only in Python ("Trace every call as curl" and "Asserted context at mint" in the feature matrix). |

## Internal

| Port | Internal | How it is hidden |
| --- | --- | --- |
| Python | `_http`, `_log`, `_redact`, `token_validator._strict`; and any name in a submodule (`builders`, `keys`, `token_source`, `authz_challenge.ciba`, ...) that is not in one of the three packages' `__all__`, such as `authz_challenge.ciba.urllib_http`, `authz_challenge.resolver.new_code` / `new_handle` and module constants like `token_source.WELL_KNOWN_PATH` | Internal modules and helpers start with `_`. The submodules themselves keep plain names: they are layout, and what in them is API is re-exported from the packages. |
| TypeScript | every module under `src/` other than the two entry points (`http`, `runtime`, the logging helpers, `validator/strict`, `validator/jwks`, ...) | `package.json` `"exports"` lists only `.` and `./validator`, so `import ".../dist/http.js"` fails with `ERR_PACKAGE_PATH_NOT_EXPORTED`. Internal helpers carry `@internal` and `stripInternal` drops them from the published `.d.ts`; `scripts/api_surface.py` type-checks the published declarations on their own, so nothing public can refer to a stripped name. |
| Go | `internal/sdklog` and every unexported identifier | Go's `internal/` rule and lower-case names. No exported package variable is left: the evidence paths are constants and the validator defaults are functions that return a copy. |
| Java | `global.idpartners.clientattestation.internal` (`HttpTransport`, `SdkLog`) and the package-private types (`Jws`, `Jwks`, `tokenvalidator.Strict`, `JwksProvider`, `ValidatorLog`) | `module-info.java` doesn't export `internal`. On the class path its types are still public (Java can't share a type between packages otherwise), and their javadoc says "Not API". |

## Names across ports

Each port follows its language's conventions: `snake_case` in Python, `camelCase` in TypeScript and Java,
exported `PascalCase` with initialisms in Go (`HTTPSvidSource`, `SpireWorkloadAPISvidSource`,
`ClientID`), and `Exception` instead of `Error` in Java. Those differences are deliberate.

Renamed for 1.0 so the ports agree:

- Go `(*ClientAttestation).Discovery(ctx)` is now `AttesterMetadata(ctx)`, the name the other ports use
  for the same thing (their `discovery()` returns the raw document, which in Go is the `Document` field).
- Java's logger name moved from `SdkLogging.LOGGER_NAME` to `ClientAttestation.LOGGER_NAME`.
- TypeScript's top-level `WELL_KNOWN_PATH` is gone; use `PingFederateProfile.WELL_KNOWN_PATH`, as in
  Python and Java.

Differences that stay, because each is the language's own shape or would cost more than it saves:

| Concept | Python | TypeScript | Go | Java |
| --- | --- | --- | --- | --- |
| Generate / load a key | `SigningKeyPair.generate`, `.from_jwk` | `SigningKeyPair.generate`, `.fromJwk` | `Generate`, `FromJWK` (package functions; Go has no static methods) | `SigningKeyPair.generate`, `.fromJwk` |
| Evidence sources | `FileTokenSvidSource`, `GoogleMetadataSvidSource`, `StaticSvidSource`, ... | same names | same, with Go initialisms | nested in the interface: `SvidSource.File`, `.GoogleMetadata`, `.Static`, ... |
| Auto-detect evidence | `auto_detect_evidence()` | `autoDetectEvidence()` | `AutoDetectEvidence()` | `Evidence.autoDetect()` |
| Evidence missing | `EvidenceNotFound` | `EvidenceNotFound` | `*EvidenceNotFound` | `Evidence.EvidenceNotFoundException` |
| Transport failure | `TransportError` | `TransportError` (with `kind`) | `*ClientAttestationError` (no separate type) | `TransportException` |
| Authorization header | `authorization_header()` → `{"Authorization": ...}` | `authorizationHeader()` → header map | `AuthorizationHeader(ctx)` → the header value | `authorizationHeader()` → header map |
| Attach to an HTTP client | `requests_auth()`, `httpx_auth()` | `fetch()` | `RoundTripper()`, `RoundTripperOver()` | `authorize(...)`, `send(...)` |
| Validator config / result | `ValidatorConfig`, `ValidationResult` | `ValidatorConfig`, `ValidationResult` | `tokenvalidator.Config`, `tokenvalidator.Result` (Go avoids repeating the package name) | `ValidatorConfig`, `ValidationResult` |
| Make a validator | `AccessTokenValidator(config, ...)` | `new AccessTokenValidator(config, opts)` | `tokenvalidator.New(config, opts...)` | `AccessTokenValidator.builder(config)...build()` |
| Validator defaults | `DEFAULT_ALGORITHMS` (tuple) | `DEFAULT_ALGORITHMS` (readonly array) | `DefaultAlgorithms()` (returns a copy) | `ValidatorConfig.DEFAULT_ALGORITHMS` (unmodifiable list) |
| Error codes | `token_validator.errors.EXPIRED` | `errors.EXPIRED` | `tokenvalidator.ErrExpired` | `ErrorCodes.EXPIRED` |
| Introspection | `introspect(token, token_type_hint=...)` | `introspect(token, tokenTypeHint?)` | `Introspect(token)` (no hint) | `introspect(token[, hint])` |

## Changing the API

1. Make the change, in every port that has the feature.
2. Regenerate the snapshot: `python3 scripts/api_surface.py <port>` (needs the port's dependencies:
   Python's in the interpreter you run it with or `--python`, `npm ci` for TypeScript, Go, and a JDK with
   `./mvnw` for Java).
3. Add a CHANGELOG line under `[Unreleased]` that says which tier the change is in. A Stable removal or
   rename is deprecated first (a "Deprecated" entry naming the major release that removes it).
4. If the change moves something between tiers, update this page and the item's doc comment.
