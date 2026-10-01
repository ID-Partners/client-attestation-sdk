# Changelog

All four ports share one version number. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [semver](https://semver.org/) as described under "Status and versioning" in the README.

## [Unreleased]

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
