# Troubleshooting

Enable [SDK logging](logging.md) to identify the failed operation. Log events name the host,
path and request step. They omit credentials.

## Token acquisition

| Symptom | What to check |
| --- | --- |
| `EvidenceNotFound` or `EvidenceNotFoundException` | Verify the configured token file or SPIRE socket exists inside the running application. See [evidence configuration](configuration.md#workload-identity). In Java, `token()` reports it as the cause of a `ClientAttestationException`. |
| `PermissionError` (Python) or another file-read error | The token file exists but the process can't read it. Check the file and directory permissions and the pod's security context. |
| `could not auto-detect the workload's platform identity` | No evidence source matched. Mount a projected token, run a SPIRE agent, set `CLIENT_ATTESTATION_SVID`, or pass an evidence source in code. A variable is consulted only when no earlier source matched, so a wrong `SPIFFE_ENDPOINT_SOCKET` is not reported while the default token file exists. |
| No evidence detected on a laptop | Supply a token file issued for the attester's evidence audience. Ask the identity provider administrator for the token. The SDK cannot create a trusted platform identity locally. |
| SPIRE socket exists but fetching fails | Check that `spire-agent` is on the application's `PATH`. Check that the process can reach the socket and has a matching SPIRE registration. |
| Discovery returns 404 | Check the attester base URL and `/.well-known/client-attester`. Use static metadata when the attester publishes no discovery document. See [Attester profiles](attester-profiles.md#static-endpoints-no-discovery). |
| HTTPS requirement error | Use HTTPS for the attester and discovered endpoints. Non-loopback HTTP requires the explicit insecure option shown in [Configuration](configuration.md#one-call-client-options). |
| Challenge request fails | Check the advertised `challenge_endpoint`, its response status and `attestation_challenge` response field. The default client stops when an advertised challenge cannot be fetched. |
| Mint rejects the evidence | Ask the attester administrator to check the evidence issuer, audience, expiry and workload-to-client mapping. A file source cannot change the audience of an existing token. |
| Token endpoint reports an unknown or expired challenge after mint succeeds | Ask the attester administrator whether mint consumes the challenge. If it does, configure `challenge_at_token` / `challengeAtToken` / `WithChallengeAtToken` as `false`. |
| Every call obtains a new token | Retain the same client instance. Check that the token response supplies `expires_in` greater than the configured refresh margin. |
| Each acquisition is slow on a host without cloud metadata | Auto-detection probes the GCP (and in Python Azure) metadata service on every acquisition when no earlier source matches. Pass the evidence source explicitly. |
| Token endpoint answers `invalid_client` | The authorisation server does not accept the attestation. Check its trust in the attester's signing key, the `pop_audience` and the PoP method. The error's `body` carries the first 512 characters of the server's response. |
| Java `IllegalArgumentException: credential requests require HttpClient.Redirect.NEVER` | `send` refuses an `HttpClient` that follows redirects. Build it with `HttpClient.Redirect.NEVER`, the default. |
| Resource rejects a DPoP-bound token | Use the language's HTTP adapter or request-header method. It adds the required proof. Confirm the resource has a DPoP verification layer. `ProtectedResource` handles Bearer requests. |
| Timeout, redirect, oversized response or malformed response error | Check the operation named in `http.failed`. Confirm the endpoint is direct and returns the expected response format. Compare the limits with the transport implementation for your port. |

## Resource validation

| Error or symptom | What to check |
| --- | --- |
| Validator construction fails: `jwks_uri` or the introspection endpoint `must use https` | The URL is plain HTTP on a non-loopback host. Use the issuer's HTTPS URL. For a closed test rig only, set `allow_insecure` / `allowInsecure` / `AllowInsecure` / `.allowInsecure(true)`. |
| `discover` refuses the metadata | The document's `issuer` is not the expected one, the URL isn't a standard `.well-known` URL and no `issuer` was given, or an endpoint in it is plain HTTP. Pass the expected `issuer` and use HTTPS. |
| `invalid_issuer` | Match the configured issuer to the access token's trusted `iss` value. The attester URL and access-token issuer can differ. |
| `invalid_audience` | Match the API's configured audience to the audience granted by the authorisation server. `ProtectedResource` also requires its resource URI in the validator's audiences. |
| `invalid_token_type` for tokens that look valid | The issuer sets a `typ` other than `at+jwt`, such as `JWT`. Turn off the token-type check in the validator configuration. |
| `insufficient_scope` | Compare required scopes with the scopes granted in the token. Ask the authorisation server administrator about the grant policy. |
| `expired`, `not_yet_valid` or `issued_in_future` | Check system clocks and token lifetime. The validator's default leeway is 60 seconds. |
| `key_not_found` or `invalid_signature` | Check the issuer's configured JWKS URL and key rotation. An unknown `kid` can trigger a refresh. Refresh attempts are throttled. |
| `ProtectedResource` returns 401 for a DPoP-bound or mTLS-bound token | Since 1.0.1 the Bearer guard refuses any token with a non-null `cnf`, because it sees no sender proof. Verify the proof in the resource's authentication layer and call `validate` directly. See [resource configuration](configuration/resource.md). |
| `ProtectedResource` returns 401 `invalid_audience` for a token the validator accepts | Since 1.0.1 the guard requires its own resource URI in the token's audience. A token minted for another resource behind the same validator is refused. |
| Introspection raises or returns an error | Check the introspection endpoint, resource-server credentials and network access. Failure does not establish that a token is active. |

Token-validation rules and error precedence are defined in
[Validation semantics](../validation/SEMANTICS.md).

## Build and release

| Symptom | What to check |
| --- | --- |
| Python package import fails | Activate the intended environment and use `python -m pip install -e '.[test]'` from `python/`. The import name is `client_attestation_sdk`. |
| TypeScript package import fails | Use `@idpartners/client-attestation-sdk` or its `/validator` entry point. Run `npm run build` when consuming a source checkout. The package exports ESM. |
| `npm ci` fails because the lockfile differs | An intended dependency change updates `package.json` and `package-lock.json` together. Restore an accidental manifest change. |
| Java build cannot run the wrapper | Check JDK 17+, `JAVA_HOME` and access to Maven Central for the wrapper download. Use `mvnw.cmd` on Windows. |
| Interop reports a missing verifier | Obtain and install `com.pingidentity.ps.oidf:client-attestation:0.1.0` from its maintainer. See [Credential interoperability](building.md#credential-interoperability). |
| Feature or version check fails | Run the generators documented in [Contributing](../CONTRIBUTING.md). `docs/features.json` defines feature support. `VERSION` defines the shared version. |
| Public API snapshot fails | Inspect the change before regenerating the snapshot. See [Changing the public API](../CONTRIBUTING.md#changing-the-public-api). |
| GitHub source sync succeeds but packages are absent | Publishing the GitHub release in the public repository triggers package jobs. Those jobs also require CI and release-environment approval. |
| Java publish names missing secrets | Check the public repository's `release` environment against the required names in [`release.yml`](../.github/workflows/release.yml). |
