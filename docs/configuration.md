# Configuration

`ClientAttestation` obtains an access token for a workload. A workload is the application or
service that calls a protected API. Evidence is the identity token that the workload presents
to the attester. The attester verifies that identity and issues a Client Attestation bound to
the workload's instance key.

An audience is the intended recipient identified by the token's `aud` claim.

The examples use placeholder hosts. Replace them with your deployment's values.

## Component references

Each reference lists the accepted settings, their defaults and their effect.
The names match the current Python, TypeScript, Go and Java implementations.
Python-only components are marked in the table.

| Component | Reference |
| --- | --- |
| One-call token source and HTTP adapters | [Client](configuration/client.md) - constructor controls, cache, per-call refresh and resource requests. |
| Workload identity | [Evidence sources](configuration/evidence.md) - environment selection, file, SPIRE and cloud settings. |
| Attester discovery and mint protocol | [Attester profiles](attester-profiles.md) - metadata fields, precedence and custom profiles. |
| Local signing and proof creation | [Keys and builders](configuration/builders.md) - algorithms, every claim setter and credential helpers. |
| Explicit mint-endpoint client | [Attestation issuance](configuration/issuance.md) - constructor settings, bootstrap inputs and returned proofs. |
| Issuing keys outside the process | [External signers](configuration/signers.md) - Transit configuration and custom signer contract. |
| Resource-server token checks | [Validation and introspection](configuration/validation.md) - every validator setting, key caching and per-call scope policy. |
| Bearer requests and resource metadata | [Protected resource](configuration/resource.md) - constructor inputs, metadata and response decisions. |
| Human approval and credential proofing - Python only | [Authorisation challenges](configuration/authorisation-challenges.md) - CIBA, resolvers, stores and every deployment hook. |
| HTTP policy and runtime configuration | [Transport and logging](configuration/transport.md) - deadlines, limits, retries and application-owned settings. |

Build instructions are in [Building](building.md).
Runtime deployment examples are in [Deployment](deployment.md).
[API status](api.md) identifies Stable, Experimental and Internal APIs.

## Values to obtain from the attester administrator

| Value | Meaning | Where to obtain it |
| --- | --- | --- |
| Attester base URL | HTTPS base URL used for discovery. | The attester administrator. |
| Evidence audience | The audience that the identity token must contain. You configure it, and the discovery document's `evidence_audience` must match it. | The attester administrator. |
| Identity mapping | The rule that maps your workload identity to a client. | The attester administrator. |
| Token endpoint | Where the SDK requests the access token. | `token_endpoint` in discovery. The PingFederate profile falls back to `/as/token.oauth2` under the base URL. |
| PoP audience | The audience of the Client Attestation PoP JWT. | `pop_audience` in discovery. The SDK falls back to the token endpoint URL. |

PoP means proof of possession of the instance private key. The evidence audience and the PoP
audience serve different requests. The resource audience is a separate value that identifies
the API accepting the access token.

The default `PingFederateProfile` reads `/.well-known/client-attester`. This discovery path and
the mint request format are PingFederate conventions. See [Attester profiles](attester-profiles.md)
for the discovery fields, static endpoints and custom profiles.

## One-call client options

The table names the constructor argument in Python and the option in TypeScript. Go uses
functions passed to `NewClientAttestation`. Java uses methods on `ClientAttestation.builder`.

| Setting | Python | TypeScript | Go | Java | Default |
| --- | --- | --- | --- | --- | --- |
| Attester URL | `attester_url` | First constructor argument or `attesterUrl` | First constructor argument | `builder(url)` | Required unless static metadata or a custom profile supplies configuration. |
| Evidence audience | `evidence_audience` | `evidenceAudience` | `WithEvidenceAudience` | `.evidenceAudience` | Required unless static metadata is given. The discovered `evidence_audience` must equal it, or the flow fails before any evidence is fetched. |
| Evidence source | `evidence` | `evidence` | `WithEvidence` | `.evidence` | Auto-detection. |
| Attester endpoints | `metadata` | `metadata` | `WithAttesterMetadata` | `.metadata` | Discovery. |
| Attester protocol | `profile` | `profile` | `WithAttesterProfile` | `.profile` | `PingFederateProfile`. |
| Requested authorisation | `authorization_details` | `authorizationDetails` | `WithAuthorizationDetails` | `.authorizationDetails` | Omitted. |
| Operator assertion | `operator` | `operator` | `WithOperator` | `.operator` | Omitted. |
| Instance-key algorithm | `algorithm` | `algorithm` | `WithAlgorithm` | `.algorithm` | `ES256`. |
| Token refresh margin | `expiry_skew_seconds` | `expirySkewSeconds` | `WithExpirySkew` | `.expirySkewSeconds` | 30 seconds. Go takes a `time.Duration`. |
| HTTP timeout per SDK request | `timeout` | `timeoutMs` | `WithTimeout` | `.timeout` | 20 seconds. Python takes seconds, TypeScript milliseconds, Go and Java a duration. |
| Token-endpoint proof | `pop_method` | `popMethod` | `WithPopMethod` | `.popMethod` | `attestation_pop_jwt`. Also accepts `dpop_combined`. |
| Require an advertised challenge | `require_challenge` | `requireChallenge` | `WithRequireChallenge` | `.requireChallenge` | `true`. A failed challenge request stops token acquisition. |
| Repeat the mint challenge at the token endpoint | `challenge_at_token` | `challengeAtToken` | `WithChallengeAtToken` | `.challengeAtToken` | `true`. |
| Allow HTTP on non-loopback hosts | `allow_insecure` | `allowInsecure` | `WithAllowInsecure()` | `.allowInsecure` | `false`. Loopback HTTP is allowed. |
| Custom client for attester HTTP | No constructor hook | No constructor hook | `WithHTTPClient` | No constructor hook | SDK client. See [client precedence](configuration/client.md#controls-specific-to-a-port). |
| Logger | Standard `logging` | `logger` | `WithLogger` | `.logger` | Off. |
| HTTP trace collection | `trace` | No option | No option | No option | `None`. A supplied Python list receives trace records. |
| Trace credential redaction | `trace_redact` | No option | No option | No option | `True`. |

Set `challenge_at_token` to `false` only when the attester administrator confirms that minting
consumes the challenge. It still appears in the mint-time instance proof. `require_challenge`
only requires a challenge when metadata advertises a challenge endpoint.

`authorization_details` is an RFC 9396 request for authorisation. Its accepted types and fields
come from the attester's policy. An `operator` assertion names the person or organisation
accountable for the workload. It does not grant authorisation.

Keep one client instance per configuration in your process. The client holds its access token
and the instance key together in memory. Token acquisition runs again when the cached token
reaches its refresh margin. Process restarts discard that cache.

## Workload identity

These environment variables are read by evidence auto-detection in all four ports:

| Variable | Value | Behaviour |
| --- | --- | --- |
| `CLIENT_ATTESTATION_SVID` | An identity token. | Used before file, SPIRE or metadata sources. The token is held as a static value. |
| `CLIENT_ATTESTATION_TOKEN_FILE` | Path to an identity token file. | The file is read on each evidence fetch. A missing configured file raises an evidence error. |
| `SPIFFE_ENDPOINT_SOCKET` | SPIRE Workload API socket path, optionally prefixed with `unix://`. | A missing configured path raises an evidence error. The source also needs the `spire-agent` executable. |

Auto-detection checks the environment token first. It then checks the configured token file,
followed by `/var/run/secrets/tokens/attester-token`. It checks the configured SPIRE socket next,
followed by `/tmp/spire-agent/public/api.sock`. It then probes the GCP metadata server.
Python also checks Azure IMDS and AWS evidence sources. Those two sources are Experimental and
have not been tested against a real attester. Their implementation is in
[`python/src/client_attestation_sdk/evidence.py`](../python/src/client_attestation_sdk/evidence.py).

A token file must already contain a token with the correct evidence audience. The file source
does not change the token's audience. See [Deployment](deployment.md) for a projected Kubernetes
ServiceAccount token example.

An explicit evidence source passed in code bypasses auto-detection:

```python
from client_attestation_sdk import ClientAttestation, FileTokenSvidSource

ca = ClientAttestation(
    "https://attester.example.com",
    evidence_audience="https://attester.example.com/evidence",
    evidence=FileTokenSvidSource("/var/run/secrets/tokens/attester-token"),
    timeout=20,
)
```

```ts
import { ClientAttestation, FileTokenSvidSource } from "@idpartners/client-attestation-sdk";

const ca = new ClientAttestation("https://attester.example.com", {
  evidenceAudience: "https://attester.example.com/evidence",
  evidence: new FileTokenSvidSource("/var/run/secrets/tokens/attester-token"),
  timeoutMs: 20_000,
});
```

```go
// Imports: time and clientattestation "github.com/id-partners/client-attestation-sdk/go".
ca, err := clientattestation.NewClientAttestation("https://attester.example.com",
    clientattestation.WithEvidenceAudience("https://attester.example.com/evidence"),
    clientattestation.WithEvidence(clientattestation.FileTokenSvidSource{
        Path: "/var/run/secrets/tokens/attester-token",
    }),
    clientattestation.WithTimeout(20*time.Second))
if err != nil {
    return err
}
```

```java
// Imports: java.time.Duration and global.idpartners.clientattestation.*.
ClientAttestation ca = ClientAttestation.builder("https://attester.example.com")
        .evidenceAudience("https://attester.example.com/evidence")
        .evidence(new SvidSource.File("/var/run/secrets/tokens/attester-token"))
        .timeout(Duration.ofSeconds(20))
        .build();
```

The SDK does not read an `ATTESTER_URL` or `EVIDENCE_AUDIENCE` environment variable. Applications
can define them and pass their values in. The [language READMEs](../README.md#documentation) show this
application configuration pattern.

Edge runtimes must supply an evidence source that works in their runtime. File sources and the
SPIRE CLI require Node APIs in TypeScript. `StaticSvidSource` holds a fixed token and cannot
renew it. An implementation of `SvidSource.fetch(audience)` can obtain renewable evidence from
the application's identity provider.

## Resource-server configuration

An access-token validator runs in the API receiving the token. A JSON Web Key Set (JWKS) contains
the public keys used to verify token signatures.

| Value | Python | TypeScript | Go | Java | Purpose |
| --- | --- | --- | --- | --- | --- |
| Issuer | `issuer` | `issuer` | `Issuer` | `.issuer` | Exact expected `iss` value. Required. |
| Audiences | `audiences` | `audiences` | `Audiences` | `.audiences` | Identifiers of this API. At least one is required. |
| Public keys URL | `jwks_uri` | `jwksUri` | `JWKSURI` | `.jwksUri` | Issuer's JWKS endpoint. A static `jwks` / `JWKS` / `.jwks` can supply the keys instead. |
| Required scopes | `required_scopes` | `requiredScopes` | `RequiredScopes` | `.requiredScopes` | Every listed scope must be present. Default is an empty list. |
| Clock leeway | `leeway_seconds` | `leewaySeconds` | `LeewaySeconds` | `.leewaySeconds` | 60 seconds by default. Go uses `ZeroLeeway: true` for zero leeway. |
| Introspection | `introspection` | `introspection` | `Introspection` | `.introspection` | Endpoint and credentials for `validate_active` / `validateActive` / `ValidateActive`. |
| Allow plain HTTP | `allow_insecure` | `allowInsecure` | `AllowInsecure` | `.allowInsecure(true)` | Off. The JWKS URL and introspection endpoint must use HTTPS unless the host is loopback. |

Take the issuer and JWKS URL from the authorisation server administrator or its metadata.
Take the resource audience and required scopes from the API owner. The attester base URL is
not necessarily the access-token issuer.

`validate` checks a JWT locally after obtaining the signing keys. `validate_active` uses RFC 7662
introspection for JWTs or opaque tokens. It does not first run `validate`. A transport
failure raises an exception or returns an error. It does not return an active verdict.
For a request guard over introspected tokens, use `ProtectedResource.authenticate_active`, which also
requires this resource in the response's `aud` and refuses a token with `cnf`.

An opaque token has no claims that the resource can validate locally.

`ProtectedResource.authenticate` handles Bearer requests. It does not verify a DPoP proof.
Since 1.0.1 it refuses a token whose `cnf` claim is non-null with 401, and it requires its own
resource in the token's audience even when the validator accepts several.
To accept sender-constrained tokens, verify the proof in the resource's authentication layer and
call `validate` directly. `AccessTokenValidator.validate` alone does not prove possession of the binding key.
See the [complete resource reference](configuration/resource.md) and
[validator reference](configuration/validation.md) for settings and per-call policy.

The exact validation rules are in [Validation semantics](../validation/SEMANTICS.md).
The [language READMEs](../README.md#documentation) show validator construction.

## Signing keys

The one-call client generates an instance key for each new token acquisition. It keeps that
key with the cached token for DPoP requests. It does not load an attester's issuing key.
An application issuing its own attestations uses `ClientAttestationBuilder` and an issuing key
trusted by the authorisation server. The offline examples generate temporary issuing keys.

`OpenBaoTransitSigner` keeps the issuing private key in OpenBao or HashiCorp Vault. The signer
is Experimental and authenticates with a supplied static token.

| Required value | What to configure |
| --- | --- |
| Vault base URL | The server origin, such as `https://openbao.example.com`. |
| Vault token | A token permitted to read `/v1/transit/keys/<key>` and sign at `/v1/transit/sign/<key>`. Obtain it from the vault administrator. |
| Transit key name | An existing key at the `transit` mount. Supported types are `ecdsa-p256`, `ecdsa-p384` and `ecdsa-p521`. |
| Verifier trust | Register the public JWK returned by the signer with the authorisation server's attestation verifier. |

The signer reads the key metadata on construction and pins the latest key version. It uses
that version for subsequent signatures. Construct a new signer to use a rotated key version.
Update the verifier's trusted keys according to the attester administrator's rotation procedure.
The SDK does not provision transit keys or renew vault tokens.
The [root README](../README.md#signing-keys-outside-the-process-vault--hsm) shows builder use.

## Logging and diagnosis

Logging is off until the application configures it. See [Logging](logging.md) for each language's
setup and event names. Python can also record HTTP requests with `trace=[]`. Keep
`trace_redact=True` to redact credentials. See [Troubleshooting](troubleshooting.md) for failure
symptoms and the configuration to check.
