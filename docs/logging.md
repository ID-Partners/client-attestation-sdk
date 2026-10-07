# Logging

Every port can log what the SDK does: discovery, minting, the token endpoint, DPoP nonce retries, JWKS
fetches, validation verdicts and HTTP failures. Each port uses its language's own logging facility and
adds no dependency. All four emit the same event names with the same attribute keys, so one log query
works whichever port a service runs.

Logging is **off by default**. Nothing is written until you configure a logger.

## Turning it on

| Port | How | Default |
| --- | --- | --- |
| Python | Standard `logging`. Loggers live under `client_attestation_sdk` (`client_attestation_sdk.token_source`, `client_attestation_sdk.validator`, `client_attestation_sdk.authz`). Configure them like any other library's. | The `client_attestation_sdk` logger has a `NullHandler`, so nothing reaches stderr. |
| Go | `clientattestation.WithLogger(*slog.Logger)` on `NewClientAttestation`; `tokenvalidator.WithLogger(*slog.Logger)` on `tokenvalidator.New`. | Discards. |
| TypeScript | `logger` option on `ClientAttestation` and in the `AccessTokenValidator` options: any object with `debug`, `info`, `warn` and `error(msg, attrs)` (the `console` object fits). | No-op. |
| Java | `ClientAttestation.builder(host).logger(System.Logger)`. Pass `System.getLogger(SdkLogging.LOGGER_NAME)` (`global.idpartners.clientattestation`) to route through `java.util.logging`, or any `System.LoggerFinder` you install (SLF4J and Log4j both ship one). | No-op. |

```python
import logging
logging.basicConfig()
logging.getLogger("client_attestation_sdk").setLevel(logging.DEBUG)
```

```go
logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
ca, err := clientattestation.NewClientAttestation("pf.example.com", clientattestation.WithLogger(logger))
```

```ts
const ca = new ClientAttestation("pf.example.com", { logger: console });
```

```java
ClientAttestation ca = ClientAttestation.builder("pf.example.com")
        .logger(System.getLogger(SdkLogging.LOGGER_NAME))
        .build();
```

## Shape of an event

The message is the event name. The attributes travel the way the language carries them:

- **Go**: slog key/value attributes.
- **TypeScript**: the second argument, a plain object.
- **Python**: `record.event` and `record.attributes` (a dict) on the `LogRecord`, and also rendered into
  the message as `event key=value ...` so a plain formatter shows them.
- **Java**: `System.Logger` has no structured attributes, so the message is `event key=value ...`.

## What is never logged

No access token, attestation, PoP or DPoP proof, SVID, challenge value, client secret, private key or
JWK member, and no `Authorization`, `DPoP` or `OAuth-Client-Attestation*` header value. URLs are logged as
`host` and `path` only, never with a query string or fragment. As a backstop, every port also replaces any attribute
value containing `eyJ` (the start of every JWT) with `<redacted:N bytes>` before it reaches the logger. Each port has a test that runs a full
flow with logging at its most verbose level and fails if any output contains `eyJ` or key material.

## Events

Levels are the four common ones: `debug`, `info`, `warn` (Python `WARNING`, Java `WARNING`) and `error`.

### Token source (the one-call client, all four ports)

| Event | Level | Attributes | When |
| --- | --- | --- | --- |
| `token.cache_hit` | debug | `expires_in` | A cached token is still good and is returned. |
| `token.refreshing` | debug | `reason` | A new token is needed. `reason` is `initial`, `expired`, `forced` or `asserted_context` (Python only). |
| `discovery.fetched` | debug | `host` | The `/.well-known/client-attester` document was fetched. |
| `discovery.cached` | debug | `host` | The flow used the discovery document fetched earlier. |
| `evidence.obtained` | debug | `source` | The platform identity was read. `source` is the evidence source's type name. |
| `challenge.fetched` | debug | `host` | The attester issued a challenge. |
| `challenge.skipped` | warn | `host` | The challenge could not be fetched and `require_challenge` is off, so the flow mints without one. |
| `attestation.minted` | debug | `host`, `client_id`, `alg` | The attester returned an attestation. `client_id` is its `sub`. |
| `dpop.nonce_retry` | info | `host`, `status`, `at` | A `use_dpop_nonce` challenge; the request is sent once more with the server's nonce. `at` is `token_endpoint` or `resource`. |
| `token.obtained` | info | `host`, `client_id`, `token_type`, `expires_in`, `pop_method` | The token endpoint issued a token. |
| `http.failed` | warn | `step`, `method`, `host`, `path`, `status`, `reason` | An outbound call failed. See below. |

### Validator (resource server: Python, TypeScript, Go)

| Event | Level | Attributes | When |
| --- | --- | --- | --- |
| `token.validated` | debug when valid, info otherwise | `result`, `mode` | A verdict. `result` is the stable error code (`valid`, `expired`, `invalid_audience`, ...); `mode` is `jwt` or `introspection`. |
| `jwks.fetched` | debug | `host`, `keys` | The JWKS was fetched; `keys` is how many usable keys it held. |
| `jwks.fetch_failed` | warn | `host`, `reason`, `status` | The JWKS fetch failed. The validator keeps serving the keys it already has. |
| `jwks.refetch_throttled` | debug | `host` | An unknown `kid` (or a stale set) would have triggered a fetch, but the last attempt was too recent. |
| `http.failed` | warn | `step`, `method`, `host`, `path`, `status`, `reason` | The introspection call failed (`step` is `introspection`). |

Java has no validator, so it emits none of these.

### Authorization challenges (Python only)

| Event | Level | Attributes | When |
| --- | --- | --- | --- |
| `authz.ciba_requested` | info | `host`, `interval`, `expires_in` | `bc-auth` accepted a backchannel request. |
| `authz.ciba_polled` | debug | `outcome`, `status`, `error` | One real call to the token endpoint (throttled polls that answer from cache are not logged). `error` is the OAuth error code. |
| `authz.resolve` | info | `resolver`, `kind`, `outcome`, `channel`, `reused`, `fallback` | A resolver answered a challenge. `outcome` is `pending`, `resolved` or `unavailable`. |
| `authz.poll` | debug | `resolver`, `kind`, `status` | A resolver reported a ceremony's status. |
| `authz.resume_verified` | info | `resolver`, `ok`, `reason` | A resumed call was checked against the approval. `reason` is set when it is refused. |

Ceremony codes, login hints, binding messages and instructions are not logged.

## Attributes

| Key | Meaning |
| --- | --- |
| `host` | Host (and port, when not the default) of the URL called. |
| `path` | Path of the URL called, without query string or fragment. |
| `method` | HTTP method. |
| `status` | HTTP status, when the server answered. Absent otherwise. |
| `step` | Which call: `discover`, `challenge`, `mint`, `token`, `introspection`, and in Python's CIBA client `ciba_request` and `ciba_poll`. |
| `reason` | For `http.failed` and `jwks.fetch_failed`: `timeout`, `network`, `redirect`, `too_large`, `status` (a non-2xx answer) or `malformed` (the body was not the JSON expected). For `token.refreshing`: see above. |
| `expires_in` | Seconds until the token expires (`token.cache_hit`: seconds left in the cache). Absent when the server gave no expiry. |
| `token_type` | `Bearer` or `DPoP`. |
| `pop_method` | `attestation_pop_jwt` or `dpop_combined`. |
| `client_id` | The client the attester mapped the workload to (the attestation's `sub`). |
| `alg` | Instance-key signature algorithm. |
| `source` | Evidence source type name. |
| `at` | Where a DPoP nonce retry happened: `token_endpoint` or `resource`. |
| `keys` | Number of usable keys in a fetched JWKS. |
| `result`, `mode` | Validation verdict and how it was reached. |
| `resolver`, `kind`, `outcome`, `channel`, `reused`, `fallback`, `ok`, `interval`, `error` | Authorization-challenge attributes (Python). |

Attributes with no value are left out rather than logged empty.

## Not covered

The SPIFFE issuance bootstrap (`AttestationIssuanceClient`), the OpenBao transit signer and the evidence
sources themselves do not log yet. Their failures still surface as exceptions or errors.
