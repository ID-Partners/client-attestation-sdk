# Access-token validation and introspection

[Configuration index](../configuration.md)

`AccessTokenValidator` checks tokens received by a resource server.
The issuer is the expected `iss` claim.
The audience identifies the resource that accepts the token.
Use access-token signing keys from the authorisation server.
An attester's issuing keys do not necessarily sign access tokens.

## ValidatorConfig

Python and TypeScript pass a configuration to `AccessTokenValidator`.
Go passes `*tokenvalidator.Config` to `tokenvalidator.New`.
Java builds `ValidatorConfig` before constructing the validator.
Each validator keeps its own copy of the configuration, so changing a config object after building a
validator (or reusing a Go `Config` for a second one) doesn't change the live validator. Java's
`ValidatorConfig` is immutable. Python checks the copy again at construction, so a config edited after
it was built (an emptied issuer, a plain-HTTP endpoint) is refused rather than used.

| Setting | Python | TypeScript | Go | Java builder | Default and behaviour |
| --- | --- | --- | --- | --- | --- |
| Issuer | `issuer` | `issuer` | `Issuer` | `.issuer` | Required. Exact expected identifier. |
| Audiences | `audiences` | `audiences` | `Audiences` | `.audiences` | Required. At least one identifier. Python and TypeScript accept a string or list. Go takes a slice. Java accepts a list or varargs. |
| Static public keys | `jwks` | `jwks` | `JWKS` | `.jwks` | Unset. Object with a `keys` array. Go takes `json.RawMessage`. Java accepts an object map or JSON text. |
| Remote keys | `jwks_uri` | `jwksUri` | `JWKSURI` | `.jwksUri` | Unset. Fetched when static keys are absent. |
| Required scopes | `required_scopes` | `requiredScopes` | `RequiredScopes` | `.requiredScopes` | Empty. Every configured scope must be present. |
| Algorithm allowlist | `accepted_algorithms` | `acceptedAlgorithms` | `AcceptedAlgorithms` | `.acceptedAlgorithms` | The nine algorithms listed below. An explicit empty list accepts no algorithm. |
| Clock allowance | `leeway_seconds` | `leewaySeconds` | `LeewaySeconds` | `.leewaySeconds` | 60 seconds. Applied to local JWT `exp`, `nbf` and `iat` checks. |
| Accepted JWT header types | `accepted_token_types` | `acceptedTokenTypes` | `AcceptedTokenTypes` | `.acceptedTokenTypes` | `at+jwt`. Only checked when `typ` is present. |
| Introspection | `introspection` | `introspection` | `Introspection` | `.introspection` | Unset. Enables the separate active-token path. |
| Allow plain HTTP | `allow_insecure` | `allowInsecure` | `AllowInsecure` | `.allowInsecure(true)` | `false`. `jwks_uri` and the introspection endpoint must use HTTPS unless the host is loopback (`localhost`, `127.0.0.1`, `::1`). Construction fails otherwise. |

The default algorithms are `ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512`,
`PS256`, `PS384` and `PS512`.
`none` and `HS*` algorithms are refused even when included in the allowlist.
Configure the algorithms that the issuer uses.
An explicit empty algorithm list differs from an omitted list.
Go `nil` selects defaults. Java selects defaults when a null algorithm list is passed.
Python's algorithm argument must be iterable - `None` does not request defaults.

Token types compare without case and without an optional `application/` prefix.
An empty type list refuses every present `typ`.
A JWT without `typ` still passes that particular check.
Python `accepted_token_types=None`, TypeScript `acceptedTokenTypes: null`, and
Java `.acceptedTokenTypes((java.util.List<String>) null)` disable the type check.
Java also provides `.disableTokenTypeCheck()` to disable it without an overload cast.
Go uses `DisableTokenTypeCheck: true`.
Go `AcceptedTokenTypes: nil` selects the default.

Python, TypeScript and Java accept an explicit zero clock allowance.
Go uses `ZeroLeeway: true` with `LeewaySeconds: 0`.
Go zero `LeewaySeconds` alone selects 60 seconds.
Go refuses a configuration with `ZeroLeeway: true` and a non-zero `LeewaySeconds`.
Every port refuses a negative allowance at construction. Python also refuses a leeway that is not an
`int`, and TypeScript one that is not a non-negative safe integer. Python and TypeScript refuse a bare
string or a non-string entry in the list settings (`accepted_algorithms`, `accepted_token_types`,
`required_scopes`), so pass a list.

Choose one key source.
The implementation gives static keys precedence when both static keys and a URI are supplied.
An empty static key set does not fall back to the remote URI.
Without usable keys, local validation returns `key_not_found`.
The validator does not automatically discover keys from its issuer string.

## Validator constructor controls

| Control | Python | TypeScript options | Go option | Java validator builder | Default |
| --- | --- | --- | --- | --- | --- |
| JWKS HTTP function | `http_get` | `httpGet` | `WithHTTPGet` | `.httpGet` | SDK GET implementation. |
| Introspection HTTP function | `http_post` | `httpPost` | `WithHTTPPost` | `.httpPost` | SDK POST implementation. |
| Clock | `clock` | `clock` | `WithClock` | `.clock` | Current time. Python returns epoch seconds. TypeScript and Java return epoch milliseconds. Go returns `time.Time`. |
| Logger | Standard `logging` | `logger` | `WithLogger` | `.logger` | Off. See [Logging](../logging.md). |

Python uses `AccessTokenValidator(config, http_post=None, http_get=None, clock=...)`.
TypeScript uses `new AccessTokenValidator(config, options)`.
Java uses `AccessTokenValidator.builder(config).httpGet(...).build()` for overrides.
Its plain `new AccessTokenValidator(config)` uses defaults.

The GET hook accepts a URL and returns the JWKS JSON text.
The POST hook accepts a URL, form-encoded body and headers and returns parsed JSON claims.
Go `HTTPGetFunc` is `func(url string) ([]byte, error)`.
Go `HTTPPostFunc` is `func(endpoint, body string, headers map[string]string) (map[string]any, error)`.
These hooks do not receive a context.
A custom HTTP hook owns its network deadline, redirect policy and certificate verification.
It must fail when the remote service cannot provide a valid response.
The SDK cannot impose its default connection behaviour on arbitrary hook code.

## Remote JWKS cache

| Behaviour | Default |
| --- | --- |
| Time between fetch attempts | At least 30 seconds. Applies to failed attempts too. |
| Refresh cached keys by age | 3600 seconds. Refresh is triggered by validation, without a background timer. |
| Unknown `kid` | Attempts a refresh subject to the minimum interval. |
| Concurrent misses | Share or serialise refresh work. |
| Failed refresh | Keeps previously loaded keys. An unknown key remains unavailable. |
| Default network timeout | 10 seconds. |
| Maximum JWKS response | 524288 bytes (512 KiB). |
| Which JWKs count | Only signature-verification keys: a JWK with `use` other than `sig`, `key_ops` without `verify`, or a private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) is skipped, as is one the port can't read. JWKs without `kid` are never merged. |
| Token with `kid` | The first counted key with that `kid` that may be used for the token's `alg`. An empty `kid` matches nothing. |
| Token without `kid` | Uses a key only when exactly one counted key exists. |
| JWK declaring `alg` | Usable only for that algorithm. |
| Failed fetch, no matching key | `key_not_found` with the fixed description `signing keys unavailable`. The cause is logged as `jwks.fetch_failed`. |

These cache intervals have no supported validator configuration setting.
Python's implementation class `JwksProvider` has `min_refresh_seconds`, `max_age_seconds`
and a monotonic `clock` for its own tests and direct use.
It is not exported by the supported validator package.
Constructing it separately does not change an `AccessTokenValidator`'s cache.
TypeScript's internal `JwksProviderOptions` has `minRefreshSeconds`, `maxAgeSeconds`,
`clock`, `logger`, `jwks`, `jwksUri` and `httpGet`.
It is excluded from the supported API.
Go and Java keep the provider private to the validator implementation.

The Python validator's injected clock affects claim checks.
Its JWKS cache uses its own monotonic clock.
TypeScript's validator clock affects claim checks while its provider uses its own default clock.
Java's injected clock affects claim checks only; the JWKS cache ages on `System.nanoTime`.
Go's validator clock affects claim checks while cache age uses the provider's time source.

## IntrospectionConfig

Introspection asks the authorisation server whether a token is active.
Configure credentials for the resource server making that request.
They are separate from the workload's Client Attestation credential.

| Setting | Python | TypeScript | Go | Java constructor argument | Requirement |
| --- | --- | --- | --- | --- | --- |
| Endpoint | `endpoint` | `endpoint` | `Endpoint` | `endpoint` | Introspection endpoint URL. |
| Resource-server client identifier | `client_id` | `clientId` | `ClientID` | `clientId` | Supplied by the authorisation server administrator. |
| Resource-server secret | `client_secret` | `clientSecret` | `ClientSecret` | `clientSecret` | Supplied at runtime. |
| Authentication method | `auth_method` | `authMethod` | `AuthMethod` | `authMethod` | `client_secret_basic` by default. Also supports `client_secret_post`. |

`client_secret_basic` sends the credentials in the `Authorization` header.
`client_secret_post` sends `client_id` and `client_secret` as form fields.
Use one of those exact values.
Java's three-argument constructor selects Basic. Its four-argument constructor accepts the method.
Go's empty `AuthMethod` selects Basic.
The default introspection timeout is 10 seconds.
The default response limit is 1048576 bytes (1 MiB).
Timeout and limit have no supported setters - use a custom HTTP POST hook for other transport requirements.

## Per-call policy

| Method | Inputs and behaviour |
| --- | --- |
| `validate(token, required_scopes=None)` | Checks local JWT structure, algorithm, type, signing key, signature and claims. TypeScript/Java use `requiredScopes`. Go uses `Validate(token, requiredScopes)`. |
| `introspect(token, token_type_hint="access_token")` | Returns the server's parsed response. It is not an authorisation verdict. TypeScript/Java use `tokenTypeHint`; Go uses `Introspect(token)` with a fixed `access_token` hint. |
| `validate_active(token, required_scopes=None)` | Uses introspection directly. TypeScript/Java use `validateActive`; Go uses `ValidateActive`. It does not first run local JWT validation. |

Omitting the per-call scope list preserves the configured scopes.
Passing an explicit empty list disables that call's configured scope requirement.
Go needs a non-nil empty slice for that override.
Java's one-argument overload preserves the configured requirement.

`validate_active` requires the response's `active` value to be JSON `true`.
It checks required scopes and checks audience when the response contains an audience.
It does not require an audience when the response omits it.
It does not perform local JWT issuer, expiry, algorithm or `typ` checks.
Use the authorisation server's introspection policy for those decisions.
Because `validate_active` accepts a response with no audience or with another configured audience, and
doesn't look at `cnf`, a resource guarding opaque tokens should use `ProtectedResource.authenticate_active`
(`authenticateActive`, `AuthenticateActive`) instead, which applies the same rules as `authenticate`. See the
[resource reference](resource.md).
A failed introspection HTTP request raises an exception or returns an error.
A failed JWKS refresh is retained as provider state and can produce `key_not_found`.
Do not treat either as an active token.
Exact error ordering and claim types are in [Validation semantics](../../validation/SEMANTICS.md).

## Configured JWT validation examples

These create validators. A later validation fetches the remote JWKS.
Replace the example issuer, resource and endpoint with administrator-supplied values.

```python
from client_attestation_sdk.token_validator import AccessTokenValidator, ValidatorConfig
validator = AccessTokenValidator(ValidatorConfig(
    issuer="https://as.example",
    audiences=["https://api.example/payments"],
    jwks_uri="https://as.example/jwks",
    required_scopes=["payments:read"],
    accepted_algorithms=["ES256"],
    accepted_token_types=["at+jwt"],
    leeway_seconds=0,
))
```

```ts
import { AccessTokenValidator } from "@idpartners/client-attestation-sdk/validator";
const validator = new AccessTokenValidator({
  issuer: "https://as.example",
  audiences: ["https://api.example/payments"],
  jwksUri: "https://as.example/jwks",
  requiredScopes: ["payments:read"],
  acceptedAlgorithms: ["ES256"],
  acceptedTokenTypes: ["at+jwt"],
  leewaySeconds: 0,
}, { logger: console });
```

```go
// Inside a function returning error.
// Import tokenvalidator "github.com/id-partners/client-attestation-sdk/go/tokenvalidator".
validator, err := tokenvalidator.New(&tokenvalidator.Config{
    Issuer: "https://as.example",
    Audiences: []string{"https://api.example/payments"},
    JWKSURI: "https://as.example/jwks",
    RequiredScopes: []string{"payments:read"},
    AcceptedAlgorithms: []string{"ES256"},
    AcceptedTokenTypes: []string{"at+jwt"},
    ZeroLeeway: true,
})
if err != nil { return err }
_ = validator
```

```java
import global.idpartners.clientattestation.tokenvalidator.*;

// Inside a method.
AccessTokenValidator validator = new AccessTokenValidator(ValidatorConfig.builder()
        .issuer("https://as.example")
        .audiences("https://api.example/payments")
        .jwksUri("https://as.example/jwks")
        .requiredScopes("payments:read")
        .acceptedAlgorithms("ES256")
        .acceptedTokenTypes("at+jwt")
        .leewaySeconds(0)
        .build());
```

## Introspection hook example

This offline example verifies the form fields and per-call scope override.
Run it with the Python environment from [Building](../building.md#python).
Successful completion prints `introspection configuration passed`.

```python
from urllib.parse import parse_qs
from client_attestation_sdk.token_validator import (
    AccessTokenValidator, IntrospectionConfig, ValidatorConfig,
)

def fake_post(url, body, headers):
    form = parse_qs(body)
    assert url == "https://as.example/introspect"
    assert form["client_id"] == ["resource-server"]
    assert form["client_secret"] == ["test-secret"]
    return {"active": True, "aud": "https://api.example", "scope": "read", "sub": "user"}

validator = AccessTokenValidator(ValidatorConfig(
    issuer="https://as.example", audiences="https://api.example",
    required_scopes=["write"],
    introspection=IntrospectionConfig("https://as.example/introspect",
        "resource-server", "test-secret", "client_secret_post"),
), http_post=fake_post)
assert not validator.validate_active("opaque-test-token").valid
assert validator.validate_active("opaque-test-token", required_scopes=[]).valid
print("introspection configuration passed")
```

## Authorisation-server discovery helper

Python `discover(metadata_url, http_get=None, *, issuer=None, allow_insecure=False)` and Java
`Discovery.discover(metadataUrl)`, `discover(metadataUrl, httpGet)`,
`discover(metadataUrl, issuer, httpGet)` and `discover(metadataUrl, issuer, httpGet, allowInsecure)`
fetch an explicit metadata URL.
The returned document's `issuer` must equal the expected issuer (RFC 8414 section 3.3): the `issuer`
argument, or the issuer the URL was built from when it is a `.well-known/oauth-authorization-server` or
`.well-known/openid-configuration` URL. Any other URL needs the `issuer` argument.
The metadata URL and the returned `jwks_uri` and `introspection_endpoint` must use HTTPS unless the host
is loopback or the insecure option is set. The document is read as strict JSON.
The default timeout is 10 seconds.
Read `issuer`, `jwks_uri` and `introspection_endpoint` from the returned document and pass them to configuration.
The helper does not register clients or choose a resource audience.
Go and TypeScript expose no equivalent discovery helper in their supported validator packages.

Source: [Python configuration](../../python/src/client_attestation_sdk/token_validator/config.py),
[Python validator](../../python/src/client_attestation_sdk/token_validator/validator.py),
[TypeScript configuration](../../typescript/src/validator/config.ts),
[TypeScript validator](../../typescript/src/validator/validator.ts),
[Go configuration](../../go/tokenvalidator/config.go),
[Java configuration](../../java/src/main/java/global/idpartners/clientattestation/tokenvalidator/ValidatorConfig.java).
