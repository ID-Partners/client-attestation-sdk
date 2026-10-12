# Protected-resource helper

[Configuration index](../configuration.md)

`ProtectedResource` adds Bearer extraction, response decisions and protected-resource metadata to a validator.
It does not create an HTTP server.
The application serves the metadata and applies the returned authentication decision.

## Constructor settings

| Setting | Python | TypeScript | Go | Java | Requirement |
| --- | --- | --- | --- | --- | --- |
| Public resource URI | `resource` | `resource` | `resource` | `resource` | Must appear in the validator's configured audiences. |
| Authorisation servers | `authorization_servers` | `authorizationServers` | `authorizationServers` | `authorizationServers` | Supplied list of server identifiers advertised in metadata. |
| Validator | `validator` | `validator` | `validator` | `validator` | Configured access-token validator. |
| Advertised scopes | `scopes_supported` | `scopesSupported` | `scopesSupported` | `scopesSupported` | Empty by default. Metadata advertisement only. |

Python uses `ProtectedResource(resource, authorization_servers, validator, scopes_supported=None)`.
TypeScript uses `new ProtectedResource(resource, authorizationServers, validator, scopesSupported?)`.
Go uses `NewProtectedResource(resource, authorizationServers, validator, scopesSupported)` and returns an error.
Java provides three-argument and four-argument constructors.

The constructor checks that the resource URI belongs to the validator's configured audience list.
`authenticate` then requires this resource URI in each token's `aud`, so a token minted only for another
audience the validator accepts gets 401. A direct `validate` call still accepts any configured audience;
use a separate validator with only this resource's audience if you call `validate` yourself.
`scopes_supported` does not require those scopes in incoming tokens.
Enforce scopes through the validator configuration or the per-call scope argument.
The helper does not infer an authorisation server from the token or issuer.

## Methods and policy

| Method | Behaviour |
| --- | --- |
| `metadata()` | Returns metadata containing `resource`, `authorization_servers` and `bearer_methods_supported: ["header"]`. Includes `scopes_supported` only when configured. Java also provides `metadataJson()`. |
| `metadata_path()` | Returns `/.well-known/oauth-protected-resource` with the resource's non-root path appended. TypeScript/Java use `metadataPath`; Go uses `MetadataPath`. |
| `metadata_url()` | Combines the public resource origin and metadata path. TypeScript/Java use `metadataUrl`; Go uses `MetadataURL`. |
| `challenge(error=None, error_description=None)` | Creates a Bearer `WWW-Authenticate` value with the metadata URL and optional error fields. TypeScript/Java use `errorDescription`; Go uses `Challenge`. |
| `authenticate(authorization_header, required_scopes=None)` | Extracts a Bearer token and runs local JWT validation. TypeScript/Java use `authorizationHeader` and `requiredScopes`; Go uses `Authenticate(header, scopes)`. |
| `authenticate_active(authorization_header, required_scopes=None)` | Extracts a Bearer token and checks it by RFC 7662 introspection, for opaque tokens. The response's `aud` must name this resource (a response without `aud` is refused), and a token with `cnf` is refused. A failed introspection call raises. TypeScript/Java use `authenticateActive(authorizationHeader, requiredScopes)`; Go `AuthenticateActive(header, scopes)` returns `(AuthDecision, error)`. Needs the validator's introspection configuration. |

Missing or invalid Bearer credentials produce status 401.
Missing required scope produces status 403.
An accepted token produces an authorised decision with status 200.
The application must stop processing when the decision refuses access.
The per-call scope argument replaces configured scopes when supplied.
An explicit empty list disables configured scope requirements for that call.

`authenticate` requires this resource in the token's audience, even when the validator accepts
several audiences. A token minted only for another resource gets `invalid_audience` and status 401.

The helper does not verify DPoP proofs. Since 1.0.1 it refuses a token whose `cnf` claim is non-null
(DPoP `cnf.jkt`, mTLS `cnf["x5t#S256"]` or a malformed value) as `invalid_token` with status 401,
because it receives no sender proof. A token without `cnf`, or with `cnf: null`, is handled as Bearer.
`AccessTokenValidator` checks the JWT signature and claims without proving possession of the binding key.
To accept sender-constrained tokens, verify the proof in the resource's authentication layer and call
`validate` directly.
A `DPoP` authorisation scheme is not accepted by this Bearer helper.

`bearer_token` / `bearerToken` / `BearerToken` extracts the token the same way in every port, pinned by
the shared cases in `validation/bearer.json`: the scheme `Bearer` (ASCII case-insensitive), then the
token. Only space, tab, CR, LF and FF separate or surround it, and the token may contain any character
except LF. Parsing takes linear time on any header. The exact rules are in
[Bearer extraction](../../validation/SEMANTICS.md#bearer-extraction).

## Offline request decision example

Run with the installed Python environment.
Successful completion prints `protected resource configuration passed`.
The example creates an ordinary Bearer access token locally for a test issuer.

```python
import time
import jwt
from client_attestation_sdk import SigningKeyPair
from client_attestation_sdk.token_validator import (
    AccessTokenValidator, ProtectedResource, ValidatorConfig,
)

key = SigningKeyPair.generate("ES256")
resource_uri = "https://api.example/payments"
validator = AccessTokenValidator(ValidatorConfig(
    issuer="https://as.example", audiences=[resource_uri],
    jwks={"keys": [key.public_jwk()]},
    required_scopes=["payments:read"], accepted_algorithms=["ES256"],
    leeway_seconds=0,
))
resource = ProtectedResource(resource_uri, ["https://as.example"], validator,
    scopes_supported=["payments:read"])
now = int(time.time())
token = jwt.encode({"iss": "https://as.example", "aud": resource_uri,
    "sub": "payment-agent", "iat": now, "exp": now + 60, "scope": "payments:read"},
    key.private_key, algorithm="ES256", headers={"kid": key.key_id, "typ": "at+jwt"})
assert resource.metadata_path() == "/.well-known/oauth-protected-resource/payments"
assert resource.authenticate(None).status == 401
assert resource.authenticate("Bearer " + token).authorized
assert resource.authenticate("Bearer " + token, ["payments:write"]).status == 403
print("protected resource configuration passed")
```

See [Deployment](../deployment.md#deploy-a-protected-resource) for proxy headers and deployment checks.
See [Examples](../examples.md#protected-resource-examples) for the supplied HTTP demonstration servers.

Source: [Python](../../python/src/client_attestation_sdk/token_validator/resource.py),
[TypeScript](../../typescript/src/validator/resource.ts), [Go](../../go/tokenvalidator/resource.go),
[Java](../../java/src/main/java/global/idpartners/clientattestation/tokenvalidator/ProtectedResource.java).
