# Authorisation challenges - Python

[Configuration index](../configuration.md)

`client_attestation_sdk.authz_challenge` parses authorisation challenges and coordinates approval.
These APIs are Experimental and available only in Python.
They require application hooks for the approval channel and storage.
They do not configure a human approval service or credential verifier.

## Challenge parsing

`parse_challenge(status=None, headers=None, body=None)` accepts an HTTP status,
response headers and a response body.
It returns the recognised challenge or `None`.
`parse_www_authenticate(value)` parses a `WWW-Authenticate` value.
Supported challenge types are `authn`, `resource_authorisation`, `consent`,
`identity_proofing` and `intent`.
The parser recognises a type without guaranteeing that a resolver handles it.
A `Challenge` contains `type`, `error`, optional `scope`, `doctype`, `acr_values`,
`grant_id`, `reason`, `pep`, `source` and `raw`.
`source` defaults to `rest` when constructing it directly.
These fields describe the received challenge.

## CibaClient settings

CIBA means Client-Initiated Backchannel Authentication.
Its backchannel request initiates approval and its token endpoint is polled for the result.
Construct `CibaClient` with keyword arguments.

| Argument | Default | Behaviour |
| --- | --- | --- |
| `bc_auth_endpoint` | Required | Full backchannel authentication endpoint. |
| `token_endpoint` | Required | Full token endpoint for CIBA polling. |
| `client_id` | Required | Registered client identifier. |
| `client_auth` | Required | Object implementing `ClientAuth.apply(endpoint, form)`. It adds client authentication to the form in place. |
| `issuer` | Required | Audience of a signed backchannel request object. |
| `request_signing_key_pem` | `None` | Private PEM key. When set, signs the backchannel request object. Otherwise sends its claims as form fields. |
| `request_signing_kid` | `None` | Optional signed request's `kid`. |
| `request_signing_alg` | `ES256` | JWS algorithm for the signed request object. Must match its key. |
| `http` | `urllib_http()` | Callable `(method, url, form, headers) -> (status, response_text)`. |
| `clock` | `time.time` | Epoch seconds for request and poll state. |
| `allow_insecure` | `False` | `bc_auth_endpoint` and `token_endpoint` must use HTTPS unless the host is loopback. The constructor raises `ValueError` otherwise. |

`urllib_http(timeout=30.0, dangerously_disable_tls_verification=False)` lives in
`client_attestation_sdk.authz_challenge.ciba`.
This helper is Internal. Its parameters describe the default implementation, not a supported helper API.
The supported override is the `CibaClient(http=...)` callable.
Its timeout is in seconds.
It uses the shared transport's redirect refusal and 1 MiB response limit.
The TLS flag disables certificate and hostname checks when `True`.
It defaults to `False`.
A custom HTTP function owns its transport policy.
The client performs no endpoint discovery.

## PrivateKeyJwtAuth

This helper implements `private_key_jwt` client authentication.

| Argument | Default | Behaviour |
| --- | --- | --- |
| `client_id` | Required | Assertion `iss` and `sub`. |
| `private_key_pem` | Required | Private PEM key registered for the client. |
| `kid` | Required | Registered signing-key identifier. |
| `extra_audiences` | `()` | Opt-in further audiences, for an AS that rejects its own issuer as the audience. Makes `aud` an array of the issuer, the endpoint called and these. |
| `algorithm` | `ES256` | Assertion signing algorithm. |
| `issuer` | `None` | The assertion's `aud`, one string. `CibaClient` fills in its own `issuer` when this is `None`; used on its own, the endpoint called is the audience. |

`apply(endpoint, form)` creates a fresh assertion and adds `client_assertion_type`
and `client_assertion` to the form.
The assertion's `aud` is the AS issuer as one string, as CIBA Core asks, unless `extra_audiences` is set.
Obtain additional issuer or endpoint identifiers from the authorisation server administrator.
The assertion lifetime is 120 seconds.
For direct assertion creation, `private_key_jwt_assertion` accepts the same fields plus
required `endpoint` and optional `ttl=120` in seconds.
Its assertion clock uses `time.time` independently of the CIBA client's injected clock.

## Request and polling inputs

`CibaClient.request` accepts these keyword arguments.

| Argument | Default | Behaviour |
| --- | --- | --- |
| `login_hint` | Required | Identifier used by the authorisation server to locate the approver. |
| `binding_message` | `None` | Message shown by the approval channel. |
| `scope` | `openid` | Space-separated requested scopes. |
| `authorization_details` | `None` | Serialised as a separate form field, including when a request object is signed. |
| `extra` | `None` | Additional request claims. Raises `ValueError`, before anything is signed, if it sets `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`, `login_hint` or `binding_message`. |
| `request_ttl` | `300` | Signed request-object lifetime in seconds. It does not set the returned CIBA grant lifetime. |

The accepted response supplies `auth_req_id`, `interval` and `expires_in`.
Both are read as whole seconds. A missing, non-numeric or below-1 `interval` becomes 3 seconds, and
`interval` is capped at 600. A missing, zero or unreadable `expires_in` becomes 120 seconds (CIBA requires
the AS to send it), and it is capped at 3600, so a request always ends on the client's clock.
Keep the returned `CibaRequest` and pass the same instance to `poll(req)`.
`to_dict()` stores only `auth_req_id`, `interval`, `expires_in`, `requested_at`, `last_outcome` and
`last_poll_at`. `rehydrate()` rebuilds a request from that and starts the poll throttle from the later of
`last_poll_at` and now. `auth_req_id` is the credential in that state: whoever holds it can poll for the token.

`poll` returns `pending`, `approved`, `denied` or `expired`.
It does not sleep or start a polling task.
Calls within `interval + 0.5` seconds of the last HTTP poll return cached state.
The poll lock is held only while reading and updating poll state, not during the token-endpoint call; a
second poll while a call is under way answers from cache.
`slow_down` adds 5 seconds to the interval.
A transport failure preserves the previous outcome and records `last_error`.
It does not approve the request.
Only a 200 whose body is a JSON object with a non-empty `access_token` is `approved`. Any other 200 stays
`pending` and sets `last_error`. An error body that isn't a JSON object is read as unparseable.
A successful token response is retained in `token_response` and `access_token`.

## Resolver settings

A ceremony is the stored approval state bound to a subject and instruction.
Each resolver accepts a store and deployment hooks.

| Setting | CibaResolver | WebConsentResolver | ProofingResolver | Behaviour |
| --- | --- | --- | --- | --- |
| `client` | Required | No argument | `None` | CIBA client. Proofing needs it to push the presentation request to a paired device. |
| `hooks` | `None` gives `Hooks()` | Required | Required | Deployment callbacks listed below. |
| `store` | `None` gives `MemoryStore()` | Same | Same | Ceremony storage. |
| `code_prefix` | `PAY` | `WEB` | `MDL` | Prefix for handles and displayed references. A dict selects a prefix by challenge type. |
| `ttl_seconds` | From CIBA response | `300` | `300` | Ceremony lifetime in seconds. |
| `interval` | From CIBA response | `3` | `3` | Advertised poll interval in seconds. |
| `max_attempts` | `1` | No setting | `1` | Attempt limit for the same bound instruction within the attempt window. Prior attempts are counted only in a `MemoryStore`; other stores never reach the limit. |
| `attempt_window` | `600.0` | No setting | `600.0` | Seconds used when counting prior failed attempts. |
| `clock` | `time.time` | `time.time` | `time.time` | Epoch-second clock. |
| `max_approval_age` | `300.0` | `300.0` | `300.0` | Maximum age in seconds for a resumed approval. `None` disables this age check. |
| `doctypes` | No setting | No setting | `()` | Credential doctypes the proofing resolver may request because a challenge names them. Any other doctype must be pinned in `instruction["doctype"]`; a challenge contradicting the pinned one is refused. |

`CibaResolver` and `WebConsentResolver` handle `resource_authorisation` and `identity_proofing`.
`ProofingResolver` handles `identity_proofing`, and never accepts an approval another resolver observed
(a CIBA tap or a web click) as a verified credential presentation.
The proofing resolver needs a paired device, a CIBA client and a verifier-session hook.
It uses CIBA to push the request.
It uses `proofing_status` to establish credential verification.
It does not redeem the push grant as evidence of identity proofing.

All `resolve` methods take `challenge` and keyword arguments `subject`, `instruction`,
`initiator` and optional `binding_message=None`.
CIBA and proofing resolvers also accept `scope="openid"`.
An instruction is the application object describing the operation being approved.
The subject participates in the instruction hash. The hash is over exact code points (no Unicode
normalisation), and `resolve` and `verify_resume` raise `ValueError` for a non-string object key or a tuple
anywhere in the instruction, because JSON would print different Python values the same way.
Resolve returns `Pending`, `Resolved` or `Unavailable`.
A live ceremony for the same subject and instruction is reused only for the `initiator`, and the kind of
resolver, that raised it. Another initiator gets `Unavailable` until that ceremony ends.
Any exception during a CIBA push releases the claimed ceremony, and a failed push doesn't count against
`max_attempts`.
`poll(code)` reads the ceremony's current result or returns `None` for an unknown code.
The code is an opaque handle. The reference is a separate display value.

All three resolvers provide `verify_resume(code, subject=..., instruction=...)`.
It accepts only a ceremony this resolver raised and an approval this resolver observed, and checks the
same subject and instruction, an approved state and the approval age. `WebConsentResolver` also refuses
an empty subject.
Before accepting, it reads the ceremony back through `rehydrate` and refuses one the store marks used.
It then records the use through `consume` (atomic) or, without it, `persist`. If reading back or
recording fails, the resume is refused.
A second resume is refused.

## Every deployment hook

All `Hooks` callbacks default to `None`, except `log`.
Only implement callbacks used by the selected resolver.

| Hook | Input and result | Purpose |
| --- | --- | --- |
| `channel_for` | `(subject) -> CHANNEL_DEVICE / CHANNEL_WEB / CHANNEL_LOCAL` | Finds an available approval channel. Missing or failed lookup falls back to local. |
| `already_covered` | `(subject, instruction) -> assurance string or None` | Returns an existing authorisation or verified proofing that covers the operation. A truthy result resolves without a new ceremony. |
| `persist` | `(ceremony) -> None` | Writes durable state. Use `Ceremony.to_dict()` for serialisation. |
| `rehydrate` | `(code) -> dict or None` | Restores durable state in `Ceremony.to_dict()` format. |
| `find_live_persisted` | `(subject, txn_hash) -> dict or None` | Finds an existing live ceremony across restarts or replicas. Used by CIBA and proofing resolvers. |
| `register_for_device` | `(ceremony) -> None` | Publishes the instruction or presentation request for the device to retrieve by reference. |
| `consent_url_for` | `(ceremony) -> URL string` | Creates the browser consent URL. Required for web consent. |
| `on_outcome` | `(ceremony, status) -> None` | Records approved, denied or expired outcomes. |
| `web_status` | `(ceremony) -> status string` | Reads browser consent outcome. Missing callback leaves the ceremony pending until expiry. |
| `proofing_start` | `(ceremony) -> dict` | Opens a verifier session. Must return `session_id`. Can include `request_uri` or `dcApiRequest` for the holder. Returned non-null fields become ceremony `extra` fields. |
| `proofing_status` | `(ceremony) -> status string` | Reads the credential verifier's result. |
| `settle_seconds` | Number, default `3.0` | CIBA resolver waits this long after approval before its final outcome, allowing an out-of-band outcome to be recorded. |
| `log` | `(message) -> None`, default no-op | Receives resolver diagnostic strings. They name a ceremony by its display reference (or a short hash), never by the handle that `poll` and `verify_resume` take. |
| `consume` | `(ceremony) -> bool` | Optional compare-and-set for `verify_resume`: record `consumed_at` only if the stored record has none, and return `True` if this call did. `False` refuses the resume. When set, it replaces `persist` for that write. |

`MemoryStore` lasts only for the process lifetime.
The store interface has `get(code)`, `put(ceremony)` and `find_live(subject, txn_hash, now=None)`.
An optional `put_if_no_live(ceremony, now=None)` supplies atomic claim-and-insert.
An optional `discard(code)` removes a failed claim.
For replicas, implement atomic claiming and resume consumption in shared storage.
The built-in resolver locks are process-local.
A failing `persist` or `find_live_persisted` while resolving is logged and doesn't block the push.
A failing `rehydrate`, `consume` or `persist` in `verify_resume` refuses the resume.
Single use across replicas is only as strong as the store's read-your-writes behaviour, and only atomic
with `consume`.

`Ceremony.to_dict()` includes the bound instruction, subject, grant state, outcome, and the `resolver`
and `approved_via` fields, which the store must persist. A ceremony persisted by a version without them
can't be polled or resumed.
Its state fields are described in the [Python API snapshot](../api-surface/python.txt).
Treat these as stored transaction data.
They are not constructor configuration for the token source.

## Offline web consent example

Run with the Python environment from [Building](../building.md#python).
The callbacks simulate an approval site. They do not contact a server.
Successful completion prints `web consent configuration passed`.

```python
from client_attestation_sdk.authz_challenge import (
    APPROVED, RESOURCE_AUTHORISATION, Challenge, Hooks, MemoryStore, WebConsentResolver,
)

hooks = Hooks(
    consent_url_for=lambda ceremony: "https://consent.example/approve/" + ceremony.code,
    web_status=lambda ceremony: APPROVED,
)
resolver = WebConsentResolver(hooks, MemoryStore(), code_prefix="WEB",
    ttl_seconds=120, interval=3)
pending = resolver.resolve(
    Challenge(type=RESOURCE_AUTHORISATION, error="insufficient_authorization"),
    subject="user@example.com", instruction={"operation": "payment", "amount": 25},
    initiator="payment-agent",
)
assert pending.consent_url.startswith("https://consent.example/approve/")
result = resolver.poll(pending.code)
assert result.status == APPROVED
print("web consent configuration passed")
```

Obtain live endpoints, registered keys and approval-channel behaviour from the authorisation server administrator.
Obtain verifier-session fields from the credential verifier's integration documentation.
The callbacks above demonstrate the contract without establishing live integration support.

Source: [CIBA](../../python/src/client_attestation_sdk/authz_challenge/ciba.py),
[Resolvers and hooks](../../python/src/client_attestation_sdk/authz_challenge/resolver.py),
[Parser](../../python/src/client_attestation_sdk/authz_challenge/challenge.py).
