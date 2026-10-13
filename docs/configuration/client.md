# Client and HTTP adapters

[Configuration index](../configuration.md)

`ClientAttestation` discovers an attester, fetches workload evidence, obtains a challenge,
mints a Client Attestation and exchanges it for an access token.
The [constructor table](../configuration.md#one-call-client-options) lists every shared setting.
The following settings complete that table.

## Controls specific to a port

| Port | Setting | Default | Behaviour |
| --- | --- | --- | --- |
| Python | `trace` | `None` | Pass a list to collect HTTP trace records. The SDK appends to the supplied list. |
| Python | `trace_redact` | `True` | Redacts credentials from traces. Setting it to `False` records credentials. |
| Go | `WithHTTPClient(client)` | SDK HTTP client | Uses a supplied `*http.Client` for attester and token requests. See the timeout and redirect rules below. |
| Go | `WithLogger(logger)` | Discard logger | Uses a supplied `*slog.Logger`. |
| TypeScript | `logger` | No-op logger | Object implementing `debug`, `info`, `warn` and `error(message, attributes)`. |
| Java | `.logger(logger)` | No-op logger | Uses a supplied `System.Logger`. |
| Python | Standard `logging` configuration | `NullHandler` | No constructor logger argument. See [Logging](../logging.md). |

Python timeouts use seconds. TypeScript `timeoutMs` uses milliseconds.
Go `WithTimeout` uses `time.Duration`. Java `.timeout` uses `java.time.Duration`.
The client timeout applies to each of its own HTTP requests and bounds the whole request in every port,
including a server that keeps sending slowly.
Evidence sources and resource requests don't use it. The GCP and Azure sources have their own 5-second
timeout and the SPIRE source 30 seconds. TypeScript's `ca.fetch` has no timeout of its own (it reads at
most 64 KiB of a nonce challenge within the client timeout): pass an `AbortSignal` in `init`.
It does not set a deadline for the complete multi-request acquisition flow.

Go's `WithTimeout` of zero or a negative duration means the 20-second default. A custom client whose `http.Client.Timeout` is zero or negative gets the `WithTimeout` value,
which defaults to 20 seconds, so no SDK request is unbounded. An existing positive `http.Client.Timeout`
takes precedence.
The SDK always replaces `CheckRedirect` with a redirect refusal policy, even when the supplied
client has its own (since 1.0.1).
The SDK copies the client, so the supplied one is not changed.
Go options apply in the order supplied - a later option replaces an earlier value for the same field.

TypeScript accepts `new ClientAttestation(url, options)` or `new ClientAttestation(options)`.
A positional URL takes precedence over `options.attesterUrl`.
Python accepts a positional URL or `attester_url=`.
Java accepts `builder(url)` or `builder().attesterUrl(url)`.
Go takes a URL as the first argument to `NewClientAttestation`.
A bare host is treated as HTTPS.
An omitted URL requires static metadata or a profile that supplies the configuration.

A client that discovers its attester needs the evidence audience: `evidence_audience` (Python),
`evidenceAudience` (TypeScript), `WithEvidenceAudience` (Go) or `.evidenceAudience(...)` (Java). The
discovered `evidence_audience` must equal it. A missing value fails before any request, and a different one
fails before any evidence is fetched. Static metadata needs none; a value given with it must match.

## Token cache and per-call controls

| Operation | Python | TypeScript | Go | Java |
| --- | --- | --- | --- | --- |
| Obtain or reuse a token | `token()` | `await token()` | `Token(ctx)` | `token()` |
| Force acquisition | `token(force_refresh=True)` | `await token({ forceRefresh: true })` | `TokenWithOptions(ctx, WithForceRefresh())` | `token(true)` |
| Force acquisition while obtaining an authorisation header | `authorization_header(force_refresh=True)` | `await authorizationHeader({ forceRefresh: true })` | `AuthorizationHeaderWithOptions(ctx, WithForceRefresh())` | No force-refresh overload - call `token(true)` first |
| Headers for a resource request | `request_headers(method, url)` | `await requestHeaders(method, url, { forceRefresh: true })` - third argument optional | `RequestHeaders(ctx, method, url)` | `requestHeaders(method, url)` |
| Resolved metadata | `attester_metadata()` | `await attesterMetadata()` | `AttesterMetadata(ctx)` | `attesterMetadata()` |
| Raw discovery document | `discovery()` | `await discovery()` | `AttesterMetadata(ctx).Document` after checking the returned error | `discovery()` |

The client stores the access token and its instance private key in memory.
A new acquisition generates a new instance key.
The default refresh margin is 30 seconds before the token response's `expires_in` lifetime ends.
A negative margin is refused when the client is built.
`expires_in` is read the same way in every port: a JSON number or a string of decimal digits, capped at
24 hours. A missing, non-numeric, infinite, zero or negative value prevents reuse.
A lifetime at or below the refresh margin causes the next call to acquire again.
The cache runs on a monotonic clock, so changing the system time neither serves an expired token nor
drops a good one.
A process restart discards the token, key and discovered metadata.
For changed static endpoints or profile configuration, construct a new client.

Python also accepts `token(asserted_context={"type": "transaction", "value": {...}})`.
This attester-specific field requests a fresh attestation and token.
It bypasses the normal cache and leaves the cached token unchanged.
Other ports do not expose `asserted_context`.
Obtain its accepted fields from the attester administrator.

## Challenges and proof selection

`pop_method="attestation_pop_jwt"` sends `OAuth-Client-Attestation-PoP` to the token endpoint.
`pop_method="dpop_combined"` sends a `DPoP` proof using the instance key.
The corresponding option names are `popMethod`, `WithPopMethod` and `.popMethod`.
Leaving it unset, `None`/`null`/`undefined` or `""`, means `attestation_pop_jwt`, so a value read from an
unset environment variable keeps the default.
In Go, `WithPopMethod("")` is ignored, like `WithAlgorithm("")`, so an earlier `WithPopMethod` still
applies; leaving the option out gives the default.
Any other value must be exactly one of the two names, which are case-sensitive.
Anything else, a case variant, surrounding whitespace or a non-string included, is refused when the client
is built, before any request: `ValueError` (Python), `RangeError` (TypeScript), an error from
`NewClientAttestation` (Go) or `IllegalArgumentException` from `build()` (Java).
The shared cases are in [`vectors/pop-method.json`](../../vectors/pop-method.json).
The authorisation server must accept the selected method.

`require_challenge` defaults to `True`.
It requires a successful challenge only when metadata advertises `challenge_endpoint`.
Setting it to `False` permits acquisition after a failed challenge call.
`challenge_at_token` defaults to `True`.
Setting it to `False` omits the mint challenge from the token-endpoint proof.
It still appears in the mint-time instance proof.

## Resource adapters

| Port | Adapter | Configuration owned by the application |
| --- | --- | --- |
| Python | `requests_auth()` | Install the `requests` extra. Pass the hook as `requests`' `auth` argument. Set the resource request timeout on `requests`. |
| Python | `httpx_auth()` | Install the `httpx` extra. Pass the hook as the HTTPX client's `auth`. Set the HTTPX client timeout. |
| TypeScript | `fetch(input, init)` | Accepts a URL string, `URL` or `Request`. `init` contains Fetch request settings, including method, headers, body and signal. |
| Go | `RoundTripper()` | Wrap with `http.Client{Transport: ca.RoundTripper(), Timeout: ...}`. |
| Go | `RoundTripperOver(base)` | Supply an existing `http.RoundTripper` for resource connections. This is separate from `WithHTTPClient`. |
| Java | `send(client, request, method, uri, bodyHandler)` | Supply the resource `HttpClient`, request builder and response body handler. Set timeouts on that client and request. |
| Java | `authorize(request)` or `authorize(request, method, uri)` | Adds headers to a request builder. The method/URI overload supplies the values needed for DPoP. It does not send or retry the request. |

Adapters generate a fresh resource proof when the token response has `token_type: DPoP`.
They can retry once after a `use_dpop_nonce` response with a `DPoP-Nonce` header.
A retry needs a replayable request body.
A streaming body that cannot be replayed prevents automatic replay.
A retry signs the nonce of the challenge it answers. A `DPoP-Nonce` longer than 1024 characters is
ignored, and nonces are remembered for at most 256 origins, oldest first out.
A 400 body is inspected for a nonce challenge only up to 64 KiB; the caller still gets the whole body.
The request-header methods and `DpopProofBuilder` refuse a URL with a backslash, ASCII whitespace or a
control character before its query or fragment. Give them the exact URL your HTTP client sends.
Redirect handling differs by adapter. TypeScript `fetch` uses `redirect: "manual"` and returns a
redirect to the caller without resending credentials. Java `send` refuses an
`HttpClient` that follows redirects (`IllegalArgumentException`); build it with
`HttpClient.Redirect.NEVER`, the `HttpClient` default. `authorize` only adds headers, so the client
you send the request with must not follow redirects. Go's `RoundTripper` refuses every redirect hop
with a `*ClientAttestationError` and doesn't contact the target, including a same-origin one; set the
`http.Client`'s `CheckRedirect` to return `http.ErrUseLastResponse` to get the 3xx response back instead.
Python's `requests_auth()` follows redirects. For a DPoP-bound token it takes the token and DPoP proof
off the request before `requests` builds the next hop, and ignores responses from another origin. For a
Bearer token it relies on `requests`, which drops `Authorization` when the host changes but keeps it on a
same-host hop. `httpx_auth()` with
`follow_redirects=True` still forwards the original DPoP proof (not the token) on a cross-origin hop, so
leave `follow_redirects` off with it.

`authorization_header` returns a header dictionary in Python.
`authorizationHeader` returns a header object in TypeScript and a header map in Java.
Go `AuthorizationHeader` returns a header value.
These methods supply `Authorization: DPoP <token>` for a DPoP token without its proof.
Use request headers or an adapter for that token.
Raw request-header methods do not observe the response and retry it.
Build fresh headers for each request.

## Python setup example

This constructs a client without network calls. Calling `token()` starts acquisition.
Install `client-attestation-sdk[requests]` to use the Requests adapter.

```python
import logging
import os
import requests
from client_attestation_sdk import ClientAttestation, FileTokenSvidSource

logging.basicConfig(level=logging.INFO)
ca = ClientAttestation(
    os.environ["ATTESTER_URL"],
    evidence_audience=os.environ["EVIDENCE_AUDIENCE"],
    evidence=FileTokenSvidSource(os.environ["CLIENT_ATTESTATION_TOKEN_FILE"]),
    algorithm="ES256",
    expiry_skew_seconds=30,
    timeout=20.0,
    pop_method="attestation_pop_jwt",
    require_challenge=True,
    challenge_at_token=True,
)
# Run against the configured resource. This performs network calls.
response = requests.get(os.environ["RESOURCE_URL"], auth=ca.requests_auth(), timeout=10)
response.raise_for_status()
```

`ATTESTER_URL`, `EVIDENCE_AUDIENCE` and `RESOURCE_URL` are application-defined environment variables.
The SDK reads none of them itself.
See the [language READMEs](../../README.md#documentation) for the other ports' complete examples.

Source: [Python](../../python/src/client_attestation_sdk/token_source.py),
[TypeScript](../../typescript/src/token-source.ts), [Go](../../go/tokensource.go),
[Java](../../java/src/main/java/global/idpartners/clientattestation/ClientAttestation.java).
