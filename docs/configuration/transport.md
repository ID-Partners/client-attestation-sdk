# Transport, logging and configuration boundaries

[Configuration index](../configuration.md)

The SDK sends requests through several components.
A timeout on one component does not configure every request in the application.
Use the component's documented setting and unit.

## Default transport controls

| Operation | Default timeout | Default response limit | Supported override |
| --- | --- | --- | --- |
| One-call discovery, challenge, mint and token requests | 20 seconds per request | 1048576 bytes | Client timeout. Go also accepts `WithHTTPClient`. |
| Attestation issuance mint | 20 seconds | 1048576 bytes | Go `HTTPClient`, subject to the 20-second mint context. Other ports have no timeout setter. |
| GCP / Azure identity fetch | 5 seconds | 1048576 bytes | Source timeout in Python, TypeScript and Go. Azure is Python only. Java GCP timeout is fixed. |
| Metadata source detection | 300 milliseconds per probe | Implementation-specific probe cap | No supported auto-detection setting. TypeScript has internal test overrides. |
| SPIRE CLI | 30 seconds, then the process is killed | Subprocess output handling | Socket path and executable path. No deadline setter. |
| HTTP demonstration SVID source | 20 seconds | 1048576 bytes | Go custom client. |
| Remote JWKS | 10 seconds | 524288 bytes | Validator HTTP GET hook. No public timeout or size setter. |
| Introspection | 10 seconds | 1048576 bytes | Validator HTTP POST hook. No public timeout or size setter. |
| Authorisation-server metadata helper | 10 seconds | 1048576 bytes | Python and Java only (no Go or TypeScript helper). HTTP GET hook. |
| OpenBao Transit | 5 seconds | 1048576 bytes | No transport constructor option. |
| Python CIBA HTTP transport | 30 seconds | 1048576 bytes | Custom `http` function. The internal `urllib_http` helper has a timeout parameter. |
| Protected API request | Application HTTP-client setting | Application HTTP-client setting | Requests, HTTPX, Fetch, Go `http.Client` or Java request/client settings. |

Default SDK HTTP transports refuse redirects and verify TLS certificates.
These rules apply to SDK endpoint calls.
Injected HTTP functions and application resource clients own their own connection behaviour.
Go replaces the `CheckRedirect` policy of a client supplied with `WithHTTPClient` or as the
issuance client's `HTTPClient`, so SDK endpoint calls refuse redirects there too (since 1.0.1).

The one-call client validates HTTPS for its base URL and endpoints.
Loopback HTTP is allowed for local use.
Non-loopback HTTP needs its explicit `allow_insecure` setting.
Other components do not all share this URL validation.
There is no global `allow_insecure` environment variable.
CIBA's certificate-verification flag is a separate control.

No supported SDK setting supplies a custom CA file, proxy URL, TLS client certificate,
connection pool size, general retry count or response-size limit.
The available custom HTTP hooks and Go clients provide application integration points.
Check certificate and proxy settings in the selected runtime's documentation.
The SDK does not expose a single cross-language TLS configuration API.

## Retry and failure policy

In `dpop_combined` mode, the one-call client retries once when the token endpoint requires a DPoP nonce.
The resource adapters also support one nonce retry when the request can be replayed.
There is no configurable general retry loop for minting or token acquisition.
An HTTP failure stops acquisition unless the advertised challenge is explicitly optional.
CIBA polling retains a pending outcome after a transport failure.
Remote JWKS refresh retains cached keys after a failure.
These behaviours belong to their respective components.

## Logging and tracing

[Logging](../logging.md) lists the logger setup, events and attribute names for every port.
The logger is off by default.
TypeScript passes `logger` to the client or validator options.
Go uses each package's `WithLogger`.
Java uses each builder's `.logger`.
Python uses the `client_attestation_sdk` logging hierarchy.

Python's client `trace` is independent of structured logging.
Pass a list to collect request traces.
`trace_redact=True` is the default.
`trace_redact=False` retains credentials in those records.
The `Hooks.log` callback for Python resolvers is also separate from structured logging.
Its diagnostic strings can contain transaction identifiers.
Select storage and access controls appropriate to the recorded data.

## Environment and configuration files

The SDK has no YAML, TOML or JSON application configuration loader.
Constructors, builders, Go options and source-selection environment variables are its configuration interfaces.
The [evidence guide](evidence.md) lists every SDK auto-detection variable.
The application owns variables such as `ATTESTER_URL`, `RESOURCE_URL` and vault credentials.
Pass those values into SDK constructors.
A `.env` file has no effect unless the application or launch environment loads it.

Proxies: Python's transport honours `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` through `urllib`, except
for GCP metadata and Azure IMDS requests, which always go direct so a proxy never sees the identity token.
Go's default client uses `http.DefaultTransport`, which honours the same variables (again except for GCP
metadata requests); a client supplied with `WithHTTPClient` uses its own transport. TypeScript uses the runtime's global `fetch`, which
in Node does not read the proxy variables unless the runtime is configured to. Java's transport doesn't set a
proxy on its `HttpClient`, so the JDK's default `ProxySelector` applies: the JVM properties
`https.proxyHost`, `https.proxyPort`, `http.nonProxyHosts` and `java.net.useSystemProxies`, not the
`HTTPS_PROXY` environment variable. GCP metadata requests ignore the JVM proxy settings.

Build configuration belongs to each port's manifest.
Python extras are `requests`, `httpx`, `aws` and `test`.
TypeScript uses the root package export and the `/validator` export.
Go has separate client and `tokenvalidator` packages within its module.
Java exposes the `global.idpartners.clientattestation` module.
See [Building](../building.md) for toolchains, test commands and package outputs.
See [Deployment](../deployment.md) for runtime evidence and server prerequisites.

Source: [Python transport](../../python/src/client_attestation_sdk/_http.py),
[TypeScript transport](../../typescript/src/http.ts), [Go transport](../../go/httpx.go),
[Java transport](../../java/src/main/java/global/idpartners/clientattestation/internal/HttpTransport.java).
