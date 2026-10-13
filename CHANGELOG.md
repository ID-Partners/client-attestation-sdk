# Changelog

All four ports share one version number. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [semver](https://semver.org/) as described under "Status and versioning" in the README.

## [Unreleased]

## [1.2.0] - 2026-10-14

A security and fix release. It is a minor release because one Stable type widened: TypeScript's
`ClientAttestationOptions.popMethod` now also allows `""` and `null`, values the runtime already
accepted. Upgrade from 1.1.0, or from 1.0.1 on npm.

1.1.0 was published to PyPI, Maven Central and the Go module proxy but not to npm: the release workflow's
`npm publish` read the tarball path as a GitHub repository. TypeScript users go from 1.0.1 to this release,
and should read the 1.1.0 notes below too.

Five changes refuse or send differently something earlier releases accepted - check these before you
upgrade. They ship under the security exception in the README's versioning policy:

- **PoP method**: use exactly `attestation_pop_jwt` or `dpop_combined` (case-sensitive); a misspelt value
  now fails when the client is built. Unset or `""` still means `attestation_pop_jwt`.
- **Java `send()` port**: a request URI whose port is empty (`https://h:/t`) or `0` now throws
  `IllegalArgumentException`. Write the port out or leave it off.
- **Introspection `auth_method`**: use exactly `client_secret_basic` or `client_secret_post` (or leave it
  unset for `client_secret_basic`). Any other value, a typo included, is now a config error; it used to send
  the secret as `client_secret_post`. Also: Python `auth_method=None` or `""`, and `""` in TypeScript and
  Java, used to send `client_secret_post` and now send `client_secret_basic`. If your authorisation server
  expects `client_secret_post`, set it explicitly.
- **Basic credentials**: with `client_secret_basic` the client id and secret are form-urlencoded per
  RFC 6749 section 2.3.1 before they are joined and base64-encoded. An authorisation server that compared
  them raw needs credentials made only of unreserved characters (`A-Z a-z 0-9 - . _ ~`), or
  `client_secret_post`.
- **Introspection credentials**: the client id and secret must be non-empty strings. A missing, `null`,
  empty or non-string value is now a config error naming the field. Before, TypeScript sent `rs:` for a
  missing secret, Java `rs:null`, and Go and Python sent an empty one.

### Changed

- Java: `ClientAttestation.send()` throws `IllegalArgumentException` for a request URI whose port is empty
  (`https://h:/t`) or `0`, before anything is sent. `HttpClient` sends such a URI to the scheme's default
  port, so code that relied on that must write the port out or leave it off. See the `send()` entry under
  Fixed.
- All four ports (Stable behaviour change): the one-call client refuses a PoP method other than
  `attestation_pop_jwt` or `dpop_combined` when it is built, before any request: `ValueError` (Python),
  `RangeError` (TypeScript), an error from `NewClientAttestation` (Go) or `IllegalArgumentException` from
  `build()` (Java). The names are case-sensitive, and a value with surrounding whitespace or a non-string
  is refused too. Unset, `None`/`null`/`undefined` or `""`, still means `attestation_pop_jwt` in every port.
  Before, any other value, such as `DPOP_COMBINED` or a typo of `dpop_combined`, quietly fell back to a PoP
  JWT, so a caller who asked for DPoP-bound tokens got Bearer tokens without being told: a silent downgrade
  of sender constraint, which the fail-closed defaults exist to prevent. A caller passing a misspelt value
  now gets an error at build time; fix the spelling. In Go, `WithPopMethod("")` is ignored, like
  `WithAlgorithm("")`, so an earlier `WithPopMethod` still applies. The token flow also fails before any
  request, rather than sending a PoP JWT, if it ever holds a value that isn't one of the two. The cases are
  shared in `vectors/pop-method.json`.
- TypeScript (Stable, additive): `ClientAttestationOptions.popMethod` is typed
  `"attestation_pop_jwt" | "dpop_combined" | "" | null`, so a typed caller can pass the unset values the
  constructor already took without a cast.
- All four ports (Stable behaviour change): the introspection client authentication follows RFC 6749
  section 2.3.1, and a bad method is refused. Both changes are what the RFC requires or what the config
  says, so a resource server's secret is never sent in a way it didn't ask for. `client_secret_basic` now
  form-urlencodes the client id and the secret before joining them with `:` and base64-encoding them: every
  byte except `A-Z a-z 0-9 - . _ ~` is `%XX` (uppercase hex, UTF-8) and a space is `+`, the same bytes in
  every port and pinned by `client_auth` in `validation/introspection.json`. Before, they were joined raw,
  so an authorisation server that decodes per the RFC failed a client id containing `:` or a secret
  containing `%` or `+`. Credentials made only of those unreserved characters send the same header as
  before. An authorisation server that did not decode, and so accepted the raw form, now fails credentials
  with any other character: register credentials without them, or switch to `client_secret_post`. Also,
  `auth_method` (`authMethod`, `AuthMethod`) other than exactly `client_secret_basic` or
  `client_secret_post` is now refused with the port's config error, when the `IntrospectionConfig`
  (Python, Java) or the validator (TypeScript, Go) is built. Any other value, a typo included, used to be
  taken as `client_secret_post`, which moved the secret into the form body; a caller that relied on that
  must name `client_secret_post`. Unset means `client_secret_basic` in every port, and unset is the same
  everywhere: `null` / `None`, `""`, or (Python, TypeScript) leaving it out, so a method read from an
  environment variable that isn't set takes the default. That changes what some unset values sent before:
  Python `None` and `""`, and `""` in TypeScript and Java, sent `client_secret_post` and now send
  `client_secret_basic` (TypeScript `null`/`undefined`, Java `null` and Go `""` already sent Basic). Set
  `client_secret_post` explicitly if the authorisation server expects it (security model F5, F6).

### Fixed

- All four ports: a refused introspection `auth_method` is described by its type and length in the error,
  never echoed, so a secret passed in the wrong argument doesn't end up in the message or a log.
- Release: the npm publish step passes the tarball as `./npm-dist/…`, so npm reads it as a file.
- All four ports: output a helper started by `spire-agent` writes after the agent has exited no longer fails
  the SPIRE fetch. While the agent is running, more than 1 MiB of stdout still kills it and fails the fetch;
  once it has exited, stdout is read for at most 250 ms more and at most 1 MiB in all, and the exit status
  decides. In 1.1.0 a helper writing more than 1 MiB in that window failed the fetch in Go, Python and
  TypeScript, while Java returned the token. When reading stops at the 1 MiB or the 250 ms, the last line may
  be cut off, so a token is only taken from a line that ends in a newline. Java's reader no longer blocks in
  a read after the agent exits (it reads what the pipe has available), and Python kills an over-limit agent
  from the calling thread.
- SPIRE CLI source: an agent that itself writes more than 1 MiB and exits at once now always fails the fetch
  with `output is larger than 1048576 bytes`. What it wrote before exiting can still be in the pipe when its
  exit is seen, and was read as post-exit output (cut at 1 MiB, the exit status deciding). That happened in
  most runs in Java and in occasional runs in Python and Go. Now what was read so far plus what is waiting
  in the pipe at the moment the exit is first seen counts as written while the agent ran (`available()` in
  Java; FIONREAD in Python on POSIX and in Go on Linux, macOS and the BSDs). Only output that arrives after
  that moment is post-exit output. TypeScript always failed and is unchanged. Each port has a 50-run test of
  this. In `vectors/spire-cli.json`, helpers that hold stdout now outlive the case's time limit (4 s against
  3 s), so a port that waited for the pipe to close instead of ending the 250 ms grace period fails the case.
- Java: `ClientAttestation.send()` compared the port as written when checking a request's URI against
  the URL the credentials are for (it does this for a URL the `htu` rule refuses, such as an IPv6 zone
  literal). So `:08443` and `:8443`, or `:443` and no port on https, were different origins. Now the port is
  compared as a number and dropped only when it is the scheme's own default: `:443` on https, `:80` on http.
  A URI whose port is not a number from 1 to 65535 (empty, signed, `0`, too large, not digits) is on no
  origin, and `send()` refuses it, even when the request names exactly the same URI. The address of an IPv6
  literal is compared case-insensitively; its zone ID is compared as written.
- Python: evidence auto-detection picks the Experimental `AwsWebIdentitySvidSource` when
  `AWS_CONTAINER_CREDENTIALS_FULL_URI` is set (EKS Pod Identity, among others), which fell through to
  `EvidenceNotFound`. EC2 instance profiles are
  still not detected, and the docstrings that said they were are corrected: pass the source explicitly there.

## [1.1.0] - 2026-10-12

A security release, and a minor one because it adds Stable API. It closes the findings of the second
production-readiness review: credentials sent across a redirect or over plain http, introspection without
the resource binding, and evidence requested for an audience the attester chose. Upgrade from 1.0.1.

Check these before you upgrade. Each entry says what to set or change. The refusals ship under the security
exception in the README's versioning policy; the Go timeout change is a bug fix:

- **Evidence audience** (Added): the one-call client needs `evidence_audience` / `evidenceAudience` /
  `WithEvidenceAudience` / `.evidenceAudience(...)` unless you give static metadata. Java's
  `ClientAttestation(String)` constructor can't set it and is deprecated (Deprecated): use the builder.
- **Resource helpers** (Changed): a resource URL must be https, loopback excepted, or set `allow_insecure`.
  Java `send` refuses a request whose URI is on another origin than its `uri` argument.
- **DPoP `htu`** (Changed): for a DPoP-bound token, the resource helpers and `DpopProofBuilder` refuse a URL
  with no `htu`: a relative URL, a scheme other than http or https, or a non-ASCII host (give the `xn--` form).
- **Userinfo** (Changed): every SDK HTTP call refuses a URL with userinfo (`https://user:pass@host/`). Put
  credentials where the API expects them, not in the URL.
- **Proxies** (Changed): Go, Java and Python send plain http directly, never through `HTTP_PROXY`. An endpoint
  reachable only through a plain-http proxy needs https or a direct route.
- **Go `RoundTripper` redirects** (Fixed): every redirect hop fails, same-origin included. To get the 3xx back,
  set the `http.Client`'s `CheckRedirect` to return `http.ErrUseLastResponse`.
- **Validator endpoints** (Fixed): a plain-http `jwks_uri` or introspection endpoint is refused when the
  validator is built, loopback excepted. Use https, or set `allow_insecure` / `allowInsecure` /
  `Config.AllowInsecure` / `.allowInsecure(true)`.
- **AS-metadata discovery** (Fixed, Python and Java): `discover` refuses a document whose `issuer` isn't the
  expected one, and plain-http URLs. A metadata URL that isn't a standard `.well-known` URL needs `issuer=`
  (Java: the `issuer` argument); for plain http pass `allow_insecure`.
- **Keys** (Fixed): `confirmationJwk` refuses a JWK with private members, or a `kty` or curve other than EC
  P-256/384/521 or RSA; pass the public JWK. `SigningKeyPair.fromJwk` refuses RSA keys under 2048 bits, an
  algorithm outside ES/RS/PS 256-512, and a JWK whose public members aren't its private key's. Go's `FromJWK`
  no longer loads Ed25519. Use a supported key of the right size.
- **Go timeouts** (Fixed): `WithTimeout(d)` with `d <= 0`, or a `WithHTTPClient` client with no `Timeout`,
  means the 20 s default instead of no timeout. Set a longer timeout if a call needs one.

### Added

- All four ports, **breaking for callers that use attester discovery**: the one-call client takes the evidence
  audience, `evidence_audience=` (Python), `evidenceAudience` (TypeScript), `WithEvidenceAudience` (Go) or
  `.evidenceAudience(...)` (Java), and requires it unless static metadata is given. The attester's discovery
  document must name the same audience. If it doesn't, or the setting is missing, the flow fails with
  `ClientAttestationError` (Java `ClientAttestationException`) before any evidence is fetched. Every evidence
  source (GCP, AWS, Azure, SPIRE) fetches a platform identity token for whatever audience it is given, so the
  discovery document could choose which service the workload minted a token for. This ships in a minor release
  under the security exception in the README's versioning policy. It is new Stable API.
- All four ports: `ProtectedResource.authenticate_active` / `authenticateActive` / `AuthenticateActive`, a
  request guard for tokens checked by RFC 7662 introspection, such as opaque tokens. It applies the same rules
  as `authenticate`: the introspection response's `aud` must name this resource (a response without `aud` is
  refused), and a token with `cnf` is refused. Before this, a resource guarding opaque tokens had to call
  `validate_active` itself, which accepts a response with no audience or with another audience the validator
  accepts, and doesn't look at `cnf`. A failed introspection call raises (Go: returns an error), as
  `validate_active` does. `validation/introspection.json` pins the guard's verdict for every case
  (`expect_guard`), with three new `cnf` cases. It is new Stable API: Python `authenticate_active`,
  TypeScript and Java `authenticateActive`, Go `AuthenticateActive`.
- Component configuration references cover client adapters, evidence, keys and builders, issuance,
  external signers, validation, protected resources and Python authorisation challenges.
  They include defaults, units, per-call controls and offline examples.
- Documentation guides for configuration, builds, deployment, examples and troubleshooting.
  Every language README now includes a complete offline builder example and an API-call example.

### Deprecated

- Java: the `ClientAttestation(String attesterUrl)` constructor. It can't set the evidence audience, so
  `token()` on a client built with it now always throws. Use `ClientAttestation.builder(attesterUrl)
  .evidenceAudience(...).build()`. It goes in the next major release.

### Changed

- All four ports: `DpopProofBuilder` (Go `NewDpopProofBuilder(...).URI(...).Build()`) refuses, with its
  argument error, a URL that the shared `htu` rule in `vectors/README.md` gives no `htu`: a relative URL
  (Python signed `/relative/path` as `:///relative/path`), a scheme other than `http` and `https` (`wss`
  included), a non-ASCII (IDN) host (give the `xn--` form), a host with characters other than letters,
  digits, `-`, `.`, `_` and `~`, and a port that is not a number up to 65535. For a DPoP-bound token,
  `RequestHeaders` / `requestHeaders` / `request_headers` refuse the same URLs with the client's error. A
  client configured for DPoP (`dpop_combined`) checks the URL before it fetches the token, so a refused
  URL no longer costs a mint and a token request on a cold cache; a DPoP token from a client configured
  otherwise is checked once it arrives. A Bearer token carries no `htu`, so for it the helpers still
  refuse only a backslash, whitespace or a control character. So Go's `RoundTripper` returns a
  `*ClientAttestationError`, and sends nothing, for a DPoP-bound request to a Unicode host (`net/url`
  writes the host percent-encoded, and the rule refuses that); give the `xn--` form.
- All four ports: the resource helpers refuse a resource URL that isn't https, as every other credential
  call already did. Loopback hosts and `allow_insecure` / `allowInsecure` / `WithAllowInsecure()` are
  exempt. This covers `request_headers` / `requestHeaders` / `RequestHeaders`, and through them
  `requests_auth`, `httpx_auth`, TypeScript `fetch`, the Go `RoundTripper` and Java `authorize` / `send`.
  A relative URL, which has no scheme, is refused too. A Stable behaviour change, made under the security
  exception in the README's versioning policy.
- Java: `send(client, request, method, uri, handler)` throws `IllegalArgumentException` when `request`'s
  URI is on another origin than `uri`, the URL the credentials are built for. A Stable behaviour change,
  made under the same exception.
- Examples: the issuance-bootstrap examples (Go, Python, TypeScript) and the one-call-token examples
  (Python, TypeScript) default to `https://pf.example.com` instead of a plain-http host. They refuse a
  plain-http `ISSUER` or attester URL for anything but loopback unless you set `ALLOW_INSECURE=1`.
- Python (Experimental `authz_challenge`): **the `private_key_jwt` client assertion's `aud` is now the AS's
  issuer, one string**, as CIBA Core §7.1, FAPI-CIBA and the OpenID Foundation's 2025 audience-confusion
  guidance ask. Before, a `CibaClient` sent the URL it posted to: the `bc-auth` endpoint on `bc-auth` and
  the token endpoint on each poll. A caller that passes `issuer` to `CibaClient` and uses a
  `PrivateKeyJwtAuth` without `extra_audiences` now sends `aud` = that issuer, and an AS that accepts only
  its endpoint URL answers `invalid_client`. To send what was sent before, set
  `PrivateKeyJwtAuth(..., audience_mode=AUDIENCE_ENDPOINT)` (or pass `audience_mode=AUDIENCE_ENDPOINT` to
  `private_key_jwt_assertion`). `CibaClient` passes its `issuer` to `client_auth.apply` on every call as a
  keyword, `apply(endpoint, form, issuer=...)`, when the implementation takes it; it no longer copies a
  `PrivateKeyJwtAuth`, so later changes to the caller's object (a rotated key and `kid`) apply, and a custom
  `ClientAuth` can receive the issuer too. A `ClientAuth` whose `apply` takes only `endpoint` and `form` is
  called as before. `PrivateKeyJwtAuth` and `private_key_jwt_assertion` take new `issuer` and
  `audience_mode` arguments (`AUDIENCE_ISSUER`, the default, or `AUDIENCE_ENDPOINT`). An issuer set on the
  `PrivateKeyJwtAuth` wins over the client's; with no issuer at all the endpoint called is the audience. An
  empty `issuer` or an unknown `audience_mode` raises `ValueError`. `extra_audiences` is the other explicit
  opt-in: it makes `aud` an array of the audience above, the endpoint called and the extras; empty entries
  are ignored, and with none left `aud` stays one string.
- Go, Java and Python: SDK HTTP calls go through a proxy only for https to a host that is not loopback,
  link-local or a cloud metadata server, as a CONNECT tunnel that keeps TLS end to end. Plain http always
  goes direct, so an OpenBao `X-Vault-Token` or a metadata identity token no longer crosses a proxy in
  cleartext. Go uses `HTTPS_PROXY` (and `NO_PROXY`) for a client without a `Transport` of its own, the
  token validator's JWKS and introspection clients included; Python uses `HTTPS_PROXY` (and `NO_PROXY`),
  read once, and no longer the macOS or Windows system proxy settings; Java uses the JVM's proxy settings
  (`https.proxyHost`). Breaking if a plain-http endpoint (an OpenBao reached with `allow_insecure`) is
  reachable only through `HTTP_PROXY`: serve it over https, or reach it without the proxy. TypeScript is
  unchanged: `fetch` uses no environment proxy unless Node is started with `NODE_USE_ENV_PROXY=1`, which
  then proxies plain http too.
- All four ports: an SDK HTTP call refuses a URL with userinfo (`https://user:password@host/`) with a
  transport error, before connecting. Python sent it as part of the `Host` header and a proxy's `CONNECT`
  line, and TypeScript's `fetch` already refused it.

### Fixed

- Go: the validator's `http.failed` event for introspection logs `reason=too_large` for an oversized body
  and `reason=malformed` for one that isn't a strict JSON object, as docs/logging.md says. It logged `network`.
- Go: every SDK HTTP request has a timeout. `WithTimeout(d)` with `d <= 0` means the 20 s default, and a
  `WithHTTPClient` client whose `Timeout` is zero or negative gets the configured timeout. Before, either
  meant no timeout at all. A zero or negative `GoogleMetadataSvidSource.Timeout` means its 5 s default.
- Documentation uses the published TypeScript package name and the current package release destinations.
  Resource-server examples state the Bearer guard's proof-verification limits.
- Python: an SDK HTTP call's timeout bounds the whole call (connect, a proxy's `CONNECT` reply, the TLS
  handshake, headers and body), as in the other ports. It used to apply to each socket operation, so a
  server sending a byte at a time could hold a call, and the client's token lock, open indefinitely. Name
  resolution is still outside it. When a host has several addresses, each connect attempt gets an equal
  share of what is left, so an address that never answers doesn't stop the next one being tried.
- All four ports: transport error messages name a URL without its userinfo, query or fragment. Go's
  error for a failed request carried the query, Python's carried the password from userinfo, and Java's
  and TypeScript's carried both.
- Python: `AzureImdsSvidSource` requests a managed-identity token only for the Entra resource the caller
  configured, `resource=` or `CLIENT_ATTESTATION_AZURE_RESOURCE` when auto-detected. The resource used to be
  the attester's `evidence_audience` from discovery, and IMDS issues a token for any resource it is asked for,
  so an attester could obtain a working token for, say, Azure Resource Manager. Breaking for Azure users
  (the source is Experimental): set the variable or pass `resource=`. Without it, or when the attester asks for
  another audience, `fetch` raises `ClientAttestationError` and IMDS is not called.
- Examples: the issuance-bootstrap examples no longer follow redirects from the token endpoint, so the
  attestation and PoP are never resent to another host. A 3xx is reported as an error. The token request
  also has a timeout and a 1 MiB cap on the response.
- Examples: no example prints an access token or a prefix of one. They print its length and a short
  SHA-256 fingerprint instead.
- Examples: the protected resource servers listen on 127.0.0.1 only. The Go server sets read, write,
  header and idle timeouts. The Python server handles each connection in its own thread with a socket
  timeout, so one slow client no longer blocks it.
- Java, TypeScript: `bearerToken`, and so `ProtectedResource.authenticate`, parses the `Authorization` header
  in linear time. The old regular expression backtracked on a crafted header (a run of spaces and a
  character it couldn't match), so one unauthenticated request cost about a minute of CPU in Java and
  blocked the TypeScript event loop for seconds.
- All four ports: `bearerToken` (Python `bearer_token`) returns the same token for every header, pinned by
  the new shared cases in `validation/bearer.json`. Only space, tab, CR, LF and FF separate or surround the
  token, and a token may contain any character but LF. Some malformed headers that were accepted before now
  get HTTP 401: a vertical tab before or after `Bearer` (Python, Java, TypeScript), an NBSP or other
  non-ASCII space before or after it (Python, TypeScript), a token containing LF (Python), and a trailing
  vertical tab (Java) or trailing vertical tab or non-ASCII space (Python, TypeScript), which is now kept as
  part of the token instead of trimmed. Java and TypeScript now accept a token containing CR, U+2028 or
  U+2029 (and Java U+0085), as Go always has. In Python a header of `Bearer` followed only by whitespace
  now yields a one-character token, as in the other ports, so the reply is 401 `invalid_token` rather
  than a bare 401.
- All four ports: the token validator refuses a plain-http `jwks_uri` or introspection endpoint when it is
  built, so a network attacker can't serve forged keys or read the resource server's client secret.
  Loopback hosts are exempt, as on the client. The opt-out is new Stable API: Python
  `ValidatorConfig(allow_insecure=True)`, TypeScript `allowInsecure: true`, Go `Config.AllowInsecure`, Java
  `ValidatorConfig.Builder.allowInsecure(true)`.
- All four ports: the token validator refuses a negative leeway. Python also refuses a leeway that is not an
  `int` (`NaN` switched off the `exp`, `nbf` and `iat` checks), and TypeScript one that is not a
  non-negative safe integer (`NaN` did the same, and `"60"` concatenated).
- Python and TypeScript: the validator's list options refuse a bare string or a non-string entry. A bare
  string was read as its characters, so `accepted_token_types="at+jwt"` accepted a `typ` of `t`.
- Python and Java: AS-metadata `discover` refuses a document whose `issuer` is not the issuer the metadata
  URL was built from (RFC 8414 section 3.3), and a plain-http metadata URL, `jwks_uri` or
  `introspection_endpoint` (loopback exempt). It reads the document as strict JSON. A metadata URL that is
  not a standard `.well-known` URL now needs the expected issuer. The new arguments are Stable API: Python
  `discover(..., issuer=..., allow_insecure=...)`, Java `Discovery.discover(url, issuer, httpGet)` and
  `Discovery.discover(url, issuer, httpGet, allowInsecure)`.
- All four ports: `OpenBaoTransitSigner` refuses a plain-http vault address unless the host is loopback, so
  the vault token is not sent in cleartext and the public key is not read from whoever answers. The
  Experimental API gains an opt-out: `allow_insecure=True` (Python), `{ allowInsecure: true }` (TypeScript),
  `WithOpenBaoAllowInsecure()` (Go), a trailing `boolean allowInsecure` constructor argument (Java).
- All four ports: `OpenBaoTransitSigner` refuses a transit key name with characters other than letters,
  digits, `_`, `.` and `-`, or that is `.` or `..`, before any request. Such a name could send the vault
  token to another vault path.
- All four ports: `AttestationIssuanceClient` refuses a plain-http endpoint unless the host is loopback, and
  its transport applies the same rule to every call a custom `AttesterProfile` makes. The Experimental API
  gains an opt-out: `allow_insecure=True` (Python), `{ allowInsecure: true }` (TypeScript),
  `WithIssuanceAllowInsecure()` or the `AllowInsecure` field (Go), a trailing `boolean allowInsecure`
  constructor argument (Java).
- All four ports: `AttestationIssuanceClient.bootstrap` returns an error when a profile mints no attestation,
  rather than panicking (Go), throwing `NullPointerException` (Java), `AttributeError` (Python) or
  `TypeError` (TypeScript), or returning an empty attestation.
- Python (Experimental `authz_challenge`): the resolvers name a ceremony by its display `reference` in
  `Hooks.log`, never by the handle that `poll` and `verify_resume` take. A failed push returns the
  `reference` in `Unavailable.detail` instead of the handle.
- Python (Experimental `authz_challenge`): a live ceremony is reused only for the `initiator` that raised it.
  Another initiator resolving the same instruction for the same subject gets `Unavailable` until that
  ceremony ends, instead of the first initiator's handle.
- Python (Experimental `authz_challenge`): `CibaClient.poll` reports `approved` only for a 200 whose body is a
  JSON object with a non-empty `access_token`. Any other 200 stays `pending` and sets `last_error`.
- Python (Experimental `authz_challenge`): `CibaClient.request` raises `ValueError` when `extra` sets `iss`,
  `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`, `login_hint` or `binding_message`. Before, `extra` overrode
  them, including in the signed request object.
- Python (Experimental `authz_challenge`): `CibaClient.poll` no longer raises `AttributeError` when a non-200
  token response is JSON but not an object. It reads the body as unparseable and stays `pending`.
- Python (Experimental `authz_challenge`): `CibaClient.poll` holds its lock only while it reads and updates
  the poll state, not during the token-endpoint call, so one slow AS answer (up to the 30-second timeout)
  no longer holds up every other ceremony's poll. A second poll of a request whose call is still under
  way answers from cache, so the AS still sees at most one call per interval. That poll does not end the
  request on the client clock, even past its deadline: the AS's answer to the call in flight is honoured
  when it arrives, so an approval given just before the deadline reaches every caller instead of both
  being told `expired`. Once a final verdict is in, a later transport error no longer changes `last_error`,
  and the `authz.ciba_polled` event logs the outcome `poll` returned. `CibaRequest.to_dict` now includes
  `last_poll_at`, and `rehydrate` starts the throttle from the later of that and now; a stored time more
  than `interval` seconds ahead is ignored.
- Python (Experimental `authz_challenge`): `transaction_hash` (and so `resolve` and `verify_resume`) raises
  `ValueError` for a non-string object key or a tuple anywhere in the instruction. JSON prints `{1: x}` and
  `{"1": x}`, `{True: x}` and `{"true": x}`, or a tuple and a list the same way, so different Python values
  shared a hash. The hash is over exact code points: it does not normalise Unicode, and now says so.
- All four ports: the logging backstop also redacts any value under a credential key (`auth_req_id`, `code`,
  `handle`, `token`, `secret`, `password`, `x-vault-token`, any key ending in `_token`, and the rest listed
  in `docs/logging.md`), and any value carrying a Vault or OpenBao token (`hvs.`, `hvb.`, `hvr.` and the
  older `s.`, `b.`, `r.` forms) or an `Authorization` header value anywhere in it (`Bearer x`, ` Bearer x`,
  `Authorization: Bearer x`; a bare `Bearer` or `token_type=Bearer` passes). Before, only values containing
  `eyJ` were caught (and in Python, a fixed list of keys), so an opaque access token, `auth_req_id` or
  ceremony handle passed to a log call by mistake would have been written. No event the SDK logs today is
  affected. The new `validation/redaction.json` holds cases that all four ports' logging tests read. In
  TypeScript, a value under a credential key whose `toString` throws is logged as `<redacted>` instead of
  throwing out of the log call.
- All four ports: an error about a 2xx response the SDK can't use (malformed JSON, a duplicate member,
  trailing data, a form-encoded body, a missing `access_token` or `attestation`) no longer keeps or quotes
  the body, which can hold the access token or attestation. `body` is now null/empty for these errors, and
  the message and cause chain don't quote the body. Java put up to 512 characters of it in the
  `TransportException` message that became the cause of the token or mint error, and chained the jose4j
  parser exception, which can quote it. TypeScript chained V8's `SyntaxError`, which quotes part of it.
  Go, Python and TypeScript kept it in `body`.
- All four ports: an error body is at most the first 512 characters of a non-2xx response, as documented.
  The token endpoint's error body was kept in full in every port, as were Java's discovery, challenge and
  mint error bodies, Python's `TransportError.body` and the Go, Python and TypeScript `IssuanceError`.
  A caller that parses a long OAuth error from `body` now gets truncated JSON. Java no longer appends
  `...` to a cut body (`body()`, `TransportException.body()` and the messages that quote one), so a
  long body comes back as exactly the first 512 characters, a prefix of the response, as in the other
  ports.
- All four ports: values that hold a credential print it redacted. Go adds `String` and `GoString` to
  `ClientAttestation`, `ClientAttestationCredential`, `OpenBaoTransitSigner`, `MintRequest`, `MintResult`,
  `IssuedAttestation` and `StaticSvidSource`, and `LogValue` to the last four (Stable and Experimental
  types alike; additions only). Java's `MintRequest` and `MintResult` override `toString` (Experimental).
  Python's `MintRequest`, `MintResult` and `JwtSvid` leave the evidence, challenge, attestation and token
  out of `repr`. TypeScript's `MintRequest.evidence` and `.challenge` and `IssuedAttestation.attestation`
  are now getters over private fields, and `StaticSvidSource` keeps its SVID in a private field, so
  `JSON.stringify` and `console.log` don't show them (reads are unchanged; Experimental and Stable).
- Python: `trace_redact=True` also redacts any request-body value that looks like a JWT. A custom attester
  profile's own members, such as `evidence` and `pop` in the documented example, appeared verbatim in the
  trace.
- Python: `CibaError` keeps at most 512 characters of a non-200 `bc-auth` body, and none of a 200 one
  (which carries the `auth_req_id`).
- All four ports: `ClientAttestationBuilder.confirmationJwk` (Python `confirmation_jwk`, Go
  `ConfirmationJWK`) refuses a JWK with a private or secret member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`,
  `k`), a `kty` other than `EC` or `RSA`, an EC curve other than P-256, P-384 or P-521, or a missing public
  member, and copies only `kty`, the public members and `kid` into `cnf.jwk`. Before, the map was signed
  into the attestation as given, so a private JWK published its private key. Python, TypeScript and Java
  throw when the JWK is set; Go returns the error from `Build`.
- All four ports: the attestation builder refuses an `exp` that is not after `iat` (a zero or negative
  `expiresIn`, or an `expiresAt` at or before `issuedAt`). Before, it signed an already-expired attestation.
  There is no upper bound.
- All four ports: `SigningKeyPair.fromJwk` (Python `from_jwk`, Go `FromJWK`) refuses an algorithm other
  than ES256/384/512, RS256/384/512 or PS256/384/512, an EC key on another curve than the algorithm's, an
  RSA key under 2048 bits, and a JWK whose public members are not its private key's. Go and Python signed
  with RSA-1024; Go signed a P-384 key as ES256 (a 96-byte signature no verifier accepts); Go and Java
  accepted another key's `x`/`y` or `n`, so proofs were signed by one key while `kid`, `cnf.jwk` and the
  DPoP `jwk` named another. Go's `FromJWK` no longer loads an Ed25519 key for `EdDSA`, which no other port
  did and nothing documented. Java refuses an EC key declared as `RS256` when it is loaded rather than when
  it signs.
- All four ports: a loaded key's public JWK is re-encoded from the key: EC coordinates at the curve's full
  width, RSA `n` and `e` in minimal octets, and only `kty`, the key members and the thumbprint `kid`. Go and
  TypeScript published a short `x` or a zero-padded `n` as given, Java kept the input's other members (`use`,
  `x5u`, `alg`, ...), and Python's RSA public JWK carried `key_ops`. The same key now gives the same `kid`,
  the same `cnf.jwk` (`kty`, the key members and `kid`) and the same DPoP header `jwk` (those members
  without `kid`) in every port.
- Go: a key loaded with `FromJWK` signed PoP and attestation headers with the JWK's own `kid` (jwx copies
  it into the header), while `KeyID()` and `cnf.jwk.kid` were the RFC 7638 thumbprint, and its DPoP proofs
  carried that `kid` too. The header `kid` is now always the thumbprint, and DPoP proofs carry none, as in
  the other ports.
- Java: a DPoP proof's `jwk` header carried the key's `kid`, which the other ports leave out. It is now the
  `cnf.jwk` members without `kid`.
- All four ports: an attestation signed through a `JwsSigner` refuses a signer algorithm other than
  ES256/384/512, RS256/384/512 or PS256/384/512, an empty signature, and an ES signature that is not the
  fixed-width `r||s` (DER or truncated). A signer reporting `none` with an empty signature produced an
  unsigned attestation.
- Go, Python and Java: `OpenBaoTransitSigner` refuses a transit key whose public key is on another curve
  than its `type` says (TypeScript already did). Python reads the vault's signature as strict base64url; it
  skipped characters outside the alphabet.
- All four ports: `MintRequest.sign`, and so `instanceProof`, refuse the `typ` of the SDK's own credentials
  (`oauth-client-attestation+jwt`, `oauth-client-attestation-pop+jwt`, `dpop+jwt`), compared
  case-insensitively and with or without `application/`. A custom `AttesterProfile` could use it to have the
  instance key sign a Client Attestation PoP or DPoP proof with claims of its choosing.
- Python (Experimental `authz_challenge`): a resolver polls and resumes only the ceremonies it raised, and
  `verify_resume` accepts only an approval its own resolver observed. With shared hooks or a shared store,
  `ProofingResolver.verify_resume` accepted a ceremony a `CibaResolver` tap or a `WebConsentResolver` click had
  approved as a verified credential presentation. `Ceremony` gains `resolver` and `approved_via`, which a
  deployment's store must persist; a ceremony persisted by an earlier version can no longer be polled or
  resumed. `CibaResolver` and `WebConsentResolver` still take `identity_proofing` challenges, but their
  approval is a tap or a click and `ProofingResolver` never accepts it.
- Python (Experimental `authz_challenge`): `verify_resume` reads the ceremony back through `Hooks.rehydrate`
  before accepting it and refuses one the store marks used, so a replica holding a stale in-memory copy no
  longer accepts a code another replica already used. If the use can't be recorded (the `persist` hook raises)
  the resume is refused instead of accepted. The new optional `Hooks.consume(ceremony) -> bool` hook makes the
  write an atomic compare-and-set.
- Python (Experimental `authz_challenge`): any exception during a CIBA push now releases the claimed ceremony.
  Before, only `CibaError` did: a custom transport's error, a `client_auth` failure or an `interval` of `1e400`
  (which raised `OverflowError`) left a claimed ceremony that never expired, and every later `resolve` for the
  instruction returned it as `reused` without pushing. `ProofingResolver` had the same gap. A push that failed
  no longer counts against `max_attempts`.
- Python (Experimental `authz_challenge`): `CibaClient` reads `bc-auth`'s `interval` as at most 600 seconds and
  `expires_in` as at most 3600, and uses 120 when `expires_in` is missing, zero or unreadable (CIBA requires
  it), so a ceremony always ends on the client's clock.
- Python (Experimental `authz_challenge`): `CibaClient` refuses a plain-http `bc_auth_endpoint` or
  `token_endpoint` unless the host is loopback. The opt-out is `allow_insecure=True`.
- Python (Experimental `authz_challenge`): `ProofingResolver` no longer lets the PEP choose the credential. It
  asks for the challenge's `doctype` only when it is in the new `doctypes` allowlist, otherwise the caller
  must pin `instruction["doctype"]`, and it refuses a challenge whose `doctype` contradicts the pinned one.
  `verify_resume` needs the doctype in `instruction` unless the proofed one is in `doctypes`.
- Python (Experimental `authz_challenge`): `WebConsentResolver` gains `verify_resume`, with the same instruction
  binding, single use and `max_approval_age` as the other resolvers. It refuses an empty subject. The consent
  URL is out of `Pending` and `PollResult` reprs, moves from `PollResult.detail` to `PollResult.consent_url`,
  and is no longer returned once the ceremony has ended.
- Python (Experimental `authz_challenge`): `parse_www_authenticate` takes linear time on any input (a long
  token took seconds before) and ignores a header over 8 KiB. It returns only the Bearer challenge's params:
  a later challenge's params (`Bearer realm="api", DPoP error="insufficient_scope"`) were merged into it, and
  a Bearer challenge after another scheme is now found. `parse_challenge` ignores a body over 64 KiB and
  reads one nested too deeply to parse as not JSON, instead of raising `RecursionError`, and drops a field
  that is not a string (or a list of strings) instead of using its Python repr. `CibaClient` reads such responses as
  unparseable too.
- Go: `ClientAttestation.RoundTripper` no longer attaches the access token (or a DPoP proof) when an
  `http.Client` follows a redirect. `http.Client` calls the transport again for every hop, so a resource
  that answered 3xx could have the token sent to any host and scheme in `Location`. The hop now fails
  with a `*ClientAttestationError` and the target is not contacted; set `CheckRedirect` to return
  `http.ErrUseLastResponse` to get the 3xx back instead. This is a behaviour change: every hop now
  fails, including a same-origin one such as `/items` to `/items/`, and the error is the SDK's usual
  "refusing to follow HTTP redirect" one.
- Python: `requests_auth()` no longer sends a DPoP-bound access token, or a DPoP proof, to a redirect
  target. `requests` builds each hop from the original request and runs the auth hook on it, so a 3xx
  (including one returned to the nonce retry) forwarded the proof, and a target that answered with a
  DPoP nonce challenge got a retry carrying the token and a proof signed for its own URL. Once a
  response arrives the token and proof are now taken off the request `requests` copies for hops, and
  the hook ignores responses from any origin other than the request's. Redirects are still followed,
  without credentials. `httpx_auth()` with `follow_redirects=True` no longer retries, or remembers a
  nonce from, a response whose redirect chain left the request's origin. Same-origin redirects keep
  nonce handling. httpx still forwards the original proof (not the token) on a cross-origin hop, so
  leave `follow_redirects` off with it.
- Python: `CibaResolver` no longer writes the first characters of the CIBA `auth_req_id` to `Hooks.log`
  when it pushes a ceremony. The `auth_req_id` is what the token endpoint accepts for the grant.
- All four ports: a token endpoint's `expires_in` is read the same way everywhere. A JSON number or a
  string of decimal digits is accepted and capped at 24 hours; a missing, non-numeric, infinite, zero or
  negative value means the token is not cached. Go no longer fails the flow on a string or fractional
  `expires_in`; Python no longer keeps the previous expiry when the value is invalid.
- All four ports: a negative expiry skew is rejected when the client is built (TypeScript and Python
  also reject a non-finite one).
- All four ports: GCP metadata auto-detection and `GoogleMetadataSvidSource` require HTTP 200 and the
  `Metadata-Flavor: Google` response header, so another host answering `metadata.google.internal` is
  not used. Python's Azure IMDS probe requires HTTP 200 and the documented instance-metadata JSON.
- All four ports: `FileTokenSvidSource` refuses a path that is not a regular file (a FIFO, `/dev/zero`)
  or is larger than 64 KiB, with the port's `EvidenceNotFound` error.
- Go and Python: SDK GCP metadata requests (and Python's Azure IMDS requests) no longer go through
  `HTTP_PROXY` or another proxy environment variable, so a proxy never sees the metadata server's token.
  Java: they ignore the JVM's proxy settings.
- TypeScript: `ClientAttestation.fetch` reads at most 64 KiB of a 400 response with a `DPoP-Nonce`
  header, within the client's timeout, and leaves the caller's body intact. A longer body is not a
  nonce challenge. Python's `requests_auth` and `httpx_auth` read at most 64 KiB the same way (a read
  error during that peek still reaches the caller, after the bytes read before it). Go applies the same
  rule.
- TypeScript: `SpireWorkloadApiSvidSource` kills a `spire-agent` that has not exited within 30 seconds,
  as the other ports already did.
- All four ports: the client's DPoP nonce memory is bounded. A `DPoP-Nonce` longer than 1024 characters
  is ignored (not remembered, and a challenge carrying one is not retried), and nonces are kept for at most
  256 origins, the one stored longest ago going first. Before, every nonce a DPoP-bound response carried
  was kept for its origin with no limit, so responses from many hosts could grow the client's memory
  without bound. Java keys a nonce by the URL's authority when `URI` finds no host in it (a name with
  `_`), not by the URL's path.
- All four ports: a `use_dpop_nonce` retry carries the nonce of the challenge it answers, not whichever
  nonce was stored for the origin last (a concurrent response could have replaced it).
- All four ports: `RequestHeaders` / `requestHeaders` / `request_headers` and `DpopProofBuilder` refuse a
  URL with a backslash, ASCII whitespace or a control character before its query or fragment: the
  client's error type from the header helpers, the builder's argument error from `DpopProofBuilder`.
  Python's `request_headers` read such a URL with `urllib.parse`, which takes
  `https://evil.example\@as.example/t` to be at as.example while `requests` sends it to evil.example, so
  evil.example got the token and a proof it could replay once at as.example. Give `request_headers` the
  exact URL your HTTP client sends; `requests_auth()` and `httpx_auth()` already use the prepared URL
  (`httpx_auth()` now refuses a raw backslash in a path, which httpx sends as it is). TypeScript's `fetch`
  signs the URL as fetch parses it, so a backslash there still works.
- All four ports: `DpopProofBuilder` and the DPoP nonce memory read a URL by one rule (described in
  `vectors/README.md` and pinned by the new shared `vectors/htu.json`), so every port signs the same `htu`.
  Go drops a zero-padded default port (`:00443`) as the others did. Java and Python percent-encode a
  non-ASCII path character as UTF-8 as Go and TypeScript did. TypeScript keeps dot-segments and an IPv6
  literal as written in a URL given to the builder or `requestHeaders` (`fetch` still signs the URL as
  WHATWG parses it). TypeScript gave `https:as.example.com/t`, and a URL with leading whitespace, an `htu`
  with no path, so the proof for `/t` was valid for the origin root; every port now refuses both. Every
  other ASCII character in the path is signed as written, `[`, `]`, `|`, `^` and a `%` that does not start
  a `%XX` escape included, so the `htu` is the request target the SDK's own integrations send: Go's
  `RoundTripper`, TypeScript's `fetch` and Python's `httpx_auth` send `/items[0]` as it is (Go escapes `[`
  and `]` only when something else in the path needs escaping), and a resource compares `htu` after RFC
  3986 normalisation, which does not decode `%5B`. Python's `requests_auth` and Java's `send` sign the
  target as their client escapes it. Callers of `RequestHeaders` / `requestHeaders` should pass the URL
  their client sends (Go `req.URL.String()`, TypeScript `new URL(u).href`).
- Java: `ClientAttestation.send` closes (an `InputStream` or `Stream` body) or cancels (a `Publisher`
  body) a nonce challenge before it retries, so a streaming `BodyHandler` no longer holds a connection per
  challenged call. It also sees a 400 `use_dpop_nonce` challenge whatever the `BodyHandler`: at most 64 KiB
  of the body is read first and the handler still gets all of it. A longer 400 body is not a challenge,
  as in the other ports.
- Java, Python, TypeScript: the token cache runs on a monotonic clock (`System.nanoTime`,
  `time.monotonic`, `performance.now`), so stepping the wall clock back no longer serves an expired token,
  and stepping it forward no longer drops a good one. Go already did.
- All four ports: `SpireWorkloadApiSvidSource` (Go `SpireWorkloadAPISvidSource`, Java
  `SvidSource.SpireWorkloadApi`) reads the JWT-SVID from the output `spire-agent api fetch jwt` really
  prints, `token(<spiffe id>):` with the token on the next, tab-indented line. It returned an empty SVID
  for that output (Go with no error). The one-line `token(<spiffe id>): <jwt>` form and a bare JWT line
  still work. The first token is taken, `hint(...)` and `bundle(...)` sections are skipped, and only a
  compact JWS whose header is a JSON object with an `alg` counts: a dotted string such as a version number
  or a log line is no longer taken for a token. Output with no token is an `EvidenceNotFound`
  (`EvidenceNotFoundException` in Java) that gives the output's size, not the output, which can hold the
  token and the bundle. The agent's stderr is not read as output (Java merged it into stdout). Java and
  Python now fail when the agent exits with a non-zero status, as Go and TypeScript did, and TypeScript's
  error for that no longer carries the agent's stderr.
- All four ports: the SPIRE source reads at most 1 MiB of `spire-agent` stdout. An agent that prints more
  is killed and the fetch fails with `spire-agent fetch failed: output is larger than 1048576 bytes`
  (Python `RuntimeError`, Java `IllegalStateException`). Go and Python read stdout without a limit, and
  Java kept the first MiB and dropped the rest, so a token in it still counted. The agent's stderr goes to
  the null device in every port: Python buffered all of it, Go up to 64 KiB, and in TypeScript 1 MiB of
  stderr failed a fetch that had a token on stdout. TypeScript's error for an agent that could not start
  no longer passes Node's error through, whose message can carry the agent's stderr: it is `spire-agent fetch failed: could
  not run <bin> (<code>)`, with `code` kept (`ENOENT` when the agent is not installed). Python's timeout
  is still `subprocess.TimeoutExpired`, now without the agent's output attached. The agent's exit decides
  the outcome in every port: once it has exited, stdout is read for at most 250 ms more, then the pipe is
  closed, so a helper the agent started that holds stdout open no longer delays a fetch. (A helper that writes
  more than 1 MiB to stdout inside those 250 ms still fails it in Go, Python and TypeScript.) On exit
  status 0 the output read so far is parsed (the first token wins); on any other status, or if the agent
  was killed, the fetch fails. Before, a fetch where such a helper held stdout open failed after 1 second
  in Go and waited up to another 30 seconds in Java and Python (then failed if the helper had not closed
  it), while TypeScript returned the token. The shared cases are in `vectors/spire-cli.json`.
- All four ports: the SPIRE source reads the agent's output by the same rules. Only ASCII space, tab and CR
  around a line or value are ignored, so a leading BOM (trimmed only by TypeScript), an NBSP (trimmed by all
  but Java) or a vertical tab or form feed is no longer trimmed and the line is not a token. A label with no value, such as `hint(...):`,
  no longer takes the next line as its value when that line is another label, so a following one-line
  `token(...): <jwt>` is found. A token's header must be canonical base64url of strict JSON, read by the
  token validator's parser: Java accepted `{"alg":"ES256",}`, Go, Python and TypeScript a duplicate `alg`,
  and Python and TypeScript a header starting with a BOM. Python's "could not parse" error counts lines by
  LF alone, as the other ports do.
- Python: the validator's copy of its config no longer normalises `accepted_token_types` a second time, so a
  configured `application/application/x` stays `application/x` instead of becoming `x`.

### Security

- Java: `DpopProofBuilder` and `ClientAttestation.requestHeaders` no longer put the userinfo
  (`user:password` included) into a DPoP proof's `htu` when `java.net.URI` finds no host in the URL (a host
  name with `_`, such as `https://user:pw@my_host/t`), so the password was signed into a proof sent to the
  resource. It also kept a default port and the original case there. This shipped in 1.0.1.
- Python: the minimum dependency versions no longer allow releases with known vulnerabilities. `pyjwt`
  is now `>=2.10.1` (CVE-2024-53861), `cryptography` is `>=42.0.4` (CVE-2024-26130) and the optional
  `requests` extra is `>=2.32.4` (CVE-2023-32681, CVE-2024-35195, CVE-2024-47081). pip upgrades an older
  installed copy when you upgrade the SDK.
- Python, TypeScript and Java: the validators choose a signing key as `validation/SEMANTICS.md` says. A
  token without `kid` was accepted when the key set held several JWKs without `kid` (they were stored as
  one key), a token `kid` of `""` matched a JWK whose `kid` was `""`, and of two JWKs with the same `kid`
  the last was used. Now a token without `kid` needs a set of exactly one key, an empty `kid` matches
  nothing, and the first JWK with the `kid` that may be used for the token's `alg` wins. Go already did
  this, but stopped at a first JWK that declared another `alg`; it now passes over it.
- Go and Python: an EC key verifies only the algorithm of its curve (P-256 `ES256`, P-384 `ES384`, P-521
  `ES512`). A P-256 JWK without `alg` verified `ES384` tokens. Both also refuse RSA keys under 2048 bits,
  as TypeScript and Java did. Either is `invalid_signature`.
- TypeScript: an RSA JWK without `alg` verifies every accepted `RS*` and `PS*` algorithm, as in the other
  ports. It verified only `RS256`.
- All four ports: a JWK that isn't a signature-verification key is skipped: a `use` other than `sig`, a
  `key_ops` without `verify`, or a private key member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`).
- Go: a JWK it can't read (an unknown `kty`, a `kid` that isn't a string, an RSA key without `e`, an entry
  that isn't a JSON object) is left out and the rest of the set still counts, as in the other ports. It made
  the whole set fail: `New` refused a static JWKS, and a fetched one was treated as malformed, so every token
  got `key_not_found`.
- TypeScript: a JWK whose `key_ops` holds `verify` and other operations (`["sign","verify"]`, as exported
  from a key pair) verifies signatures, as in the other ports. WebCrypto refused to import it, so the key
  was skipped. An entry of `keys` that isn't a JSON object is skipped; in a static JWKS it threw.
- Python: an entry of `keys` that isn't a JSON object is skipped. A number or `null` raised `TypeError`.
- All four ports: after a failed JWKS fetch, `key_not_found` has the fixed description `signing keys
  unavailable`. The description carried the fetch error (the internal JWKS host, dial errors, up to 512
  characters of the issuer's response) into `WWW-Authenticate`, and in Python a U+FFFD in it could make a
  WSGI server fail to set the header. The failure is still logged as `jwks.fetch_failed`.
- Java: the strict JSON reader takes only ASCII hex digits in a `\u` escape; it took Arabic-Indic digits
  and fullwidth letters. It reads an integer of more than 19 digits as a double rather than a `BigInteger`,
  whose parsing is quadratic and ran on the unverified header.
- Python and Java: once the key set is stale, a request whose key is already held uses it rather than
  waiting for another request's JWKS refresh. A request for a `kid` not yet held still waits for a fetch in
  flight, as in Go and TypeScript.
- Go and TypeScript: the same. Such a request waited for the other request's fetch, up to the 10 second
  timeout, or for as long as an injected `httpGet` without a timeout took.
- Java and TypeScript: the JWKS cache ages, and spaces its refetches, on a monotonic clock. It used the wall
  clock (TypeScript `Date.now`, Java the validator's `Builder.clock`), so a backward step in the clock
  throttled every refetch and kept a removed key trusted past the hour, and in Java a fixed
  `Builder.clock` stopped the cache refetching after its first attempt. `Builder.clock` now only sets the
  time `exp`, `nbf` and `iat` are checked against. Go and Python already used a monotonic clock.
- Go, Python and TypeScript: the token validator keeps its own copy of its config. Changing the config
  after building a validator, such as reusing a Go `Config` for a second validator, changed the live one:
  an emptied issuer let Go accept tokens without `iss`, and a changed introspection endpoint got the client
  secret without the https check. Go copies the `Config` (and its slices and `Introspection`) in `New`,
  Python the `ValidatorConfig` (its lists and `IntrospectionConfig`), and TypeScript the JWKS and
  introspection settings (it already copied the arrays). Java's config was already immutable. Python also
  runs the `ValidatorConfig` checks again on its copy, so a config changed before it is handed to the
  validator (an emptied issuer, a plain-http introspection endpoint or `jwks_uri`) is refused rather than
  used.

## [1.0.1] - 2026-10-10

A security release. Upgrade from 1.0.0. Two fixes change what some callers see - check these before you
upgrade:

- A resource that accepts DPoP-bound or mTLS-bound access tokens through `ProtectedResource.authenticate`
  now gets HTTP 401 for them. That guard receives no sender proof, so it can't accept them safely. Verify
  the proof yourself and call `validate` directly.
- Java: a credential request on an `HttpClient` built with `Redirect.NORMAL` or `Redirect.ALWAYS` now
  throws `IllegalArgumentException`. Build the client with `HttpClient.Redirect.NEVER`, which is the
  `HttpClient` default.

### Fixed

- All four ports: `ProtectedResource.authenticate` checks this resource's audience when its validator
  accepts multiple audiences. Tokens naming only another resource return HTTP 401.
- All four ports: the Bearer `ProtectedResource.authenticate` guard refuses tokens with a non-null `cnf`
  claim. Sender-constrained tokens require separate proof verification before a resource grants access.
- Go: SDK HTTP calls refuse redirects even when an injected client's redirect policy permits them.
- TypeScript: `ClientAttestation.fetch` returns redirects without resending credentials to the target.
- Java: credential send helpers require `HttpClient.Redirect.NEVER` before obtaining or sending credentials.

## [1.0.0] - 2026-10-08

The first stable release. The public API of every port is frozen under semver: [`docs/api.md`](docs/api.md)
says what is Stable, what is Experimental and what is internal, and CI fails on any change to it that isn't
deliberate. Coming from 0.3.0, read Changed and Removed below; every break is listed there.

### Added

- **The 1.0 API, frozen and written down.** [`docs/api.md`](docs/api.md) puts every public name in each
  port into one of three tiers: Stable (semver from 1.0.0), Experimental (may change in any minor
  release; each item is marked in its doc comment and listed with the reason) and Internal (not API). See
  "Status and versioning" in the README for the policy.
- **API snapshots that CI checks.** `scripts/api_surface.py` writes each port's public API from the real
  build to `docs/api-surface/{python,typescript,go,java}.txt`, and each port's CI job runs it with
  `--check`, which fails and prints the diff if the build no longer matches. An intended API change
  regenerates the snapshot in the same pull request (see CONTRIBUTING.md).
- Java: a `module-info.java` (module `global.idpartners.clientattestation`) that exports the API packages
  and not `internal`. It `requires transitive org.jose4j` and `java.net.http`.
- Java: `SigningKeyPair.fromJwk(Map<String, Object>, String)`, so a key can be loaded without jose4j types.
- Java: `ClientAttestation.LOGGER_NAME`. Go: `tokenvalidator.HTTPGetFunc` and `HTTPPostFunc`, the types
  `WithHTTPGet` and `WithHTTPPost` already took. TypeScript: the `AttesterDiscovery` type that
  `discovery()` returns.
- **Attester profiles in all four ports.** The attester-specific steps – discovering the attester's
  endpoints and building, sending and reading the mint request (including the instance proof and its
  `typ`) – now belong to an `AttesterProfile`. The built-in `PingFederateProfile` is the default and is
  exactly the previous behaviour, byte for byte on the wire. The draft-defined parts (challenge, PoP or DPoP
  proof, token request, nonce retry, caching, https rule) stay in the client, and the log events keep their
  names. See [`docs/attester-profiles.md`](docs/attester-profiles.md).
  - Static endpoints for an attester with no discovery document: `metadata=AttesterMetadata(...)` (Python),
    the `metadata` option (TypeScript), `WithAttesterMetadata` (Go), `.metadata(...)` (Java). No discovery
    request is made, and the attester URL becomes optional.
  - A custom profile: `profile=` (Python), the `profile` option (TypeScript), `WithAttesterProfile` (Go),
    `.profile(...)` (Java). `AttestationIssuanceClient` takes one too.
  - New types in each port: `AttesterProfile`, `PingFederateProfile`, `AttesterMetadata`, `AttesterTransport`,
    `MintRequest` (with `instance_proof` / `sign` helpers) and `MintResult`; and `attester_metadata()` /
    `attesterMetadata()` on the one-call client (Go's `Discovery` now returns `*AttesterMetadata`).
- TypeScript: `new ClientAttestation(options)` with the URL as `options.attesterUrl`, or none at all with
  static `metadata`. Java: `ClientAttestation.builder()` with no URL, and `Builder.attesterUrl(...)`.
- **Java: the resource-server token validator**, closing the last gap between the ports.
  `global.idpartners.clientattestation.tokenvalidator` has `AccessTokenValidator` (JWT validation with the
  same check order, stable error codes and defaults as Python, TypeScript and Go, plus RFC 7662
  introspection), JWKS caching with the same refetch cooldown, single flight, max age and size cap,
  `Discovery.discover` for AS metadata, and `ProtectedResource` for RFC 9728 metadata, bearer extraction
  and `WWW-Authenticate` challenges. It logs the same validator events through a `System.Logger` passed to
  `AccessTokenValidator.builder(config).logger(...)`. `./verify-validation.sh` now checks all four ports
  agree on the shared vectors, and CI's validation job has a JDK for it.
- **[`validation/SEMANTICS.md`](validation/SEMANTICS.md)**, the precise contract every port's validator
  implements, and 101 new shared vectors that pin it: 93 token cases (up from 11) and 19 introspection
  cases. `./verify-validation.sh` now also runs each port's `validate_active` against canned RFC 7662
  responses.
- **An injectable validator clock in every port**: Python `AccessTokenValidator(config, clock=...)` (epoch
  seconds), TypeScript `{ clock }` (epoch milliseconds), Go `WithClock(func() time.Time)` and Java
  `AccessTokenValidator.Builder.clock(...)` (now public).
- **Go: `Config.ZeroLeeway`**, because `LeewaySeconds: 0` still means the 60-second default.

### Changed

- **Go: `ClientAttestation.Discovery(ctx)` is renamed `AttesterMetadata(ctx)`**, the name every other port
  uses for the same thing. Breaking: there is no alias, because the next release is 1.0.
- **Go: `tokenvalidator.DefaultAlgorithms` and `DefaultTokenTypes` are functions** that return a new
  slice each call. They were exported slices that any importer could change to widen what a default
  validator accepted. Breaking: `DefaultAlgorithms` becomes `DefaultAlgorithms()`.
- **Go: `DefaultTokenFile` and `DefaultSpiffeSocket` are constants.** They were variables, so any importer
  could change where evidence auto-detection looked. Breaking only for code that assigned to them.
- **Java: `HttpTransport` and `SdkLogging` moved to `global.idpartners.clientattestation.internal`** (as
  `HttpTransport` and `SdkLog`), which the module doesn't export. They were public only so the SDK's own
  packages could share them, and were never API. Breaking for code that imported them: use
  `ClientAttestation.LOGGER_NAME` for the logger name. `TransportException`'s constructors are now public.
- TypeScript: `DEFAULT_ALGORITHMS` and `DEFAULT_TOKEN_TYPES` are frozen arrays, so they can't be widened at
  run time. `autoDetectEvidence()` no longer shows its test-only options parameter in the types.
- Python: `ValidationResult.success` and `.failure` are now private (`_success`, `_failure`); the
  validator builds results and the other ports never exposed them.
- Marked **Experimental** (see docs/api.md for why): the attester-profile interface (`AttesterProfile`,
  `AttesterTransport`, `MintRequest`, `MintResult`), `OpenBaoTransitSigner`, the issuance client
  (`AttestationIssuanceClient`, `IssuedAttestation`, `IssuanceError`, `INSTANCE_PROOF_TYP`), the SPIRE CLI
  and HTTP SVID sources, the log event vocabulary, Java's jose4j-typed `SigningKeyPair` methods, and the
  Python-only `authz_challenge`, `spiffe` helpers, Azure and AWS sources, `trace` and `asserted_context`.
- **The four validators now agree on every malformed or hostile token.** Before this, the shared vectors
  only covered well-formed tokens, and the ports disagreed on 32 of the new shared-config cases. The verdicts
  users will see change:
  - A signed payload that isn't a JSON object (not JSON at all, or an array, string or `null`) is
    `invalid_token` everywhere. Python, TypeScript and Java said `invalid_signature` for some of these.
  - `alg: none` (any case) and every `HS*` algorithm are `unsupported_algorithm` even when listed in the
    accepted algorithms, and refused before any key lookup. A configured `none` used to get
    `invalid_token` or `invalid_signature` depending on the port.
  - Headers and payloads are parsed as strict JSON in every port: invalid UTF-8, a byte-order mark, `NaN`,
    trailing commas, leading zeros, raw control characters, trailing data and nesting deeper than 64 levels
    are `invalid_token`. jose4j (Java) took trailing commas, leading zeros and raw control characters;
    TypeScript, Go and Java took invalid UTF-8; Python took `NaN` and a BOM.
  - **Duplicate member names are rejected** (`invalid_token`) at any depth in the header and payload, and
    in introspection responses. Python, TypeScript and Go used to keep the last value.
  - A header with `crit`, a padded or non-canonical base64url segment, or the wrong number of segments is
    `invalid_token`. Go accepted a padded segment and a `crit` header.
  - `exp`, `nbf` and `iat` must be finite numbers within ±(2^53 − 1), else `invalid_token`. Python, Java
    and TypeScript accepted `exp: 1e20`; Go overflowed it into `expired`.
  - Non-string entries in `aud` or `scp`, a non-string `scope`, and a non-string `sub` make the token
    `invalid_token` instead of being dropped.
  - A string `scp` (as Microsoft Entra ID issues it) is now read as space-delimited scopes, like `scope`.
    Every port used to ignore it and grant no scopes.
  - `scope` is split on spaces only (RFC 6749 section 3.3), so a tab or no-break space no longer separates
    scopes.
  - A non-string `typ` is always `invalid_token_type`; a non-string or empty `kid` is `key_not_found`; a
    token without `kid` only matches a key set holding exactly one key.
- **Introspection: only `"active": true` is active** in Python and TypeScript, as RFC 7662 says and Go and
  Java already did. `"true"`, `1` and other truthy values are now `inactive`.
- **Go: `ValidateActive` returns `(Result, error)`.** A failed introspection call (no endpoint, transport
  failure, non-2xx, oversized or malformed body) is now an error in every port, never an `invalid_token`
  verdict; Go was the odd one out. This is a breaking change to the Go signature.
- **Go: an explicitly empty `AcceptedAlgorithms` or `AcceptedTokenTypes` accepts nothing**, as in the other
  ports. `nil` still means the defaults.
- **Go: the introspection response cap is 1 MiB**, the same as the other ports (it was 64 KiB), and a
  larger response is an error rather than silently truncated.
- The PingFederate mint now rejects a response whose `attestation` is missing or not a string in every
  port and both clients. Before, the TypeScript and Go issuance clients returned an empty attestation.
- The https error for the attester URL names `attester_url` (Python, Java) or `attesterUrl` (TypeScript)
  instead of `pf_host` / `pfHost`.
- **TypeScript is tested in a real Workers runtime.** CI runs the bundled package in `workerd`,
  Cloudflare's open-source Workers runtime, with Node compatibility switched off (`npm run test:edge`):
  key generation, the attestation, PoP and DPoP builders, and the token validator against the shared
  validation vectors.
- Coverage floors raised to today's measured coverage: Python 95%, Go 84%, TypeScript lines 99% and
  statements 98%, Java 95% lines and 91% branches.

### Removed

- **Python: `ClientAttestation(pf_host=...)`.** Pass the attester URL positionally or as `attester_url=`.
  It was briefly a deprecated alias during this release's development; with the next release being 1.0
  it is removed instead. The other ports only ever took the URL positionally.
- Python: `urllib_http(insecure_tls=...)` (deprecated in 0.3.0); use
  `dangerously_disable_tls_verification=`. `urllib_http`, `new_code` and `new_handle` are also no longer
  exported from `client_attestation_sdk.authz_challenge` (they are internal; tests import them from
  their modules).
- Python: internal helpers that were importable without an underscore are renamed with one:
  `keys.sign_compact`, `keys.require_text`, `signer.sign_external`, `builders.url_origin`,
  `builders.normalize_htu`, `builders.access_token_hash`, `token_validator.config.is_forbidden_algorithm`
  and `normalise_type`. None was in an `__all__`.
- TypeScript: `normalizeBaseUrl` and `jwtSub` (main entry point) and `resolveConfig` (`/validator`),
  internal helpers exported by mistake; and the top-level `WELL_KNOWN_PATH`, which is
  `PingFederateProfile.WELL_KNOWN_PATH` as in the other ports.
- Go: `NormalizeHTU`, an internal helper exported by mistake.
- **Python: the top-level `token_validator` and `authz_challenge` packages**, deprecated in 0.3.0. Import
  `client_attestation_sdk.token_validator` and `client_attestation_sdk.authz_challenge` instead; the
  module contents are unchanged.

### Fixed

- **Python: the validator no longer crashes on a hostile token.** A signed token with `exp`, `nbf` or `iat`
  of `1e400` raised an unhandled `OverflowError`, and a numeric `aud` raised `TypeError`, out of
  `validate()` instead of returning a verdict. Both are now `invalid_token`.
- **Java: the Maven Central publish.** The 0.3.0 upload was rejected because the runner's Maven 3.10 put
  `maven-metadata-local.xml` and `_remote.repositories` into the bundle. `java/mvnw` now pins Maven 3.9.16
  (checked by SHA-256), and CI, the release and the verify scripts all build with it.

## [0.3.0] - 2026-10-08

### Added

- **Logging hooks in all four ports**, off by default. Python logs through the standard `logging`
  module under `client_attestation_sdk` (with a `NullHandler`); Go takes a `*slog.Logger`
  (`WithLogger`, for the token source and the validator); TypeScript takes a `logger` option with
  `debug`/`info`/`warn`/`error`; Java takes a `System.Logger` (`.logger(...)`, no SLF4J dependency). Every
  port emits the same events with the same attribute keys: discovery, evidence, challenge, mint, token
  obtained / cached / refreshed (with expiry), DPoP nonce retries, HTTP failures (host and path, never a
  query string), JWKS fetches and throttling, validation verdicts, and in Python the CIBA and challenge
  resolver steps. No token, attestation, proof, SVID, challenge, secret or key is ever logged, and each port
  has a test that runs a full flow at the most verbose level to prove it. See
  [`docs/logging.md`](docs/logging.md).

### Changed

- **Go: the module now needs Go 1.25 or later** (it was 1.23, which is out of support). It comes with
  `lestrrat-go/jwx/v2` 2.1.7 and `golang.org/x/crypto` 0.53, which need 1.25.
- **TypeScript: `jose` 6.2.12 or later.**
- **Python: the package now needs Python 3.11 or later** (it was 3.10, which reaches end of life this
  month). CI runs 3.11 to 3.14, and a separate job tests the declared minimum `pyjwt` and `cryptography`.
- **Python: `token_validator` and `authz_challenge` now live under `client_attestation_sdk`.** Import
  `client_attestation_sdk.token_validator` and `client_attestation_sdk.authz_challenge` instead. The old
  top-level names were generic enough to collide with other packages in the same environment.
- **Java publishes to Maven Central** from this release, at the same coordinates
  (`global.idpartners:client-attestation-sdk`) and signed with GPG, so installing it no longer needs the
  GitHub Packages repository or a token. GitHub Packages gets this release as well, and is then dropped.
- **TypeScript: `SigningKeyPair.generate` makes a non-extractable private key.** Nothing in the SDK needs
  to export it, so it can no longer leak through `exportJWK`. Pass `{ extractable: true }` if you persist
  the key yourself.
- **`HttpSvidSource` is documented as development-only** in all four ports. It has no caller
  authentication, so anyone who can reach its URL can get the workload's SVID.

### Deprecated

- **Python: the top-level `token_validator` and `authz_challenge` packages.** They are now thin aliases
  that re-export the new modules (submodule imports such as `from token_validator.jwks import ...` still
  work) and raise a `DeprecationWarning`. They will be removed in 0.4.0.

### Fixed

- **Python: PyJWT 2.10 or later** (it was 2.8). Before 2.10, PyJWT's `to_jwk` sometimes dropped a leading
  zero byte from an EC `x` or `y`, so about one generated key in 170 had a public JWK that RFC 7518
  §6.2.1.2 says is invalid. That JWK also changed the key's RFC 7638 thumbprint (`kid`), and a strict
  verifier would refuse it.
- **TypeScript: the package loads on edge runtimes** (Cloudflare Workers, Vercel Edge, Deno Deploy without
  Node compatibility). It used to import `node:child_process`, `node:fs` and `node:crypto` at load time and
  use `Buffer` and `process.env`, so importing anything from it failed there. Crypto, encoding and HTTP now
  use WebCrypto, `TextEncoder`/`TextDecoder`, `btoa` and `fetch`. The three evidence sources that need Node
  (`SpireWorkloadApiSvidSource`, `FileTokenSvidSource`, and the file and socket probes in
  `autoDetectEvidence`) load the built-in on first use, and throw a `ClientAttestationError` naming the
  source when the runtime has none. The public API is unchanged. A new test bundles the package for a
  neutral platform with esbuild and runs it with `process`, `Buffer` and `require` removed.

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
