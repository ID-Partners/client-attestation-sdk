# Access-token validation semantics

This is the contract every port's resource-server validator implements (Python
`client_attestation_sdk.token_validator`, TypeScript `src/validator`, Go `tokenvalidator`, Java
`global.idpartners.clientattestation.tokenvalidator`). For the same token, config and clock, all four return
the same verdict. [`tokens.json`](tokens.json), [`introspection.json`](introspection.json) and
[`config.json`](config.json) pin it: each case names the rule it tests, and
[`../verify-validation.sh`](../verify-validation.sh) fails if any port disagrees with any expected verdict. CI
runs it on every pull request.

Where a rule could go either way, it fails closed: a token the validator can't read unambiguously is refused.

## Verdicts

`validate` returns a result that is either valid or carries exactly one of these codes. They are stable: the
same string in every port, and never renamed.

| Code | Meaning |
|---|---|
| `invalid_token` | The token is malformed: not a compact JWS, a header or payload that isn't a strict JSON object, a claim of the wrong type. Also used when the signature verified but the payload is malformed. |
| `unsupported_algorithm` | The header `alg` is missing, not a string, forbidden (`none`, `HS*`) or not in the accepted list. |
| `key_not_found` | No key in the issuer's key set matches the token's `kid` and `alg`. |
| `invalid_signature` | The signature does not verify with the resolved key. |
| `invalid_token_type` | The header `typ` is present and not an accepted type. |
| `invalid_issuer` | `iss` is not exactly the configured issuer. |
| `missing_expiry` | There is no `exp`. |
| `expired` | `exp` has passed, allowing for leeway. |
| `not_yet_valid` | `nbf` is in the future, allowing for leeway. |
| `issued_in_future` | `iat` is in the future, allowing for leeway. |
| `invalid_audience` | None of the configured audiences is in `aud`. |
| `insufficient_scope` | A required scope is not granted. |
| `inactive` | Introspection only: the authorisation server did not say `"active": true`. |

`ProtectedResource` maps `insufficient_scope` to HTTP 403 and every other code to 401 with
`error="invalid_token"`. No error description ever quotes token bytes.

`ProtectedResource.authenticate` additionally requires its own `resource` in the validated token's
audience. A validator may accept multiple audiences; a token accepted for another configured audience
gets `invalid_audience` and HTTP 401 at this resource. The four resource suites exercise the same shared
`valid` token with a validator configured for two resources, and require acceptance only at its audience.

`ProtectedResource.authenticate` is a Bearer request guard. It rejects a token with a non-null `cnf`
claim as `invalid_token` and HTTP 401 because this API receives no sender proof. This includes DPoP
`cnf.jkt`, mTLS `cnf["x5t#S256"]`, and malformed confirmation values. Absent or null `cnf` retains Bearer
behaviour. All four resource suites sign and exercise these cases. Low-level `validate` remains JWT
validation only; a caller using a sender-constrained token must verify its sender proof separately.

### Bearer extraction

`bearerToken` (Python `bearer_token`, Go `BearerToken`), and so `ProtectedResource.authenticate`, takes the
token from an `Authorization` header value. Every port returns what Go's RE2 pattern
`(?i)^\s*Bearer\s+(.+?)\s*$` returns, or no token (Go `""`, the others null / `None`):

- Only space, tab, LF, FF and CR count as whitespace. A vertical tab, NBSP, U+0085, U+2028 or any other
  non-ASCII space does not separate the scheme from the token, so `Bearer<NBSP>x` has no token.
- The scheme `Bearer` matches case-insensitively in ASCII only.
- Whitespace before the scheme and after the token is dropped. The token may contain any character but LF,
  including inner spaces and CR, so `Bearer a\nb` has no token.
- When only whitespace follows the scheme, the token is the last non-LF character after the first
  whitespace character: `Bearer  ` (two spaces) gives `" "`, while `Bearer ` and `Bearer \n` give none.

Every port parses the header in linear time; none runs a backtracking regular expression on it.
[`bearer.json`](bearer.json) pins this: each case is a header and the token every port must return, and all
four resource test suites read it.

## Local validation, in order

`validate` runs these steps in this order and returns the first failure. The order is part of the contract:
a token with two defects gets the same code everywhere.

### 1. Compact serialisation → `invalid_token`

- The token is a string of exactly three `.`-separated segments.
- Each segment is canonical unpadded base64url (RFC 7515 section 2): only `A-Z a-z 0-9 - _`, no `=`, a length
  that isn't 1 mod 4, and zero padding bits (the segment must equal the re-encoding of its bytes).
- The header decodes to a strict JSON object (see [Strict JSON](#strict-json)).
- The header has no `crit` member. We implement no JWS extensions, so RFC 7515 section 4.1.11 requires
  rejecting any `crit`, and an empty one is itself invalid.

### 2. Algorithm → `unsupported_algorithm`

- `alg` must be present and a string.
- `none`, compared case-insensitively, is **always** refused, whatever the accepted list says.
- Every `alg` starting `HS` (case-insensitive) is **always** refused. The issuer keys are asymmetric; an HMAC
  checked against one would be keyed with public material, which is the classic key-confusion forgery.
- Otherwise `alg` must appear, exactly and case-sensitively, in `accepted_algorithms`. The default list is
  `ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512`. An explicitly empty list accepts nothing.

The forbidden algorithms are refused before any key lookup, so the check can't be defeated by a key set that
happens to hold a symmetric or mislabelled key.

### 3. Key → `key_not_found`

The key set is the JWKs that may verify a signature, in document order. A JWK is left out, as if it weren't
published, when its `use` is present and not `"sig"`, when its `key_ops` is present and is not an array
holding `"verify"`, when it carries a private key member (`d`, `p`, `q`, `dp`, `dq`, `qi` or `k`), or when the
port can't read it (an entry that isn't a JSON object, a key type or curve the port doesn't support, a
malformed key). A JWK left out costs only itself, never the rest of the set. Every JWK left is its own key:
JWKs without a `kid` are never merged into one.

- `kid` absent (or JSON `null`): the token matches a key only when the key set holds exactly one key.
- `kid` a string: the first key in the set with that `kid` that may be used for the header `alg` (one with
  that `kid` that declares another `alg` is passed over). An empty string matches no key, not even a JWK
  whose `kid` is the empty string.
- `kid` any other type: no key.
- A JWK that declares `alg` is only used for that `alg`.

With a `jwks_uri`, an unknown `kid` triggers at most one refetch per 30 seconds (and a set older than an
hour is refetched); a failed fetch keeps the keys already held. When no key matches and the last fetch
failed, the description is exactly `signing keys unavailable`. Why the fetch failed (the JWKS host, a
network error, the issuer's response) goes to the log as `jwks.fetch_failed`, never into the description,
which a resource puts in its `WWW-Authenticate` header for anyone to read.

### 4. Signature → `invalid_signature`

The signature over `header.payload` (the ASCII of the first two segments) must verify with the resolved key
under exactly the header `alg`. A signature of the wrong length, or a key the algorithm can't use, is
`invalid_signature`. What an algorithm can use, whether or not the JWK declares `alg`:

- `ES256`, `ES384` and `ES512` need an EC key on P-256, P-384 and P-521 respectively. A P-256 key never
  verifies an `ES384` signature, even one made with that key.
- `RS*` and `PS*` need an RSA key with a modulus of at least 2048 bits (RFC 7518 section 3.3). An RSA JWK
  without `alg` verifies any of them that is accepted.
- A key of another type (an EC key for `RS256`, an RSA key for `ES256`) verifies nothing.

### 5. Payload → `invalid_token`

The payload decodes to a strict JSON object. This happens after the signature verifies: the issuer signed
malformed claims, so the token is malformed rather than forged. A payload that isn't JSON at all and one that
is JSON but not an object (array, string, number, `null`) are both `invalid_token`.

### 6. Token type → `invalid_token_type`

When the header carries `typ` and the check is on, `typ` is compared as RFC 7515 section 4.1.9 says:
lower-cased, with an optional leading `application/` removed. The default list is `at+jwt` (RFC 9068). A
`typ` that isn't a string never matches. A token without `typ` (or with `"typ": null`) passes
this step, even when the list is explicitly empty. Passing `None` / `null` (Go: `DisableTokenTypeCheck`)
turns the check off.

### 7. Issuer → `invalid_issuer`

`iss` must be a string exactly equal to the configured issuer. Any other value or type, or no `iss`, fails.

### 8. Times → `invalid_token`, then `missing_expiry`, `expired`, `not_yet_valid`, `issued_in_future`

`exp`, `nbf` and `iat` are NumericDates. All three are type-checked before any is compared:

- absent or JSON `null`: absent;
- a JSON number that is finite and within ±(2^53 − 1), the range every port holds exactly: accepted, with a
  fraction truncated toward zero (`4102444800.9` is `4102444800`, `-4.9` is `-4`);
- anything else (string, boolean, array, object, `1e400`, `100000000000000000000`): `invalid_token`.

Then, with `now` the clock in whole seconds (floored) and `leeway` in seconds:

1. no `exp`: `missing_expiry`;
2. `now > exp + leeway`: `expired` (so a token is still valid at `now == exp + leeway`);
3. `nbf` present and `now + leeway < nbf`: `not_yet_valid`;
4. `iat` present and `now + leeway < iat`: `issued_in_future`.

### 9. Audience → `invalid_token`, then `invalid_audience`

`aud` absent or `null` is an empty list; a string is a list of one; an array must hold only strings. Any
other shape, including an array with one non-string entry, is `invalid_token`: entries are never dropped.
Then at least one configured audience must be in the list (exact string match), else `invalid_audience`.

### 10. Scope → `invalid_token`, then `insufficient_scope`

- `scope`, when present (not `null`), must be a string. It is split on U+0020 SPACE only (RFC 6749 section
  3.3); runs of spaces and leading or trailing spaces produce no empty scopes. A tab or no-break space is
  part of a scope token, not a delimiter.
- `scp`, when present (not `null`), must be either a string, split exactly like `scope` (Microsoft Entra ID
  issues `scp` this way), or an array of strings. Anything else, including an array with one non-string
  entry, is `invalid_token`. It is type-checked even when `scope` is also present.
- Granted scopes come from `scope` when present, else from `scp`, else none. When both are present `scope`
  wins and `scp` grants nothing; this is the precedence every port already had.
- Reading a string `scp` grants nothing a token didn't say: every required scope must still be listed.
- Every required scope (the call's override, else the configured list) must be granted, else
  `insufficient_scope`.

### 11. Subject → `invalid_token`

`sub`, when present and not `null`, must be a string. A valid result's subject is that string, or none.

## Strict JSON

Headers, payloads and introspection responses are read the same way in every port. A document is accepted
only if it is:

- valid UTF-8 (RFC 8259 section 8.1), with no byte-order mark;
- one JSON value per RFC 8259 with nothing but whitespace after it: no `NaN` or `Infinity`, no trailing
  commas, no leading zeros, no raw control characters in strings, no single quotes or bare names, and a
  `\u` escape takes exactly four ASCII hex digits (`0-9 a-f A-F`; not Arabic-Indic digits or fullwidth
  letters);
- an object at the top level;
- no deeper than **64** levels of nesting (the outermost object is level 1);
- free of duplicate member names in **every** object at any depth. Names are compared after escapes are
  decoded, so `"iss"` and `"iss"` are duplicates.

RFC 7519 section 4 and RFC 7515 section 4 let a recipient either reject duplicate names or keep the last one.
We reject, because "last one wins" is exactly where parsers disagree, and a token that means different
things to different readers is a token to refuse. jose4j already rejected them; Python, TypeScript and Go
now detect them themselves.

Numbers are read as IEEE 754 doubles wherever that matters: a number too large for a double becomes
±infinity rather than an error, so it is only malformed where a NumericDate is expected. (Python keeps an
integer of up to 4000 digits exact and Java one of up to 19 digits, as a `Long` or `BigInteger`; a longer one
is a double there too. The verdict is the same, only the type in the claims map differs.)

## Configuration

| Setting | Omitted | Explicitly empty / zero |
|---|---|---|
| Accepted algorithms | the default list | nothing is accepted: every token is `unsupported_algorithm` |
| Accepted token types | `at+jwt` | every `typ` is refused; a token without `typ` still passes |
| Leeway | 60 seconds | no leeway at all |

Python, TypeScript and Java tell "omitted" from "empty" by the argument being absent. Go uses its types:

- `AcceptedAlgorithms` / `AcceptedTokenTypes`: `nil` means the default, a non-nil empty slice
  (`[]string{}`) means nothing.
- `LeewaySeconds` is an `int`, which can't tell unset from 0, so 0 still means the default 60 seconds and
  `ZeroLeeway: true` means no leeway. `New` refuses `ZeroLeeway` with a non-zero `LeewaySeconds`.

Every port can be given a clock (Python `clock=`, epoch seconds; TypeScript `clock`, epoch milliseconds; Go
`WithClock`; Java `Builder.clock`, epoch milliseconds), which is how the shared vectors pin leeway.
That clock is only for `exp`, `nbf` and `iat`. The JWKS cache ages, and spaces its refetches, on the
runtime's monotonic clock (Python `time.monotonic`, TypeScript `performance.now`, Go the monotonic reading
of `time.Now`, Java `System.nanoTime`), so validating as of a fixed instant, or a step in the wall clock,
neither stops nor forces a refetch.

A configuration that can't be honoured is refused when the validator is built, with the port's config
error (Python `ValueError`, TypeScript `Error`, Go an `error` from `New`, Java `IllegalArgumentException`),
never discovered later as a token that slipped through:

- **Leeway** is a non-negative integer number of seconds. A negative leeway is refused in every port.
  Python also refuses anything but an `int` (a `bool`, a float, `NaN`), and TypeScript anything but a
  non-negative safe integer (`NaN`, a fraction, a string): `NaN` makes every time comparison false, which
  would switch off the `exp`, `nbf` and `iat` checks, and `"60"` would concatenate.
- **List options** (accepted algorithms, accepted token types, required scopes, and audiences when given as
  a list) are lists of strings. Python and TypeScript refuse a bare string or a non-string entry: a bare
  string would be read as its characters, so `"at+jwt"` would accept a `typ` of `t`. (A single audience may
  still be passed as a string.) Go and Java's types already rule this out.
- **Endpoints.** The JWKS URI and the introspection endpoint must use `https`. Over plain http anyone on
  the path could serve their own keys and forge any token, or read the client secret the resource server
  sends to the introspection endpoint. The only exemptions are the ones the client makes for its own
  endpoints: a loopback host (`localhost`, `127.0.0.1` or `::1`, case-insensitively; not the rest of
  127/8 and not a name that merely starts with `localhost`), and an explicit opt-out named like the client's:
  Python `allow_insecure=True`, TypeScript `allowInsecure: true`, Go `Config.AllowInsecure`, Java
  `Builder.allowInsecure(true)`. Python, like its client, exempts only `http://` on a loopback host; the
  other ports, like theirs, exempt a loopback host whatever the scheme.
- **Introspection client authentication** is exactly `client_secret_basic` or `client_secret_post`
  (case-sensitive). Any other value, such as `client_secret_basci` or `private_key_jwt`, is refused: it used
  to be taken as `client_secret_post`, so a typo moved the secret from the `Authorization` header into the
  form body. Unset means `client_secret_basic`, and unset is the same in every port: `null` (Python
  `None`, TypeScript `undefined` or `null`, Java `null`), `""` (all four; Go has only this), or leaving it
  out. So a method read from an environment variable that isn't set takes the default. (Before this rule,
  Python `None` / `""` and TypeScript / Java `""` sent `client_secret_post`.) A refused method is described
  in the error by its type and length, never echoed. The client id and secret must be non-empty strings:
  missing, `null`, `""` or a non-string is refused, naming the field and never the value (Go has no
  `null`, and its `""` is refused the same way). Python and Java
  refuse a bad value in the `IntrospectionConfig` constructor (Python checks again when the validator is
  built, for an object changed after construction); TypeScript and Go refuse it when the validator is built.

[`config.json`](config.json) pins these: each case is a configuration on top of the shared one and whether
building a validator from it is `accepted` or `refused`.

### AS-metadata discovery

Python `discover` and Java `Discovery.discover` (the ports that have it) fetch an RFC 8414 / OpenID Connect
metadata document, and return it only if it is safe to configure a validator from:

1. The metadata URL must use https, with the same exemptions as above (`allow_insecure` /
   `allowInsecure`). This is checked before any request.
2. The expected issuer is the one the caller passes (`issuer=` / the `issuer` argument), or else the one the
   URL was built from: `/.well-known/oauth-authorization-server` or `/.well-known/openid-configuration`
   inserted after the host (RFC 8414 section 3.1: `https://as.example/.well-known/oauth-authorization-server/t1`
   is issuer `https://as.example/t1`), or appended to the issuer's path (OpenID Connect Discovery section 4:
   `https://as.example/t1/.well-known/openid-configuration` is `https://as.example/t1`). Insertion is tried
   first. A URL that is neither, or has a query or fragment, names no issuer, and the call is refused before
   any request unless the caller passes one.
3. The body is read as [strict JSON](#strict-json) and must be an object.
4. Its `issuer` must be a string equal to the expected issuer (RFC 8414 section 3.3). A passed issuer is
   compared exactly. A derived one may also come back with a terminating `/`, which RFC 8414 and OpenID
   Connect Discovery drop when building the URL.
5. `jwks_uri` and `introspection_endpoint`, when present and not `null`, must be strings that use https,
   with the same exemptions.

An insecure metadata URL, or one that names no issuer, is a config error (Python `ValueError`, Java
`IllegalArgumentException`). A failed fetch or a document that fails steps 3 to 5 is a failed call
(`TransportError` / `TransportException`): the document says nothing the validator can use.

## Introspection

`validate_active` / `validateActive` / `ValidateActive` POSTs the token to the RFC 7662 endpoint and checks
the response.

**A failed call is an error, never a verdict.** No introspection endpoint configured, a network or TLS
failure, a timeout, a redirect (never followed: the request carries the resource server's credentials), a
non-2xx status, a body over the cap or a body that isn't a strict JSON object all mean the authorisation
server said nothing about the token, so the call fails rather than returning `invalid_token`:

| Port | No endpoint configured | Call failed |
|---|---|---|
| Python | `ValueError` | `TransportError` |
| TypeScript | `Error` | `TransportError` |
| Go | `ValidateActive` returns a non-nil `error` (and a zero `Result`) | same |
| Java | `IllegalStateException` | `TransportException` (or whatever the injected transport throws) |

An injected transport that returns something other than a JSON object is treated as a failed call.

The default transport caps the response at **1 MiB** (1,048,576 bytes) in every port. The body is decoded
as UTF-8 with invalid sequences replaced by U+FFFD (each port's shared transport does this), then read as
[strict JSON](#strict-json), so a response with duplicate member names is a failed call.

When the call succeeds, the response is checked in this order:

1. `active` must be exactly JSON `true` (RFC 7662 section 2.2 defines it as a boolean). Missing, `false`,
   `"true"`, `1`, `null` or an object: `inactive`.
2. Scope, as in [step 10](#10-scope--invalid_token-then-insufficient_scope).
3. Audience, as in [step 9](#9-audience--invalid_token-then-invalid_audience), except that a response with no
   audience (absent, `null` or an empty array) passes: the authorisation server isn't obliged to return
   `aud`.
4. Subject, as in [step 11](#11-subject--invalid_token).

Introspection does not check `exp`, `nbf`, `iat`, `iss` or the token type: that is the authorisation server's
job, and `active: true` is its answer.

### Client authentication

The request authenticates the resource server to the authorisation server with its client id and secret:

- `client_secret_basic` (the default) sends `Authorization: Basic <base64(id ":" secret)>` and no
  credentials in the form. As RFC 6749 section 2.3.1 requires, the id and the secret are each
  form-urlencoded (Appendix B) first, then joined with `:` and base64'd (standard alphabet, padded). The
  encoding is byte for byte what Python's `urllib.parse.quote_plus(s, safe="")` produces: the string's UTF-8
  bytes, with `A-Z`, `a-z`, `0-9`, `-`, `.`, `_` and `~` kept as they are, a space as `+`, and every other
  byte as `%XX` in uppercase hex. So `:` is `%3A`, `%` is `%25`, `+` is `%2B`, `*` is `%2A` and `é` is
  `%C3%A9`. Go uses `url.QueryEscape`, which produces the same bytes. Java and TypeScript have their own
  encoder, because `URLEncoder` keeps `*` and encodes `~`, and `encodeURIComponent` keeps `! ' ( ) *` and
  encodes a space as `%20`.
- `client_secret_post` sends no `Authorization` header and puts `client_id` and `client_secret` in the form
  body, with the rest of the form.

Before this rule the id and secret were joined unencoded, so an authorisation server that decodes as the RFC
says failed a client id containing `:`, or a secret containing `%` or `+`. Credentials made only of
`A-Z a-z 0-9 - . _ ~` give the same header as before.

`client_auth` in [`introspection.json`](introspection.json) pins the exact header and the decoded form
fields for a client id and secret that contain `:`, `%`, `+`, a space, `*`, `~`, `! ' ( )`, `/ ? # & =` and
non-ASCII characters (one outside the BMP), for each method and for the default.

### The introspection guard

`ProtectedResource.authenticate_active` / `authenticateActive` / `AuthenticateActive` guards a request with
`validate_active` and then applies the same two rules as the JWT guard, `authenticate`:

1. **This resource.** The response's audience must name the resource the guard was built for. A validator may
   accept several audiences (one per resource it serves), so an audience the validator accepts can still name
   a different resource: `invalid_audience`. A response with no audience is refused too (`invalid_audience`),
   because nothing then says the token was issued for this resource.
2. **No sender constraint.** A response with a `cnf` member that isn't `null` is `invalid_token`. A
   DPoP-bound or mTLS-bound token is only usable with its proof, which a Bearer guard never sees.

Both rules run after `validate_active`'s own checks, so a response that fails one of those first gets that
verdict instead. For example, a response for another resource that also lacks a required scope is
`insufficient_scope` (403), not `invalid_audience` (401). Either way the guard refuses it.

A failed introspection call fails the guard the same way it fails `validate_active`. `expect_guard` in
`introspection.json` pins the guard's verdict for every case, for a guard whose validator accepts both
`guard.audiences`.

## Known limits

- **Unpaired surrogate escapes in member names.** Go's JSON decoder turns an unpaired `\ud800`-style escape
  into U+FFFD before names are compared; the others compare the raw UTF-16 code units. So two names that
  differ only in unpaired surrogates are duplicates (and refused) in Go but distinct in the other ports.
  Only an issuer can put such names in a signed token.
- **Unpaired surrogates in introspection credentials.** A client id or secret that isn't valid Unicode has
  no UTF-8 form. Python refuses it when introspecting (a `UnicodeEncodeError`, which is a `ValueError`), Java
  sends `?` for each unpaired surrogate, TypeScript sends U+FFFD, and Go, whose strings are bytes, encodes
  the bytes it was given. A real client id or secret is never like this.
- **Claims representation.** The verdict is identical; the in-memory claims map is each language's natural
  JSON type (`float64` in Go, `number` in TypeScript, `int`/`float` in Python, `Long`/`BigInteger`/`Double`
  in Java).

## Adding a case

Extend [`generate.py`](generate.py) (never hand-edit the JSON), run `python3 validation/generate.py`, then
`./verify-validation.sh`. The generator signs with a throwaway key on every run, so every token changes;
that is expected. A new rule belongs in this document too.

[`bearer.json`](bearer.json) has no signed tokens, so it is edited by hand. Escape control and non-ASCII
characters (`\u000b`, `\u00a0`), and use null for "no token". The four ports' resource tests read it directly.
