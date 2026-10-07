# Access-token validation semantics

This is the contract every port's resource-server validator implements (Python
`client_attestation_sdk.token_validator`, TypeScript `src/validator`, Go `tokenvalidator`, Java
`global.idpartners.clientattestation.tokenvalidator`). For the same token, config and clock, all four return
the same verdict. [`tokens.json`](tokens.json) and [`introspection.json`](introspection.json) pin it: each
case names the rule it tests, and [`../verify-validation.sh`](../verify-validation.sh) fails if any port
disagrees with any expected verdict. CI runs it on every pull request.

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

- `kid` absent (or JSON `null`): the token matches a key only when the key set holds exactly one key.
- `kid` a string: the key with that `kid`. An empty string matches no key.
- `kid` any other type: no key.
- A JWK that declares `alg` is only used for that `alg`.

With a `jwks_uri`, an unknown `kid` triggers at most one refetch per 30 seconds (and a set older than an
hour is refetched); a failed fetch keeps the keys already held. The failure reason is the description.

### 4. Signature → `invalid_signature`

The signature over `header.payload` (the ASCII of the first two segments) must verify with the resolved key
under exactly the header `alg`. A signature of the wrong length, or a key the algorithm can't use, is
`invalid_signature`.

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
  commas, no leading zeros, no raw control characters in strings, no single quotes or bare names;
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
integer of up to 4000 digits exact and Java keeps a large integer as a `BigInteger`; the verdict is the same,
only the type in the claims map differs.)

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

## Known limits

- **Unpaired surrogate escapes in member names.** Go's JSON decoder turns an unpaired `\ud800`-style escape
  into U+FFFD before names are compared; the others compare the raw UTF-16 code units. So two names that
  differ only in unpaired surrogates are duplicates (and refused) in Go but distinct in the other ports.
  Only an issuer can put such names in a signed token.
- **Claims representation.** The verdict is identical; the in-memory claims map is each language's natural
  JSON type (`float64` in Go, `number` in TypeScript, `int`/`float` in Python, `Long`/`BigInteger`/`Double`
  in Java).

## Adding a case

Extend [`generate.py`](generate.py) (never hand-edit the JSON), run `python3 validation/generate.py`, then
`./verify-validation.sh`. The generator signs with a throwaway key on every run, so every token changes;
that is expected. A new rule belongs in this document too.
