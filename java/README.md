# client-attestation-sdk

Client-side builder SDK for **OAuth Attestation-Based Client Authentication**
([draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)).

It mints the artifacts a client (and its attester) present at the token endpoint:

- the **Client Attestation JWT** — issued by a Client Attester, naming the client and binding its
  instance key (`cnf.jwk`);
- the **PoP JWT** (PoP method `attestation_pop_jwt`) or **DPoP proof** (PoP method `dpop_combined`) — signed
  by the client instance key to prove possession;
- the request **headers** to send.

On the other side of the API call, `tokenvalidator` validates the access tokens a resource server receives
(see [Resource server](#resource-server-validate-an-access-token)).

Built on [jose4j](https://bitbucket.org/b_c/jose4j). The AS-side counterpart that *verifies*
these artifacts is [`client-attestation`](https://github.com/dphhyland/client-attestation) — this SDK is
round-trip tested against it.

## Install

```xml
<dependency>
  <groupId>global.idpartners</groupId>
  <artifactId>client-attestation-sdk</artifactId>
  <version>1.0.1</version>
</dependency>
```

From [Maven Central](https://central.sonatype.com/artifact/global.idpartners/client-attestation-sdk), so no
repository or token setup. Releases before 1.0.0 went to GitHub Packages only.

Or build it from this repository with `./mvnw install` in `java/`.

## Attester: issue an attestation

The attester names the client and binds the client's public instance key. Sign with the attester's
issuing key.

```java
SigningKeyPair attesterKey = SigningKeyPair.generate("ES256");   // the attester's key
Map<String, Object> clientInstancePublicJwk = /* the client's public cnf key */;

String attestation = new ClientAttestationBuilder(attesterKey, "https://attester.example.com")
        .clientId("https://rp.example.com")
        .confirmationJwk(clientInstancePublicJwk)
        .expiresIn(Duration.ofMinutes(5))
        // optional: .authorizationDetails(...) / .workload(...) / .operator(sub, issuer) —
        // operator names who's accountable for running the client (RFC 8693 may_act-shaped;
        // an assertion, not proof of authorisation), distinct from clientId and from the principal.
        .build();
```

## Client: present the attestation + proof of possession

The client holds its instance key and the attestation, and mints a fresh proof per token request.

```java
SigningKeyPair instanceKey = /* the client's own key (private held by the client) */;
ClientAttestationCredential cred = new ClientAttestationCredential(attestation, instanceKey);

// Dedicated PoP-JWT mode:
Map<String, String> headers = cred.popHeaders(
        "https://rp.example.com",          // client_id (PoP iss)
        "https://as.example.com",          // AS identifier (PoP aud)
        challenge);                        // server challenge, or null

// ...or DPoP combined mode:
Map<String, String> headers = cred.dpopHeaders(
        "POST",
        "https://as.example.com/as/token.oauth2",   // htu
        challenge);                                  // DPoP nonce, or null

// headers -> OAuth-Client-Attestation + (OAuth-Client-Attestation-PoP | DPoP)
```

Add `headers` to the token request. The lower-level builders (`ClientAttestationBuilder`, `PopBuilder`,
`DpopProofBuilder`) are available directly when you need finer control (explicit `jti`, `iat`, etc.).

The one-call `ClientAttestation` orchestration class (see the [root README](../README.md#get-a-token-in-one-call))
wraps this: `.popMethod("dpop_combined")` on its builder switches it to DPoP mode, and a fetched challenge
is carried through automatically as the PoP JWT's `challenge` claim or the DPoP proof's `nonce` claim,
whichever mode is active.

### Using a DPoP-bound token

In `dpop_combined` mode the AS may issue a DPoP-bound token (`token_type: DPoP`). `ClientAttestation`
keeps the instance key that minted the attestation alongside the cached token, so it can prove possession
at a resource:

```java
ClientAttestation ca = ClientAttestation.builder("pf.example.com").popMethod("dpop_combined").build();

// Send through java.net.http: adds Authorization + a fresh DPoP proof, and retries once on a
// use_dpop_nonce challenge with the server's DPoP-Nonce.
HttpResponse<String> resp = ca.send(httpClient, HttpRequest.newBuilder(uri).GET(), "GET", uri,
        HttpResponse.BodyHandlers.ofString());

// ...or take the headers for another client:
Map<String, String> headers = ca.requestHeaders("GET", url);
// Bearer: {"Authorization": "Bearer <t>"}
// DPoP:   {"Authorization": "DPoP <t>", "DPoP": <proof with htm, htu, ath and the last nonce>}
```

`authorizationHeader()` and the one-argument `authorize(builder)` still work for Bearer tokens; for a
DPoP-bound token they give only the `DPoP <t>` scheme and you need `requestHeaders` (or the
`authorize(builder, method, uri)` overload) for the proof. The token request itself retries once if the AS
answers 400 `use_dpop_nonce` with a `DPoP-Nonce`. `DpopProofBuilder` upper-cases `htm`, strips query and
fragment from `htu`, and takes `.accessToken(t)` to add `ath`.

### Fail-closed defaults

- If the attester advertises a `challenge_endpoint` and the challenge can't be fetched, `token()` throws
  `ClientAttestationException` rather than minting without one. Opt out with `.requireChallenge(false)`.
- The attester URL and every endpoint taken from discovery must be `https`, unless the host is
  loopback (`localhost`, `127.0.0.1`, `::1`). `.allowInsecure(true)` lifts this for test rigs.

### Other attesters

`ClientAttestation` speaks PingFederate's discovery and mint protocol by default. `.profile(...)` plugs in
your own `AttesterProfile`, and `.metadata(AttesterMetadata.of(audience, attestationEndpoint,
tokenEndpoint))` gives the endpoints directly with no discovery (start from `ClientAttestation.builder()`
with no URL). `AttestationIssuanceClient` takes a profile as its last constructor argument. See
[`docs/attester-profiles.md`](../docs/attester-profiles.md).
- If `CLIENT_ATTESTATION_TOKEN_FILE` or `SPIFFE_ENDPOINT_SOCKET` is set but points at a missing path,
  evidence auto-detection throws `EvidenceNotFoundException` naming the variable instead of trying the next
  source.

## Resource server: validate an access token

`global.idpartners.clientattestation.tokenvalidator` is the resource-server side, at parity with the Python,
TypeScript and Go validators. It checks the JWT signature against the issuer's JWKS, then `typ`, `iss`,
`exp` / `nbf` / `iat` (with leeway), audience and scope, and returns a stable error code on the first
failure. The order and the codes are shared across all four ports, and `./verify-validation.sh` checks
every port returns the same verdict on the shared vectors.

```java
AccessTokenValidator validator = AccessTokenValidator.builder(ValidatorConfig.builder()
                .issuer("https://issuer.example.com")
                .audiences("https://api.example.com")
                .jwksUri("https://issuer.example.com/jwks")     // or .jwks(Map) / .jwks(String) for a static set
                .requiredScopes("read")
                .build())
        .logger(System.getLogger(ClientAttestation.LOGGER_NAME))   // optional; silent by default
        .build();

ValidationResult result = validator.validate(accessToken);   // or validate(token, List.of("write"))
if (result.valid()) {
    handle(result.subject(), result.scopes(), result.claims());
} else {
    reject(result.error());                                  // e.g. "expired", "invalid_audience"
}
```

- **Codes** are the constants in `ErrorCodes`: `invalid_token`, `unsupported_algorithm`, `key_not_found`,
  `invalid_signature`, `invalid_token_type`, `invalid_issuer`, `missing_expiry`, `expired`,
  `not_yet_valid`, `issued_in_future`, `invalid_audience`, `insufficient_scope`, and `inactive` from
  introspection.
- **Defaults**: algorithms ES/RS/PS at 256/384/512, 60 seconds of leeway, `typ` must be `at+jwt` when the
  token carries one (`.disableTokenTypeCheck()` for an issuer that stamps something else). An explicitly
  empty algorithm or type list accepts nothing, `leewaySeconds(0)` means no leeway, and `none` / `HS*` are
  refused even when listed. The precise rules, shared by every port, are in
  [validation/SEMANTICS.md](../validation/SEMANTICS.md).
- **JWKS caching**: a `jwksUri` is fetched on first use and cached for an hour. An unknown `kid` triggers a
  refetch, but never more than once every 30 seconds, and concurrent misses share one fetch, so made-up
  `kid` values can't turn every request into a call to the issuer. A failed refresh keeps the keys already
  held. Fetches go through the SDK's shared transport: 10 second timeout, no redirects, 512 KiB cap.
- **Introspection** (RFC 7662): add `.introspection(new IntrospectionConfig(endpoint, clientId, secret))`
  and call `validateActive(token)`. `client_secret_basic` by default; pass
  `IntrospectionConfig.CLIENT_SECRET_POST` as a fourth argument for form credentials. Only `"active": true`
  counts as active. A failed call (no endpoint, transport failure, non-2xx, a body over 1 MiB or not a
  strict JSON object) throws rather than returning a verdict.
- **Discovery** (RFC 8414): `Discovery.discover(metadataUrl)` returns the AS metadata document, with
  `issuer`, `jwks_uri` and `introspection_endpoint` to feed into the config.

### MCP / A2A protected resource

`ProtectedResource` adds the HTTP conventions on top: RFC 9728 metadata, RFC 6750 bearer extraction and
`WWW-Authenticate` challenges, and a guard that binds the token to this resource (RFC 8707). The
constructor refuses a validator that doesn't accept the resource as an audience.

```java
ProtectedResource resource = new ProtectedResource("https://mcp.example.com/mcp",
        List.of("https://as.example.com"), validator);

// serve resource.metadataJson() at resource.metadataPath()  ->  /.well-known/oauth-protected-resource/mcp
AuthDecision decision = resource.authenticate(request.getHeader("Authorization"));
if (!decision.authorized()) {
    response.setHeader("WWW-Authenticate", decision.wwwAuthenticate());   // 401, or 403 for scope
    response.sendError(decision.status());
}
```

Challenge values have every control character stripped, so nothing can split the header, and no failure
description echoes the token's unverified `alg`, `kid` or claims.

## Keys

`SigningKeyPair` wraps a JWK key pair with its JWS `alg` and RFC 7638 thumbprint `kid`:

```java
SigningKeyPair k = SigningKeyPair.generate("ES256");   // ES256/384/512, RS256/384/512, PS256/384/512
Map<String, Object> publicJwk = k.publicJwk();          // e.g. to publish or hand to an attester
SigningKeyPair imported = SigningKeyPair.fromJwk(existingJose4jJwk, "ES256");
```

## Build

```bash
./mvnw clean verify               # from a clean clone; coverage report in target/site/jacoco/
./mvnw clean verify -Pinterop     # adds the round-trip tests; needs client-attestation 0.1.0 in ~/.m2
```

The `interop` profile adds `src/interop-test/java`. `RoundTripTest` there builds each artifact and verifies
it through the real AS-side `ClientAttestationVerifier`, for both PoP and DPoP modes and both EC and RSA
instance keys. The verifier is not on Maven Central, so that profile is opt-in.

## Not yet included

SD-JWT-encoded attestation presentations (selective disclosure + key binding) — the verifier accepts
them (`oauth-client-attestation+sd-jwt`); a builder for them is a planned addition.
