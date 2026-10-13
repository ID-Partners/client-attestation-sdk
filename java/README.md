# client-attestation-sdk

Client-side builder SDK for **OAuth Attestation-Based Client Authentication**
([draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)).

It mints the artifacts a client (and its attester) present at the token endpoint:

- the **Client Attestation JWT** - issued by a Client Attester, naming the client and binding its
  instance key (`cnf.jwk`);
- the **PoP JWT** (PoP method `attestation_pop_jwt`) or **DPoP proof** (PoP method `dpop_combined`) - signed
  by the client instance key to prove possession;
- the request **headers** to send.

On the other side of the API call, `tokenvalidator` validates the access tokens a resource server receives
(see [Resource server](#resource-server-validate-an-access-token)).

Built on [jose4j](https://bitbucket.org/b_c/jose4j). The AS-side counterpart that *verifies*
these artifacts is [`client-attestation`](https://github.com/dphhyland/client-attestation) - this SDK is
round-trip tested against it.

## Install

Requires JDK 17 or later. Add this dependency to your application's `pom.xml`:

```xml
<dependency>
  <groupId>global.idpartners</groupId>
  <artifactId>client-attestation-sdk</artifactId>
  <version>1.2.0</version>
</dependency>
```

From [Maven Central](https://central.sonatype.com/artifact/global.idpartners/client-attestation-sdk), so no
repository or token setup. Releases before 1.0.0 went to GitHub Packages only.

Or build it from this repository with `./mvnw install` in `java/`.

## Get a token and call an API

The attester must trust your workload identity and map it to an authorised client.
Set `CLIENT_ATTESTATION_TOKEN_FILE` to an identity token file with the attester's evidence
audience. `ATTESTER_URL`, `EVIDENCE_AUDIENCE` and `API_URL` are application variables.
`EVIDENCE_AUDIENCE` is the audience your identity token carries, and the attester's discovery document must
name it too.

```bash
export ATTESTER_URL=https://attester.example.com
export EVIDENCE_AUDIENCE=https://attester.example.com/evidence
export API_URL=https://api.example.com/data
export CLIENT_ATTESTATION_TOKEN_FILE=/absolute/path/to/identity-token.jwt
```

Add this class to the application that declares the Maven dependency:

```java
import global.idpartners.clientattestation.ClientAttestation;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class CallApi {
    public static void main(String[] args) throws Exception {
        ClientAttestation ca = ClientAttestation.builder(System.getenv("ATTESTER_URL"))
                .evidenceAudience(System.getenv("EVIDENCE_AUDIENCE"))
                .build();
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20)).build();
        URI uri = URI.create(System.getenv("API_URL"));
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(60)).GET();
        HttpResponse<String> response = ca.send(http, request, "GET", uri,
                HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("API returned HTTP " + response.statusCode());
        }
        System.out.println(response.statusCode());
    }
}
```

From the application directory containing `pom.xml` and `CallApi.java`, resolve the dependency
classpath and run the source file:

```bash
mvn dependency:build-classpath -Dmdep.outputFile=classpath.txt
java --class-path "$(cat classpath.txt)" CallApi.java
```

Retain `ca` for later requests so it reuses the token cache. `send` adds a DPoP proof when
the token requires one. DPoP binds the token to a client key and requires a signed proof
for each request. See [Configuration](../docs/configuration.md) for the shared options.

## Build a credential offline

Save as `BuildCredential.java` in the application that declares the Maven dependency.
This complete class generates temporary keys and needs no server.

```java
import global.idpartners.clientattestation.ClientAttestationBuilder;
import global.idpartners.clientattestation.ClientAttestationCredential;
import global.idpartners.clientattestation.SigningKeyPair;
import java.time.Duration;
import java.util.Map;

public class BuildCredential {
    public static void main(String[] args) throws Exception {
        SigningKeyPair attester = SigningKeyPair.generate("ES256");
        SigningKeyPair instance = SigningKeyPair.generate("ES256");
        String attestation = new ClientAttestationBuilder(attester, "https://attester.example.com")
                .clientId("https://rp.example.com")
                .confirmationJwk(instance.publicJwk())
                .expiresIn(Duration.ofMinutes(5))
                .build();
        ClientAttestationCredential credential = new ClientAttestationCredential(attestation, instance);
        Map<String, String> pop = credential.popHeaders("https://rp.example.com", "https://as.example.com", null);
        Map<String, String> dpop = credential.dpopHeaders("POST", "https://as.example.com/as/token.oauth2", null);
        System.out.println(pop.keySet());
        System.out.println(dpop.keySet());
    }
}
```

From the application directory, using the classpath generated above, run:

```bash
java --class-path "$(cat classpath.txt)" BuildCredential.java
```

The generated keys are
for the example. A production authorisation server must trust the attester's signing key.

The following sections show integration fragments for an existing attester or client.

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
        // optional: .authorizationDetails(...) / .workload(...) / .operator(sub, issuer)  -
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
Map<String, String> popHeaders = cred.popHeaders(
        "https://rp.example.com",          // client_id (PoP iss)
        "https://as.example.com",          // AS identifier (PoP aud)
        challenge);                        // server challenge, or null

// ...or DPoP combined mode:
Map<String, String> dpopHeaders = cred.dpopHeaders(
        "POST",
        "https://as.example.com/as/token.oauth2",   // htu
        challenge);                                  // DPoP nonce, or null

// popHeaders  -> OAuth-Client-Attestation + OAuth-Client-Attestation-PoP
// dpopHeaders -> OAuth-Client-Attestation + DPoP
```

Add one set of headers to the token request. The lower-level builders (`ClientAttestationBuilder`, `PopBuilder`,
`DpopProofBuilder`) are available directly when you need finer control (explicit `jti`, `iat`, etc.).

The one-call `ClientAttestation` client (see the [root README](../README.md#get-a-token-in-one-call))
wraps this: `.popMethod("dpop_combined")` on its builder switches it to DPoP mode, and a fetched challenge
is carried through automatically as the PoP JWT's `challenge` claim or the DPoP proof's `nonce` claim,
whichever mode is active.

### Using a DPoP-bound token

In `dpop_combined` mode the AS may issue a DPoP-bound token (`token_type: DPoP`). `ClientAttestation`
keeps the instance key that minted the attestation alongside the cached token, so it can prove possession
at a resource:

```java
ClientAttestation ca = ClientAttestation.builder("pf.example.com")
        .evidenceAudience("https://pf.example.com")   // the audience your attester expects evidence for
        .popMethod("dpop_combined").build();

// Send through java.net.http: adds Authorization + a fresh DPoP proof, and retries once on a
// use_dpop_nonce challenge with the server's DPoP-Nonce. The client must not follow redirects.
HttpClient httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
URI uri = URI.create("https://api.example.com/data");
HttpResponse<String> resp = ca.send(httpClient, HttpRequest.newBuilder(uri).GET(), "GET", uri,
        HttpResponse.BodyHandlers.ofString());

// ...or take the headers for another client:
Map<String, String> headers = ca.requestHeaders("GET", uri.toString());
// Bearer: {"Authorization": "Bearer <t>"}
// DPoP:   {"Authorization": "DPoP <t>", "DPoP": <proof with htm, htu, ath and the last nonce>}
```

`authorizationHeader()` and the one-argument `authorize(builder)` still work for Bearer tokens; for a
DPoP-bound token they give only the `DPoP <t>` scheme and you need `requestHeaders` (or the
`authorize(builder, method, uri)` overload) for the proof. `send` refuses an `HttpClient` that follows
redirects (`IllegalArgumentException`), so a credential never reaches a redirect target; `NEVER` is the
`HttpClient` default. The request body must be re-sendable for the nonce retry. In `dpop_combined` mode the
token request itself retries once if the AS answers `use_dpop_nonce` (a 400 JSON error or a 401 DPoP
challenge) with a `DPoP-Nonce`. `DpopProofBuilder` upper-cases `htm`, strips query and
fragment from `htu`, and takes `.accessToken(t)` to add `ath`.

### Fail-closed defaults

- If the attester advertises a `challenge_endpoint` and the challenge can't be fetched, `token()` throws
  `ClientAttestationException` rather than minting without one. Opt out with `.requireChallenge(false)`.
- `.evidenceAudience(...)` is required unless `.metadata(...)` is given: it pins the audience the
  workload's identity token is fetched for, so the attester's discovery document cannot choose it (an evidence
  source mints a token for whatever audience it is asked for). A missing pin, or a discovered
  `evidence_audience` that differs, throws `ClientAttestationException` before any evidence is fetched.
- The attester URL and every endpoint taken from discovery must be `https`, unless the host is
  loopback (`localhost`, `127.0.0.1`, `::1`). `.allowInsecure(true)` lifts this for test rigs.
- If `CLIENT_ATTESTATION_TOKEN_FILE` or `SPIFFE_ENDPOINT_SOCKET` is set but points at a missing path,
  evidence auto-detection throws `EvidenceNotFoundException` naming the variable instead of trying the next
  source. Through `token()` it arrives as the cause of a `ClientAttestationException`.

### Other attesters

`ClientAttestation` speaks PingFederate's discovery and mint protocol by default. `.profile(...)` plugs in
your own `AttesterProfile`, and `.metadata(AttesterMetadata.of(audience, attestationEndpoint,
tokenEndpoint))` gives the endpoints directly with no discovery (start from `ClientAttestation.builder()`
with no URL). `AttestationIssuanceClient` takes a profile as its last constructor argument. See
[`docs/attester-profiles.md`](../docs/attester-profiles.md).

`AttestationIssuanceClient` (its endpoint and every call its profile makes) and `OpenBaoTransitSigner` (the
vault address) follow the same https rule. Each has a constructor with a trailing `boolean allowInsecure`
that lifts it.

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
if (!result.valid()) {
    reject(result.error());                                  // e.g. "expired", "invalid_audience"
} else if (result.claims().get("cnf") != null) {
    reject("invalid_token");                                 // sender-constrained: see below
} else {
    handle(result.subject(), result.scopes(), result.claims());
}
```

`validate` checks the token only. It doesn't look at `cnf`, so a DPoP- or mTLS-bound token is valid
without its sender proof: refuse one unless you verify that proof. As a request guard, use
`ProtectedResource.authenticate` (below), which does this for you.

- **Codes** are the constants in `ErrorCodes`: `invalid_token`, `unsupported_algorithm`, `key_not_found`,
  `invalid_signature`, `invalid_token_type`, `invalid_issuer`, `missing_expiry`, `expired`,
  `not_yet_valid`, `issued_in_future`, `invalid_audience`, `insufficient_scope`, and `inactive` from
  introspection.
- **Defaults**: algorithms ES/RS/PS at 256/384/512, 60 seconds of leeway, `typ` must be `at+jwt` when the
  token carries one (`.disableTokenTypeCheck()` for an issuer that stamps something else). An explicitly
  empty algorithm list accepts nothing, an empty type list refuses every token that carries a `typ`, `leewaySeconds(0)` means no leeway, and `none` / `HS*` are
  refused even when listed. The precise rules, shared by every port, are in
  [validation/SEMANTICS.md](../validation/SEMANTICS.md).
- **JWKS caching**: a `jwksUri` is fetched on first use and cached for an hour. An unknown `kid` triggers a
  refetch, but never more than once every 30 seconds, and concurrent misses share one fetch, so made-up
  `kid` values can't turn every request into a call to the issuer. A failed refresh keeps the keys already
  held, and a request whose key is already held never waits for another request's refresh. Fetches go
  through the SDK's shared transport: 10 second timeout, no redirects, 512 KiB cap.
- **Introspection** (RFC 7662): add `.introspection(new IntrospectionConfig(endpoint, clientId, secret))`
  and call `validateActive(token)`. `client_secret_basic` by default; pass
  `IntrospectionConfig.CLIENT_SECRET_POST` as a fourth argument for form credentials. Only `"active": true`
  counts as active. A failed call (no endpoint, transport failure, non-2xx, a body over 1 MiB or not a
  strict JSON object) throws rather than returning a verdict.
- **Discovery** (RFC 8414): `Discovery.discover(metadataUrl)` returns the AS metadata document, with
  `issuer`, `jwks_uri` and `introspection_endpoint` to feed into the config. It refuses a document whose
  `issuer` isn't the one the `.well-known` URL was built from; for any other URL pass the issuer,
  `Discovery.discover(metadataUrl, issuer, null)`.
- **https only**: `build()` refuses a plain-http `jwksUri` or introspection endpoint, and `discover` a
  plain-http metadata URL or endpoint, unless the host is loopback or you set `allowInsecure(true)`.

### MCP / A2A protected resource

`validateActive` uses the introspection response. It does not first run `validate`.

`ProtectedResource` adds the HTTP conventions on top: RFC 9728 metadata, RFC 6750 bearer extraction and
`WWW-Authenticate` challenges, and a guard that binds the token to this resource (RFC 8707). The
constructor refuses a validator that doesn't accept the resource as an audience. `authenticate` is a
Bearer guard: it refuses a token with a `cnf` claim (DPoP- or mTLS-bound) with 401, because it never sees
the sender proof. To accept those, verify the proof yourself and call `validate`.

`authenticate` handles Bearer requests. It requires this resource in the token's audience and
refuses a token whose `cnf` claim is non-null (DPoP-bound, mTLS-bound or malformed) with 401, because
it receives no sender proof. To accept sender-constrained tokens, verify the proof in the resource's
authentication layer and call `validate` directly. See the [resource reference](../docs/configuration/resource.md).

```java
ProtectedResource resource = new ProtectedResource("https://mcp.example.com/mcp",
        List.of("https://as.example.com"), validator);

// serve resource.metadataJson() at resource.metadataPath()  ->  /.well-known/oauth-protected-resource/mcp
AuthDecision decision = resource.authenticate(request.getHeader("Authorization"));
if (!decision.authorized()) {
    response.setHeader("WWW-Authenticate", decision.wwwAuthenticate());   // 401, or 403 for scope
    response.sendError(decision.status());
    return;                                                               // never run the action below
}
handle(decision.result().subject(), decision.result().scopes());
```

Challenge values have every control character stripped, so nothing can split the header, and no failure
description echoes the token's unverified `alg`, `kid` or claims, or why a JWKS fetch failed.

## Keys

`SigningKeyPair` wraps a JWK key pair with its JWS `alg` and RFC 7638 thumbprint `kid`:

```java
SigningKeyPair k = SigningKeyPair.generate("ES256");   // ES256/384/512, RS256/384/512, PS256/384/512
Map<String, Object> publicJwk = k.publicJwk();          // e.g. to publish or hand to an attester
SigningKeyPair imported = SigningKeyPair.fromJwk(privateJwkMap, "ES256");   // Map<String, Object> with "d"
```

## Build

```bash
./mvnw clean verify               # from a clean clone; coverage report in target/site/jacoco/
./mvnw clean verify -Pinterop     # adds the round-trip tests; needs client-attestation 0.1.0 in ~/.m2
./mvnw install                   # makes the SDK available to another local Maven project
```

Run these from `java/`. The build writes the library, sources and Javadoc JARs to `target/`.
The SDK JAR has no application entry point. See [Build and test](../docs/building.md#java)
for prerequisites and reports, and [Deployment](../docs/deployment.md) for application setup.

The `interop` profile adds `src/interop-test/java`. `RoundTripTest` there builds each artifact and verifies
it through the real AS-side `ClientAttestationVerifier`, for both PoP and DPoP modes and both EC and RSA
instance keys. The verifier is not on Maven Central, so that profile is opt-in.

## Not yet included

SD-JWT-encoded attestation presentations (selective disclosure + key binding) - the verifier accepts
them (`oauth-client-attestation+sd-jwt`); a builder for them is a planned addition.
