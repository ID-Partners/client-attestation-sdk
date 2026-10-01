# client-attestation-sdk

Client-side builder SDK for **OAuth Attestation-Based Client Authentication**
([draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)).

It mints the artifacts a client (and its attester) present at the token endpoint:

- the **Client Attestation JWT** — issued by a Client Attester, naming the client and binding its
  instance key (`cnf.jwk`);
- the **PoP JWT** (PoP method `attestation_pop_jwt`) or **DPoP proof** (PoP method `dpop_combined`) — signed
  by the client instance key to prove possession;
- the request **headers** to send.

Built on [jose4j](https://bitbucket.org/b_c/jose4j). The AS-side counterpart that *verifies*
these artifacts is [`client-attestation`](https://github.com/dphhyland/client-attestation) — this SDK is
round-trip tested against it.

## Install

Not on Maven Central yet: install from this repository (`mvn install` in `java/`), then

```xml
<dependency>
  <groupId>global.idpartners</groupId>
  <artifactId>client-attestation-sdk</artifactId>
  <version>0.2.0</version>
</dependency>
```

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
- The PingFederate host and every endpoint taken from discovery must be `https`, unless the host is
  loopback (`localhost`, `127.0.0.1`, `::1`). `.allowInsecure(true)` lifts this for test rigs.
- If `CLIENT_ATTESTATION_TOKEN_FILE` or `SPIFFE_ENDPOINT_SOCKET` is set but points at a missing path,
  evidence auto-detection throws `EvidenceNotFoundException` naming the variable instead of trying the next
  source.

## Keys

`SigningKeyPair` wraps a JWK key pair with its JWS `alg` and RFC 7638 thumbprint `kid`:

```java
SigningKeyPair k = SigningKeyPair.generate("ES256");   // ES256/384/512, RS256/384/512, PS256/384/512
Map<String, Object> publicJwk = k.publicJwk();          // e.g. to publish or hand to an attester
SigningKeyPair imported = SigningKeyPair.fromJwk(existingJose4jJwk, "ES256");
```

## Build

```bash
mvn clean verify                 # from a clean clone; coverage report in target/site/jacoco/
mvn clean verify -Pinterop       # adds the round-trip tests; needs client-attestation 0.1.0 in ~/.m2
```

The `interop` profile adds `src/interop-test/java`. `RoundTripTest` there builds each artifact and verifies
it through the real AS-side `ClientAttestationVerifier`, for both PoP and DPoP modes and both EC and RSA
instance keys. The verifier is not on Maven Central, so that profile is opt-in.

## Not yet included

SD-JWT-encoded attestation presentations (selective disclosure + key binding) — the verifier accepts
them (`oauth-client-attestation+sd-jwt`); a builder for them is a planned addition.
