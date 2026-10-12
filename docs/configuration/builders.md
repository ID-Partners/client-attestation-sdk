# Keys, JWT builders and credentials

[Configuration index](../configuration.md)

A JSON Web Key (JWK) represents a cryptographic key as JSON.
A compact JSON Web Signature (JWS) is the signed, dot-separated token these builders return.
The builders create tokens locally. They make no network requests.

## Signing keys

| Operation | Python | TypeScript | Go | Java |
| --- | --- | --- | --- | --- |
| Generate | `SigningKeyPair.generate(algorithm)` | `await SigningKeyPair.generate(algorithm, options)` | `Generate(algorithm)` | `SigningKeyPair.generate(algorithm)` |
| Import private JWK | `SigningKeyPair.from_jwk(jwk, algorithm)` | `await SigningKeyPair.fromJwk(jwk, algorithm)` | `FromJWK(jwk, algorithm)` | `SigningKeyPair.fromJwk(jwk, algorithm)` |
| Public JWK | `public_jwk()` | `publicJwk()` | `PublicJWK()` | `publicJwk()` |
| Key identifier | `key_id` | `keyId` | `KeyID()` | `keyId()` |

`algorithm` is required for generation and import.
The accepted values are `ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512`,
`PS256`, `PS384` and `PS512`.
The EC curves are P-256, P-384 and P-521 respectively.
RSA generation uses 2048-bit keys.
An unsupported algorithm fails generation.
The identifier is the public key's RFC 7638 JWK thumbprint.

TypeScript generation accepts `{ extractable: true }`.
The default is `false` - its generated private `CryptoKey` cannot be exported.
This setting is needed only when the application exports the generated private key for storage.
It does not prevent signing or public-JWK export.
The other ports expose no equivalent generation setting.
The import must contain a private key of the right type for the supplied algorithm. Every port refuses
an EC key on another curve than the algorithm's, an RSA key under 2048 bits, and a JWK whose public
members don't belong to its private key. Go and Java no longer load Ed25519 keys.
The published public JWK is re-encoded from the key: EC coordinates at the curve's full width, RSA `n` and
`e` in minimal octets, and only `kty`, the key members and the thumbprint `kid`, so the same key has the
same `kid` in every port. A signature header's `kid` is always that thumbprint.
Go `FromJWK` accepts JSON bytes, JSON text or `map[string]any`.
Python also exposes `SigningKeyPair(private_key, algorithm, public_jwk)` for a supplied cryptography key.
The private key and public JWK must belong to the same key pair.
The generated and imported factories derive that pairing for the caller.
Java's Stable import accepts `Map<String, Object>`.
Its jose4j `PublicJsonWebKey` overload is Experimental.

## ClientAttestationBuilder

The constructor takes `attester_key`, the attester's issuing key or a `JwsSigner`, and `issuer`, its issuer identifier.
Go uses `NewClientAttestationBuilder(key, issuer)` or
`NewClientAttestationBuilderWithSigner(signer, issuer)`.
The issuing key is separate from the client's instance key.

| Claim or input | Python method | TypeScript / Java method | Go method | Default and requirement |
| --- | --- | --- | --- | --- |
| Client identifier, `sub` | `client_id` | `clientId` | `ClientID` | Required. |
| Instance public key, `cnf.jwk` | `confirmation_jwk` | `confirmationJwk` | `ConfirmationJWK` | Required unless set from an instance key. Supply a public `EC` (P-256, P-384, P-521) or `RSA` JWK. A JWK with a private or secret member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`), another `kty` or a missing public member is refused; only `kty`, the public members and `kid` are copied into `cnf.jwk`. Python, TypeScript and Java throw when it is set; Go returns the error from `Build`. |
| Instance key convenience setter | `confirmation_key` | `confirmationKey` | `ConfirmationKey` | Extracts its public JWK. Replaces the confirmation JWK. |
| Issued time, `iat` | `issued_at` | `issuedAt` | `IssuedAt` | Current epoch seconds at build time. |
| Absolute expiry, `exp` | `expires_at` | `expiresAt` | `ExpiresAt` | No default. Takes precedence over relative expiry. |
| Relative expiry | `expires_in` | `expiresIn` | `ExpiresIn` | Seconds added to `iat`. Set this or absolute expiry. `exp` must be after `iat`: a zero or negative lifetime is refused. |
| Requested authorisation | `authorization_details` | `authorizationDetails` | `AuthorizationDetails` | Omitted. List of authorisation-detail objects. |
| Workload claims | `workload` | `workload` | `Workload` | Omitted. Object supplied by the attester. |
| Operator assertion | `operator(sub, issuer=None)` | `operator(sub, issuer)` - TypeScript issuer optional | `Operator(sub, issuer)` | Omitted. Produces `operator.sub` and optional `operator.iss`. Java takes both arguments; pass `null` to omit the issuer. |

Python, TypeScript and Go use epoch seconds for issued and absolute expiry times.
Python names these setter arguments `epoch_seconds`.
They use seconds for relative expiry.
Java `issuedAt` and `expiresAt` take `java.time.Instant`.
Java `expiresIn` takes `java.time.Duration`.
Java's PoP and DPoP `issuedAt` setters also take `Instant`.
Setters replace the previous value for that field.
`expires_at` takes precedence over `expires_in` even when relative expiry is set last.
Go and Java use an empty issuer string or `null` to omit the operator issuer.
The builder requires a client identifier, confirmation key and expiry.
An issuer identifier is required.
Choose a positive lifetime that meets the verifier's policy.
The builder does not enforce the authorisation server's lifetime or claim policy.
The header contains `typ: oauth-client-attestation+jwt` and the issuing key's `kid`.

## PopBuilder

The constructor takes the client's instance key.
Go uses `NewPopBuilder(instanceKey)`.
This key must match the Client Attestation's `cnf.jwk`.

| Input | Python | TypeScript / Java | Go | Default |
| --- | --- | --- | --- | --- |
| Audience, `aud` | `audience` | `audience` | `Audience` | Required. Use the configured PoP audience. |
| Client identifier, `iss` | `client_id` | `clientId` | `ClientID` | Omitted. |
| Challenge | `challenge` | `challenge` | `Challenge` | Omitted. Use the server's challenge when required. |
| JWT identifier, `jti` | `jwt_id` | `jwtId` | `JwtID` | Fresh UUID. |
| Issued time, `iat` | `issued_at` | `issuedAt` | `IssuedAt` | Current epoch seconds. |

The header contains `typ: oauth-client-attestation-pop+jwt` and the instance key's `kid`.
The builder does not add `exp`.
Build a fresh proof for each token request.
Manually fixing `jti` or `iat` makes the application responsible for their freshness.

## DpopProofBuilder

DPoP means Demonstrating Proof of Possession.
The constructor takes the client's instance key.
Go uses `NewDpopProofBuilder(instanceKey)`.

| Input | Python | TypeScript / Java | Go | Default |
| --- | --- | --- | --- | --- |
| HTTP method, `htm` | `method` | `method` | `Method` | `POST`. Converted to upper case. Set the actual resource request method. |
| Request URI, `htu` | `uri` | `uri` | `URI` | Required. Query and fragment are removed. |
| Nonce | `nonce` | `nonce` | `Nonce` | Omitted. |
| Access-token binding, `ath` | `access_token` | `accessToken` | `AccessToken` | Omitted. Computes base64url(SHA-256(access token)). Set for a resource proof. |
| JWT identifier, `jti` | `jwt_id` | `jwtId` | `JwtID` | Fresh UUID. |
| Issued time, `iat` | `issued_at` | `issuedAt` | `IssuedAt` | Current epoch seconds. |

The URI uses a lower-case scheme and host and omits the default HTTP or HTTPS port.
The header contains `typ: dpop+jwt` and the public instance `jwk` without its `kid`.
The builder does not add `exp` or perform proof verification.
Build a fresh proof for each HTTP request.
A token-endpoint proof in `dpop_combined` mode uses the key bound in the Client Attestation.
A resource proof also needs `ath` for the access token it accompanies.

## ClientAttestationCredential

The constructor takes the signed `attestationJwt` and its `instanceKey`.
Python names these arguments `attestation_jwt` and `instance_key`.
Go uses `NewClientAttestationCredential(attestationJWT, instanceKey)`.
It holds the supplied values and builds fresh proof headers.
It does not mint, renew or validate the attestation.

| Operation | Python | TypeScript / Java | Go |
| --- | --- | --- | --- |
| Dedicated PoP headers | `pop_headers(client_id, audience, challenge=None)` | `popHeaders(clientId, audience, challenge)` | `PopHeaders(clientID, audience, challenge)` |
| Combined DPoP headers | `dpop_headers(method, uri, challenge=None)` | `dpopHeaders(method, uri, challenge)` | `DpopHeaders(method, uri, challenge)` |

TypeScript's challenge is optional. Java has only the three-argument forms.
Go uses `""` to omit it. Python and Java use `None` or `null`.
Both return `OAuth-Client-Attestation` plus the selected proof header.
These are token-endpoint authentication headers.
They do not generate an access-token `Authorization` header or a resource `ath` binding.

## Offline example

Save the block as `/tmp/sdk-builders.py` and run it from the repository root with
`python/.venv/bin/python /tmp/sdk-builders.py` after the [Python installation](../building.md#python).
Successful completion prints `builder configuration passed`.

```python
import time
import jwt
from client_attestation_sdk import (
    SigningKeyPair, ClientAttestationBuilder, ClientAttestationCredential,
    PopBuilder, DpopProofBuilder,
)

now = int(time.time())
issuing_key = SigningKeyPair.generate("ES256")
instance_key = SigningKeyPair.generate("ES256")
attestation = (ClientAttestationBuilder(issuing_key, "https://attester.example")
    .client_id("payment-agent")
    .confirmation_key(instance_key)
    .issued_at(now)
    .expires_at(now + 600)
    .expires_in(30)
    .authorization_details([{"type": "payment", "currency": "AUD"}])
    .workload({"name": "payment-agent"})
    .operator("operator@example.com", "https://directory.example")
    .build())
claims = jwt.decode(attestation, options={"verify_signature": False})
assert claims["exp"] == now + 600
pop = (PopBuilder(instance_key).client_id("payment-agent")
    .audience("https://as.example").challenge("example-challenge")
    .jwt_id("offline-pop").issued_at(now).build())
proof = (DpopProofBuilder(instance_key).method("get")
    .uri("https://api.example/payments?limit=5#top")
    .access_token("example-access-token").nonce("example-nonce")
    .jwt_id("offline-dpop").issued_at(now).build())
proof_claims = jwt.decode(proof, options={"verify_signature": False})
assert proof_claims["htm"] == "GET"
assert proof_claims["htu"] == "https://api.example/payments"
assert "ath" in proof_claims
credential = ClientAttestationCredential(attestation, instance_key)
assert "OAuth-Client-Attestation-PoP" in credential.pop_headers(
    "payment-agent", "https://as.example", "example-challenge")
print("builder configuration passed")
```

Decoding without signature verification here inspects locally generated test output.
It is not access-token validation.
See [Signers](signers.md) for issuing keys held outside the process.

Source: [Python builders](../../python/src/client_attestation_sdk/builders.py),
[TypeScript builders](../../typescript/src/builders.ts), [Go builders](../../go/builders.go),
[Go DPoP](../../go/dpop.go),
[Java builders](../../java/src/main/java/global/idpartners/clientattestation/ClientAttestationBuilder.java).
