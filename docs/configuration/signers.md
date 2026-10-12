# External issuing-key signers

[Configuration index](../configuration.md)

`JwsSigner` lets the Client Attestation builder use an issuing key outside the process.
The one-call client still generates its instance key locally.
A signer is passed to `ClientAttestationBuilder` as its attester key.
Go uses `NewClientAttestationBuilderWithSigner`.

## OpenBaoTransitSigner

This Experimental signer uses OpenBao or HashiCorp Vault's Transit secrets engine.
It reads an existing key and signs through HTTP requests.

| Input | Python | TypeScript `create` | Go constructor | Java constructor | Requirement |
| --- | --- | --- | --- | --- | --- |
| Server base URL | `bao_addr` | `baoAddr` | `baoAddr` | `baoAddr` | Origin such as `https://openbao.example`. |
| Authentication token | `token` | `token` | `token` | `token` | Static token supplied by the application. |
| Transit key name | `key_name` | `keyName` | `keyName` | `keyName` | Existing key under the `transit` mount. |

Python uses `OpenBaoTransitSigner(bao_addr, token, key_name)`.
TypeScript uses `await OpenBaoTransitSigner.create(baoAddr, token, keyName)`.
Go uses `NewOpenBaoTransitSigner(baoAddr, token, keyName)` and checks the returned error.
Java uses `new OpenBaoTransitSigner(baoAddr, token, keyName)`.
Construction makes a network request to read key metadata.
The server base URL must use HTTPS unless the host is loopback (`localhost`, `127.0.0.1`, `::1`), because
the vault token is sent on every call; construction fails otherwise. The opt-out is Experimental:
`allow_insecure=True` (Python keyword), `{ allowInsecure: true }` as the fourth `create` argument
(TypeScript), `WithOpenBaoAllowInsecure()` (Go), and a trailing `boolean allowInsecure` constructor
argument (Java). The key name may contain only letters, digits, `_`, `.` and `-`, and may not be `.` or
`..`.

| Control | Current behaviour |
| --- | --- |
| Mount | Fixed `transit`. No mount-path option. |
| Key metadata path | `/v1/transit/keys/<key_name>`. |
| Signing path | `/v1/transit/sign/<key_name>`. |
| Authentication | `X-Vault-Token` with the supplied token. No automatic renewal. |
| Key types | `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`. Select ES256, ES384 and ES512 respectively. |
| Key version | Pins the latest version read at construction. Each signature requests that version. |
| HTTP timeout | Fixed 5 seconds per request. |
| Response limit | 1048576 bytes (1 MiB). |
| Redirects | Default transport refuses them. |
| Public key identifier | RFC 7638 thumbprint of the pinned public key. |
| Key creation | None. The vault administrator creates the key and grants access. |

The signer does not read `BAO_ADDR`, `VAULT_ADDR`, `BAO_TOKEN` or `VAULT_TOKEN` itself.
Applications can use those variables and pass their values.
A rotated server key does not change an already constructed signer.
Construct a new signer to use the new version.
Publish its public JWK through the verifier's configured trust source before using it.
Retain old verifying keys for credentials that remain valid under the deployment's rotation policy.
Obtain that policy from the attester administrator.

## Signer interface

| Member | Python | TypeScript | Go | Java | Contract |
| --- | --- | --- | --- | --- | --- |
| Algorithm | `algorithm` | `algorithm` | `Algorithm()` | `algorithm()` | JWS algorithm identifier. |
| Identifier | `key_id` | `keyId` | `KeyID()` | `keyId()` | Header `kid`. |
| Public key | `public_jwk()` | `publicJwk()` | `PublicJWK()` | `publicJwk()` | Public JWK matching the signing key. |
| Signature | `sign(signing_input)` | `sign(signingInput)` | `Sign(signingInput)` | `sign(signingInput)` | Sign the supplied JWS signing-input bytes. Return signature bytes. |

TypeScript signing is asynchronous.
Go returns bytes and an error.
ECDSA signatures must use JWS's raw `r || s` format.
A hardware signer returning an ASN.1 DER signature must convert it before returning.
The SDK encodes those signature bytes into the compact JWS.
A custom signer owns connection timeouts, authentication and key-version selection.
It must report signing failure to the builder.

## Application configuration example

Run this only with an existing Transit key and an authorised vault token.
The environment variable names below are application configuration.
They are not SDK auto-detection settings.

```python
import os
from client_attestation_sdk import (
    ClientAttestationBuilder, OpenBaoTransitSigner, SigningKeyPair,
)

signer = OpenBaoTransitSigner(
    bao_addr=os.environ["BAO_ADDR"],
    token=os.environ["BAO_TOKEN"],
    key_name=os.environ["ATTESTER_TRANSIT_KEY"],
)
instance_key = SigningKeyPair.generate("ES256")
attestation = (ClientAttestationBuilder(signer, os.environ["ATTESTER_ISSUER"])
    .client_id("payment-agent")
    .confirmation_key(instance_key)
    .expires_in(300)
    .build())
```

The application must register `signer.public_jwk()` with its attestation verifier's trust configuration.
See [Builders](builders.md) for every claim setter.

Source: [Python](../../python/src/client_attestation_sdk/signer.py),
[TypeScript](../../typescript/src/signer.ts), [Go](../../go/signer.go),
[Java](../../java/src/main/java/global/idpartners/clientattestation/OpenBaoTransitSigner.java).
