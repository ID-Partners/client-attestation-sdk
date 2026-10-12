# Attestation issuance

[Configuration index](../configuration.md)

`AttestationIssuanceClient` obtains a Client Attestation from an explicit mint endpoint.
It returns the attestation and its instance key.
It does not exchange the attestation for an access token.
This client is Experimental because its default mint protocol is attester-specific.

## Required configuration

| Value | Python | TypeScript `create` argument | Go constructor / field | Java constructor argument | Meaning |
| --- | --- | --- | --- | --- | --- |
| Mint endpoint | `endpoint` | `endpoint` | `endpoint` / `Endpoint` | `endpoint` | Full URL, including the mint path. Python, Go (through the constructor) and Java remove every trailing slash; TypeScript removes one. |
| Client identifier | `client_id` | `clientId` | `clientID` / `ClientID` | `clientId` | Sent to the mint endpoint. |
| Evidence and proof audience | `attester_issuer` | `attesterIssuer` | `attesterIssuer` / `AttesterIssuer` | `attesterIssuer` | Used as the evidence fetch audience and the mint instance-proof `aud`. |
| Identity source | `svid_source` | `source` | `source` / `Source` | `svidSource` | Required evidence source. No auto-detection by this constructor. |

This client does not run discovery.
The endpoint and audience do not come from the one-call client's configuration.
Obtain them from the attester administrator.
The mint endpoint, and every URL a custom profile calls through the issuance transport, must use HTTPS
unless the host is loopback (`localhost`, `127.0.0.1`, `::1`). The constructor refuses a plain-HTTP
endpoint otherwise. The opt-out is Experimental: `allow_insecure=True` (Python), `{ allowInsecure: true }`
in the `create` options (TypeScript), `WithIssuanceAllowInsecure()` or the `AllowInsecure` field (Go), and
a trailing `boolean allowInsecure` constructor argument (Java).
Its default transport refuses redirects.
`bootstrap` returns an error when the profile mints no attestation.

## Optional configuration

| Port | Setting | Default | Behaviour |
| --- | --- | --- | --- |
| Python | `instance_key` | Generated key | Supplies an existing `SigningKeyPair`. |
| Python | `algorithm` | `ES256` | Used only when the instance key is not supplied. |
| Python | `profile` | `PingFederateProfile()` | Selects the mint protocol. Its discovery method is not called. |
| TypeScript | `create(..., { instanceKey, profile })` | Generated ES256 key and PingFederate profile | Supplies either setting. There is no separate algorithm option. |
| Go | `InstanceKey` | Generated ES256 key | Replace before bootstrap to use another key or algorithm. |
| Go | `Profile` | `nil` means PingFederate | Replace before bootstrap to use another mint protocol. |
| Go | `HTTPClient` | Client with 20-second timeout | Optional transport client. The SDK fills a missing timeout and always replaces its redirect policy with refusal. |
| Java | Fifth constructor argument `instanceKey` | Generated ES256 key in the four-argument constructor | Supplies an existing key. |
| Java | Sixth constructor argument `profile` | PingFederate profile | Supplies the mint protocol. A null profile uses PingFederate. |

Python, TypeScript and Java use a fixed 20-second mint-request timeout.
They expose no issuance timeout, logger or HTTP-client constructor option.
Go additionally bounds profile minting with a 20-second context deadline.
A longer custom HTTP-client timeout does not extend that deadline.
Evidence fetching uses the source's own timeout.
The selected instance key remains with this client across bootstrap calls.
A new bootstrap does not automatically replace it.

## Bootstrap and returned proofs

| Input | Python | TypeScript | Go | Java | Default |
| --- | --- | --- | --- | --- | --- |
| Requested authorisation | `bootstrap(authorization_details=...)` | `bootstrap(authorizationDetails, challenge)` | `Bootstrap(authorizationDetails, challenge)` | `bootstrap(authorizationDetails, challenge)` | Omitted. Go uses `nil`; Java uses `null`. |
| Mint challenge | `bootstrap(challenge=...)` | Optional second argument | Empty string omits | Null omits | No challenge. Obtain one through the server's required flow. |

The PingFederate profile sends `instance_key`, `svid`, `proof` and `client_id`.
It also sends requested `authorization_details` when provided.
The instance proof uses `typ: oauth-attestation-instance-proof+jwt`.
The expected response is `{"attestation": "<JWT>", "expires_in": 300}`.
The lifetime is optional. This client does not maintain an expiry-based cache.

`IssuedAttestation` contains `attestation`, `expires_in` and `instance_key` in Python.
TypeScript uses `attestation`, `expiresIn` and `instanceKey`.
Go uses `Attestation`, `ExpiresIn` and `InstanceKey`.
Java exposes those values through record-style getter methods.

`pop(audience, client_id=None, challenge=None)` creates a fresh dedicated PoP JWT in Python.
TypeScript and Java use `clientId`. Go uses `Pop(audience, clientID, challenge)`.
`dpop(method, uri, challenge=None)` creates a fresh combined-mode token-endpoint DPoP proof.
Go uses `Dpop(method, uri, challenge)`.
The returned proofs use the instance key bound in the minted attestation.
The caller adds the selected proof and attestation headers to its token request.
These helpers do not add a resource-request `ath` value.

## Failure behaviour

A non-2xx mint response raises `IssuanceError` in Python and TypeScript.
Go returns `*IssuanceError`.
Java raises `IssuanceException`.
Python, TypeScript and Go preserve separate transport failures for network, timeout and response failures.
Java wraps mint transport failures in `IssuanceException` with the original cause.
An evidence-source failure stops bootstrap before minting.
A custom profile owns its response interpretation and can raise its own errors.

## Configured Python example

This constructor generates a key without making a network request.
`bootstrap()` calls the configured evidence source and mint endpoint.
Replace the example identifiers before running it against an attester.

```python
from client_attestation_sdk import (
    AttestationIssuanceClient, FileTokenSvidSource, SigningKeyPair,
)

client = AttestationIssuanceClient(
    endpoint="https://attester.example/federation/attestation",
    client_id="payment-agent",
    attester_issuer="https://attester.example/evidence",
    svid_source=FileTokenSvidSource("/var/run/secrets/tokens/attester-token"),
    instance_key=SigningKeyPair.generate("ES256"),
)
# Network call. Supply the challenge obtained through your attester's flow.
issued = client.bootstrap(
    authorization_details=[{"type": "payment", "currency": "AUD"}],
    challenge="replace-with-server-challenge",
)
headers = {
    "OAuth-Client-Attestation": issued.attestation,
    "OAuth-Client-Attestation-PoP": issued.pop(
        "https://as.example", "payment-agent", "replace-with-token-challenge"),
}
```

See [Attester profiles](../attester-profiles.md) for custom minting examples in all four ports.
See [Examples](../examples.md) for the supplied issuance commands.

Source: [Python](../../python/src/client_attestation_sdk/issuance.py),
[TypeScript](../../typescript/src/issuance.ts), [Go](../../go/issuance.go),
[Java](../../java/src/main/java/global/idpartners/clientattestation/AttestationIssuanceClient.java).
