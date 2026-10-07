# Attester profiles

The draft (draft-ietf-oauth-attestation-based-client-auth, -10) says what a Client Attestation and its
proof of possession look like, how a client gets a challenge, and how the pair is presented at the token
endpoint. It says nothing about how a workload gets the attestation from its attester in the first place.
That part varies from one attester to the next, and in this SDK it lives in an **attester profile**.

A profile does two things:

1. **Discover** the attester: find its evidence audience and its attestation, token, challenge and PoP
   audience endpoints. It runs once per client and the result is cached.
2. **Mint**: build the mint request (including the proof that the workload holds the new instance key, and
   that proof's `typ`), send it, and read the attestation and its lifetime out of the response.

The profile also supplies the token endpoint when the attester does not name one.

Everything the draft defines stays in the client, whatever the profile: the challenge endpoint call
(`POST challenge_endpoint`, `attestation_challenge` in the response), the Client Attestation PoP JWT or
DPoP proof, the token request with its `OAuth-Client-Attestation` headers, the DPoP nonce retry, token
caching, and the https-only rule. The log events in [`logging.md`](logging.md) fire with the same names
whichever profile runs.

The default profile is **PingFederate**, the attester the SDK was built against. Code that does not
mention a profile behaves exactly as it did in 0.3.0, byte for byte on the wire.

## The PingFederate profile

### Discovery

`GET {attester_url}/.well-known/client-attester`, answered with a JSON object:

| Member | Used for |
| --- | --- |
| `evidence_audience` | The audience the workload's platform identity (SVID) is requested for, and the `aud` of the instance proof. Required. |
| `attestation_endpoint` | Where the mint request goes. Required. |
| `challenge_endpoint` | The draft's challenge endpoint. Optional; when present, a challenge is required unless the client opts out. |
| `token_endpoint` | The token endpoint. Optional; without it the client uses `{attester_url}/as/token.oauth2`. |
| `pop_audience` | The `aud` of the Client Attestation PoP (the AS issuer). Optional; without it, the token endpoint URL. |

### Mint

`POST attestation_endpoint` with `Content-Type: application/json`:

```json
{
  "instance_key": { "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "kid": "..." },
  "svid": "<the workload's platform identity token>",
  "proof": "<instance proof JWT>",
  "authorization_details": [ ... ],
  "operator": { ... }
}
```

`authorization_details` and `operator` are sent only when set (Python also sends `asserted_context` when a
call passes one). The one-call client sends no `client_id`: the attester maps the identity to a client.
The issuance client (`AttestationIssuanceClient`) puts `client_id` first.

The instance proof is a JWT signed by the new instance key, with header
`{"alg": ..., "typ": "oauth-attestation-instance-proof+jwt", "kid": <thumbprint>}` (no `jwk`) and claims
`{"aud": evidence_audience, "jti": <uuid>, "iat": <now>, "challenge": <challenge, if any>}`. The `typ` is
proprietary; it is not in the draft.

The response is `{"attestation": "<compact JWT>", "expires_in": <seconds>}`. A response with no
`attestation` is an error. The attestation's `sub` is the client id.

## Static endpoints, no discovery

An attester that publishes no discovery document can be described directly. The client then makes no
discovery request; the profile still mints (PingFederate's mint protocol unless you also pass a profile).
Give at least the evidence audience, the attestation endpoint and the token endpoint; the challenge
endpoint and PoP audience are optional. The attester URL is not needed.

```python
from client_attestation_sdk import AttesterMetadata, ClientAttestation

ca = ClientAttestation(metadata=AttesterMetadata(
    evidence_audience="https://attester.example",
    attestation_endpoint="https://attester.example/mint",
    token_endpoint="https://as.example/token",
    challenge_endpoint="https://as.example/challenge"))
```

```ts
const ca = new ClientAttestation({
  metadata: {
    evidenceAudience: "https://attester.example",
    attestationEndpoint: "https://attester.example/mint",
    tokenEndpoint: "https://as.example/token",
  },
});
```

```go
ca, err := clientattestation.NewClientAttestation("", clientattestation.WithAttesterMetadata(
    clientattestation.AttesterMetadata{
        EvidenceAudience:    "https://attester.example",
        AttestationEndpoint: "https://attester.example/mint",
        TokenEndpoint:       "https://as.example/token",
    }))
```

```java
ClientAttestation ca = ClientAttestation.builder()
        .metadata(AttesterMetadata.of("https://attester.example", "https://attester.example/mint",
                "https://as.example/token").withChallengeEndpoint("https://as.example/challenge"))
        .build();
```

Static endpoints must still be https unless they are loopback or the client allows insecure URLs.

## Writing a custom profile

Implement the two methods. Each gets a **transport** from the client, so the profile's calls share the
client's timeout, redirect and size limits, https rule, logging and (in Python) trace. Name each call with a
`step` (`discover`, `mint`, or your own); it shows up in `http.failed` events. The **mint request** carries
the instance key, the evidence, the challenge, the optional `client_id`, `authorization_details` and
`operator`, and has two helpers: `instance_proof(typ, audience)` signs the usual
`{aud, jti, iat[, challenge]}` proof with the instance key, and `sign(claims, typ)` signs anything else.

Each example below is for a made-up attester that publishes its configuration at `/acme/config`, wants a
proof with `typ` `acme-key-proof+jwt`, and answers a mint with `{"client_attestation": ..., "ttl": ...}`.
Each port's test suite runs a profile like this end to end.

### Python

```python
from client_attestation_sdk import AttesterMetadata, AttesterProfile, ClientAttestation, MintResult

class AcmeProfile(AttesterProfile):
    def discover(self, transport, attester_url):
        doc = transport.request_json("discover", "GET", attester_url + "/acme/config")
        return AttesterMetadata(evidence_audience=doc["audience"], attestation_endpoint=doc["mint_url"],
                                token_endpoint=doc["token_url"], document=doc)

    def mint(self, transport, metadata, request):
        proof = request.instance_proof("acme-key-proof+jwt", metadata.evidence_audience)
        body = {"evidence": request.evidence, "key": request.instance_key.public_jwk(), "pop": proof}
        response = transport.request_json("mint", "POST", metadata.attestation_endpoint, body)
        return MintResult(response["client_attestation"], response.get("ttl"))

ca = ClientAttestation("https://attester.example", profile=AcmeProfile())
```

### TypeScript

```ts
import { ClientAttestation, type AttesterProfile } from "@idpartners/client-attestation-sdk";

const acme: AttesterProfile = {
  async discover(transport, attesterUrl) {
    const doc = await transport.requestJson("discover", "GET", attesterUrl + "/acme/config");
    return {
      evidenceAudience: doc.audience as string,
      attestationEndpoint: doc.mint_url as string,
      tokenEndpoint: doc.token_url as string,
      document: doc,
    };
  },
  async mint(transport, metadata, request) {
    const pop = await request.instanceProof("acme-key-proof+jwt", metadata.evidenceAudience);
    const res = await transport.requestJson("mint", "POST", metadata.attestationEndpoint!, {
      evidence: request.evidence,
      key: request.instanceKey.publicJwk(),
      pop,
    });
    return { attestation: res.client_attestation as string, expiresIn: res.ttl as number };
  },
};

const ca = new ClientAttestation("https://attester.example", { profile: acme });
```

### Go

```go
type acmeProfile struct{}

func (acmeProfile) Discover(ctx context.Context, t clientattestation.AttesterTransport, attesterURL string) (*clientattestation.AttesterMetadata, error) {
    var doc struct {
        Audience string `json:"audience"`
        MintURL  string `json:"mint_url"`
        TokenURL string `json:"token_url"`
    }
    if err := t.RequestJSON(ctx, "discover", http.MethodGet, attesterURL+"/acme/config", nil, &doc); err != nil {
        return nil, err
    }
    return &clientattestation.AttesterMetadata{EvidenceAudience: doc.Audience,
        AttestationEndpoint: doc.MintURL, TokenEndpoint: doc.TokenURL}, nil
}

func (acmeProfile) Mint(ctx context.Context, t clientattestation.AttesterTransport, md *clientattestation.AttesterMetadata, req *clientattestation.MintRequest) (*clientattestation.MintResult, error) {
    pop, err := req.InstanceProof("acme-key-proof+jwt", md.EvidenceAudience)
    if err != nil {
        return nil, err
    }
    var res struct {
        ClientAttestation string `json:"client_attestation"`
        TTL               int64  `json:"ttl"`
    }
    body := map[string]any{"evidence": req.Evidence, "key": req.InstanceKey.PublicJWK(), "pop": pop}
    if err := t.RequestJSON(ctx, "mint", http.MethodPost, md.AttestationEndpoint, body, &res); err != nil {
        return nil, err
    }
    return &clientattestation.MintResult{Attestation: res.ClientAttestation, ExpiresIn: res.TTL}, nil
}

ca, err := clientattestation.NewClientAttestation("https://attester.example",
    clientattestation.WithAttesterProfile(acmeProfile{}))
```

### Java

```java
final class AcmeProfile implements AttesterProfile {
    @Override
    public AttesterMetadata discover(AttesterTransport transport, String attesterUrl) throws Exception {
        Map<String, Object> doc = transport.requestJson("discover", "GET", attesterUrl + "/acme/config", null);
        return new AttesterMetadata((String) doc.get("audience"), (String) doc.get("mint_url"),
                (String) doc.get("token_url"), null, null, doc);
    }

    @Override
    public MintResult mint(AttesterTransport transport, AttesterMetadata metadata, MintRequest request)
            throws Exception {
        String pop = request.instanceProof("acme-key-proof+jwt", metadata.evidenceAudience());
        Map<String, Object> res = transport.requestJson("mint", "POST", metadata.attestationEndpoint(),
                Map.of("evidence", request.evidence(), "key", request.instanceKey().publicJwk(), "pop", pop));
        return new MintResult((String) res.get("client_attestation"), ((Number) res.get("ttl")).longValue());
    }
}

ClientAttestation ca = ClientAttestation.builder("https://attester.example").profile(new AcmeProfile()).build();
```

A profile and static metadata can be combined: the metadata replaces discovery, and the profile mints.

## The issuance client

`AttestationIssuanceClient` is given its endpoint and attester issuer directly, so it never discovers. It
takes a profile too (`profile=` in Python, `{ profile }` in the TypeScript `create` options, the `Profile`
field in Go, a constructor argument in Java), and uses the profile's mint with `client_id` set on the mint
request. Its transport keeps its own errors: a non-2xx answer is still an `IssuanceError` /
`IssuanceException`.

## Per-port names

| Concept | Python | TypeScript | Go | Java |
| --- | --- | --- | --- | --- |
| Profile | `AttesterProfile` (base class) | `AttesterProfile` (interface) | `AttesterProfile` (interface) | `AttesterProfile` (interface) |
| Default profile | `PingFederateProfile()` | `new PingFederateProfile()` | `PingFederateProfile{}` | `new PingFederateProfile()` |
| Metadata | `AttesterMetadata` | `AttesterMetadata` | `AttesterMetadata` | `AttesterMetadata` (record) |
| Mint request / result | `MintRequest` / `MintResult` | `MintRequest` / `MintResult` | `MintRequest` / `MintResult` | `MintRequest` / `MintResult` |
| Transport | `AttesterTransport.request_json` | `AttesterTransport.requestJson` | `AttesterTransport.RequestJSON` | `AttesterTransport.requestJson` |
| Choose a profile | `profile=` | `profile` option | `WithAttesterProfile` | `.profile(...)` |
| Static metadata | `metadata=` | `metadata` option | `WithAttesterMetadata` | `.metadata(...)` |
| Resolved metadata | `attester_metadata()` | `attesterMetadata()` | `AttesterMetadata(ctx)` | `attesterMetadata()` |

`discovery()` still returns the raw discovery document in Python, TypeScript and Java (or, with static
metadata, the given fields under the document's snake_case names). In Go the raw document is the
`Document` field of the `*AttesterMetadata`. Go's `Discovery(ctx)` used to return the metadata; in 1.0 it
is renamed `AttesterMetadata(ctx)`, the name the other ports use.

Writing a profile (`AttesterProfile`, `AttesterTransport`, `MintRequest`, `MintResult`) is Experimental in
1.0: see [`api.md`](api.md). Choosing `PingFederateProfile` or passing static metadata is Stable.

## Renamed: `pf_host` is now `attester_url`

The attester URL is no longer assumed to be PingFederate. In Python, `ClientAttestation(pf_host=...)` is
gone in 1.0: pass the URL positionally or as `attester_url=`. The other ports only ever took the URL
positionally, so nothing changes for their callers.
