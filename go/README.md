# client-attestation-sdk (Go)

Go port of the client-side SDK for **OAuth Attestation-Based Client Authentication**
(`draft-ietf-oauth-attestation-based-client-auth`). It builds the three artifacts a
client presents at the token endpoint and is wire-compatible with the Java and
Python ports — the same AS-side Java verifier accepts all three.

Package `clientattestation`; signing via
[`github.com/lestrrat-go/jwx/v2`](https://github.com/lestrrat-go/jwx).

## Artifacts

| Artifact | `typ` | Key material in header | Notable claims |
|----------|-------|------------------------|----------------|
| Client Attestation JWT | `oauth-client-attestation+jwt` | attester `kid` (RFC 7638 thumbprint) | `iss`, `sub`=client_id, `iat`, `exp`, `cnf.jwk` (instance public JWK **incl. kid**) |
| PoP JWT | `oauth-client-attestation-pop+jwt` | instance `kid` | `aud`, `jti`, `iat`, optional `iss`/`challenge` (no `exp`) |
| DPoP proof | `dpop+jwt` | embedded `jwk` (instance public JWK **excl. kid**) | `htm`, `htu`, `jti`, `iat`, optional `nonce` |

`kid` is the RFC 7638 JWK thumbprint (SHA-256, base64url no padding). `iat`/`exp`
are integer epoch seconds; `aud` is a single string. ES256 throughout.

## Usage

```go
attester, _ := clientattestation.Generate("ES256") // or FromJWK(jwk, "ES256")
instance, _ := clientattestation.Generate("ES256")

attestation, _ := clientattestation.
    NewClientAttestationBuilder(attester, "https://attester.example.com").
    ClientID("https://rp.example.com").
    ConfirmationKey(instance).
    ExpiresIn(300).
    // optional: .Workload(...) / .AuthorizationDetails(...) / .Operator(sub, issuer) —
    // Operator names who's accountable for running the client (RFC 8693 may_act-shaped;
    // an assertion, not proof of authorisation), distinct from ClientID and from the principal.
    Build()

cred, _ := clientattestation.NewClientAttestationCredential(attestation, instance)

// Dedicated PoP-JWT mode (PoP method attestation_pop_jwt):
popHeaders, _ := cred.PopHeaders("https://rp.example.com", "https://as.example.com", "")

// DPoP combined mode (PoP method dpop_combined):
dpopHeaders, _ := cred.DpopHeaders("POST", "https://as.example.com/as/token.oauth2", "")
```

`PopHeaders` returns `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP`;
`DpopHeaders` returns `OAuth-Client-Attestation` + `DPoP`.

The one-call `ClientAttestation` orchestration class (see the [root README](../README.md#get-a-token-in-one-call))
wraps this: `WithPopMethod("dpop_combined")` switches it to DPoP mode, and a fetched challenge is carried
through automatically as the PoP JWT's `challenge` claim or the DPoP proof's `nonce` claim, whichever mode
is active.

```go
ca, _ := clientattestation.NewClientAttestation("pf.example.com",
    clientattestation.WithPopMethod(clientattestation.PopMethodDpopCombined))

// Per-request headers: Bearer -> Authorization only; a DPoP-bound token (token_type DPoP) ->
// Authorization: DPoP <t> plus a fresh DPoP proof (htm, htu, ath, and the origin's last DPoP-Nonce).
headers, _ := ca.RequestHeaders(ctx, "GET", "https://api.example.com/data")

// Or let an http.Client do it: the RoundTripper builds a proof per request and retries once on a
// use_dpop_nonce challenge (rewinding the body with req.GetBody).
client := &http.Client{Transport: ca.RoundTripper()}
```

The instance key that minted the attestation is kept with the cached token, so every proof for that
token is signed by the key it is bound to; a new key comes with each new token. If the AS answers the
token request with `400 use_dpop_nonce`, the request is retried once with the server's nonce.
`AuthorizationHeader` returns `DPoP <t>` for a DPoP-bound token, but that alone is not enough - the
resource also needs a proof, so use `RequestHeaders` or `RoundTripper`.

Fail-closed defaults:

- If discovery advertises `challenge_endpoint` and no challenge can be fetched, the flow fails.
  `WithRequireChallenge(false)` proceeds without one instead.
- `CLIENT_ATTESTATION_TOKEN_FILE` or `SPIFFE_ENDPOINT_SOCKET` set to a missing path is an
  `*EvidenceNotFound` naming the variable, not a fall-through to the next source.
- The PF host and every discovered endpoint must be https unless the host is loopback
  (`localhost`, `127.0.0.1`, `::1`) or `WithAllowInsecure()` is given.

## Develop

```sh
go mod tidy
go test ./...        # round-trip self-verification
go run ./cmd/emit    # writes ../vectors/out/go.json for the cross-language gate
```
