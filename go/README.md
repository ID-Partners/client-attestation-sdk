# client-attestation-sdk (Go)

Go port of the client-side SDK for **OAuth Attestation-Based Client Authentication**
(`draft-ietf-oauth-attestation-based-client-auth`). It builds the three artifacts a
client presents at the token endpoint and is wire-compatible with the Java, Python
and TypeScript ports — the same AS-side Java verifier accepts them all.

Package `clientattestation`; signing via
[`github.com/lestrrat-go/jwx/v2`](https://github.com/lestrrat-go/jwx).

## Install

Run from the consuming application's directory. Initialise its module before adding the SDK
if it does not yet have a `go.mod`:

```bash
go mod init example.com/my-agent
```

```bash
go get github.com/id-partners/client-attestation-sdk/go
```

Go 1.25 or later. The resource-server validator is the `tokenvalidator` subpackage.

## Artifacts

| Artifact | `typ` | Key material in header | Notable claims |
|----------|-------|------------------------|----------------|
| Client Attestation JWT | `oauth-client-attestation+jwt` | attester `kid` (RFC 7638 thumbprint) | `iss`, `sub`=client_id, `iat`, `exp`, `cnf.jwk` (instance public JWK **incl. kid**) |
| PoP JWT | `oauth-client-attestation-pop+jwt` | instance `kid` | `aud`, `jti`, `iat`, optional `iss`/`challenge` (no `exp`) |
| DPoP proof | `dpop+jwt` | embedded `jwk` (instance public JWK **excl. kid**) | `htm`, `htu`, `jti`, `iat`, optional `nonce` and `ath` |

`kid` is the RFC 7638 JWK thumbprint (SHA-256, base64url no padding). `iat`/`exp`
are integer epoch seconds; `aud` is a single string. ES256 by default; `Generate` and
`WithAlgorithm` also take ES384/512, RS256/384/512 and PS256/384/512.

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

Save as `main.go` in your application module after installing the SDK with `go get`:

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	clientattestation "github.com/id-partners/client-attestation-sdk/go"
)

func main() {
	ca, err := clientattestation.NewClientAttestation(os.Getenv("ATTESTER_URL"),
		clientattestation.WithEvidenceAudience(os.Getenv("EVIDENCE_AUDIENCE")))
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Transport: ca.RoundTripper(), Timeout: 60 * time.Second}
	response, err := client.Get(os.Getenv("API_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		log.Fatalf("API returned HTTP %d", response.StatusCode)
	}
	fmt.Println(response.StatusCode)
}
```

Run `go run .`. Keep the client and `ca` for later requests so they reuse the token cache.
`RoundTripper` attaches a DPoP proof when the token requires one. DPoP binds the token to a
client key and requires a signed proof for each request.
See [Configuration](../docs/configuration.md) for options and evidence sources.

## Build a credential offline

This complete program generates temporary keys. It needs no server.

```go
package main

import (
	"fmt"
	"log"

	clientattestation "github.com/id-partners/client-attestation-sdk/go"
)

func main() {
	attester, err := clientattestation.Generate("ES256")
	must(err)
	instance, err := clientattestation.Generate("ES256")
	must(err)

	attestation, err := clientattestation.
		NewClientAttestationBuilder(attester, "https://attester.example.com").
		ClientID("https://rp.example.com").
		ConfirmationKey(instance).
		ExpiresIn(300).
		Build()
	must(err)

	cred, err := clientattestation.NewClientAttestationCredential(attestation, instance)
	must(err)

	// Dedicated PoP-JWT mode (PoP method attestation_pop_jwt):
	popHeaders, err := cred.PopHeaders("https://rp.example.com", "https://as.example.com", "")
	must(err)

	// DPoP combined mode (PoP method dpop_combined):
	dpopHeaders, err := cred.DpopHeaders("POST", "https://as.example.com/as/token.oauth2", "")
	must(err)
	fmt.Println(len(popHeaders), len(dpopHeaders)) // 2 2
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
```

Save as `main.go` in a separate example module and run `go run .`. The generated keys are for
the example. A production authorisation server must trust the attester's signing key.

`PopHeaders` returns `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP`;
`DpopHeaders` returns `OAuth-Client-Attestation` + `DPoP`.

The one-call `ClientAttestation` client (see the [root README](../README.md#get-a-token-in-one-call))
wraps this: `WithPopMethod("dpop_combined")` switches it to DPoP mode, and a fetched challenge is carried
through automatically as the PoP JWT's `challenge` claim or the DPoP proof's `nonce` claim, whichever mode
is active.

```go
ca, _ := clientattestation.NewClientAttestation("pf.example.com",
    clientattestation.WithEvidenceAudience("https://pf.example.com"), // the audience your attester expects
    clientattestation.WithPopMethod(clientattestation.PopMethodDpopCombined))

// Per-request headers: Bearer -> Authorization only; a DPoP-bound token (token_type DPoP) ->
// Authorization: DPoP <t> plus a fresh DPoP proof (htm, htu, ath, and the origin's last DPoP-Nonce).
headers, _ := ca.RequestHeaders(ctx, "GET", "https://api.example.com/data")

// Or let an http.Client do it: the RoundTripper builds a proof per request and retries once on a
// use_dpop_nonce challenge (rewinding the body with req.GetBody).
client := &http.Client{Transport: ca.RoundTripper()}
```

The instance key that minted the attestation is kept with the cached token, so every proof for that
token is signed by the key it is bound to; a new key comes with each new token. In `dpop_combined`
mode, if the AS answers the token request with `use_dpop_nonce` (a 400 JSON error or a 401 DPoP
challenge) and a `DPoP-Nonce` header, the request is retried once with the server's nonce.
`AuthorizationHeader` returns `DPoP <t>` for a DPoP-bound token, but that alone is not enough - the
resource also needs a proof, so use `RequestHeaders` or `RoundTripper`. The `RoundTripper` never attaches
credentials to a redirect hop: if the `http.Client` would follow a redirect, `Do` fails instead with a
`*url.Error` wrapping a `*ClientAttestationError` (find it with `errors.As`), without contacting the target.

Fail-closed defaults:

- `WithEvidenceAudience(aud)` is required unless `WithAttesterMetadata` is given: it pins the audience the
  workload's identity token is requested for, so the attester's discovery document can't choose it (an
  attester could otherwise have the workload mint a token for another service that trusts it). A missing
  pin, or a discovered `evidence_audience` that differs from it, is a `*ClientAttestationError` before any
  evidence is fetched. With `WithAttesterMetadata` the pin is optional and, when given, must match.
- If discovery advertises `challenge_endpoint` and no challenge can be fetched, the flow fails.
  `WithRequireChallenge(false)` proceeds without one instead.
- `CLIENT_ATTESTATION_TOKEN_FILE` or `SPIFFE_ENDPOINT_SOCKET` set to a missing path is an
  `*EvidenceNotFound` naming the variable, not a fall-through to the next source.
- The attester URL and every discovered endpoint must be https unless the host is loopback
  (`localhost`, `127.0.0.1`, `::1`) or `WithAllowInsecure()` is given.

Other attesters: `NewClientAttestation` speaks PingFederate's discovery and mint protocol by default.
`WithAttesterProfile(p)` plugs in your own `AttesterProfile`, and `WithAttesterMetadata(m)` gives the
endpoints directly with no discovery (the URL argument can then be `""`). `AttestationIssuanceClient` has a
`Profile` field. See [`docs/attester-profiles.md`](../docs/attester-profiles.md).

`AttestationIssuanceClient` (its endpoint and every call its profile makes) and `NewOpenBaoTransitSigner`
(the vault address) follow the same https rule. `WithIssuanceAllowInsecure()` or the `AllowInsecure` field,
and `WithOpenBaoAllowInsecure()`, lift it.

## Resource server: validate an access token

The `tokenvalidator` package checks the access tokens a resource server receives. The order of checks
and the error codes are shared with the other ports and pinned by
[`validation/SEMANTICS.md`](../validation/SEMANTICS.md).

```go
import "github.com/id-partners/client-attestation-sdk/go/tokenvalidator"

v, err := tokenvalidator.New(&tokenvalidator.Config{
    Issuer:         "https://issuer.example.com",
    Audiences:      []string{"https://api.example.com"},
    JWKSURI:        "https://issuer.example.com/jwks",
    RequiredScopes: []string{"read"},
})
if err != nil {
    log.Fatal(err)
}
res := v.Validate(accessToken, nil) // nil: use Config.RequiredScopes
if !res.Valid {
    log.Print(res.Error) // e.g. tokenvalidator.ErrExpired
}
```

`New` refuses a `JWKSURI` or introspection `Endpoint` that isn't https, unless its host is loopback
(`localhost`, `127.0.0.1`, `::1`); set `AllowInsecure: true` in the `Config` to lift that.

`Validate` checks the token only. It doesn't look at `cnf`, so a DPoP- or mTLS-bound token is `Valid`
without its sender proof: refuse a token whose `Claims["cnf"]` is set unless you verify that proof.

`tokenvalidator.NewProtectedResource(resource, authorizationServers, v, scopesSupported)` adds RFC 9728
metadata, Bearer extraction and `WWW-Authenticate` challenges. `Authenticate(authorizationHeader, nil)`
is the request guard: it returns an `AuthDecision` with the HTTP status (401, or 403 for missing scope)
and the challenge, and refuses a token with a `cnf` claim with 401, because it never sees the sender
proof. `AuthenticateActive(authorizationHeader, nil)` is the same guard for tokens checked by
introspection: it returns `(AuthDecision, error)`, requires this resource in the response's `aud` and
refuses `cnf`. A runnable server is in [`examples/protected-resource`](examples/protected-resource/main.go).
See [resource configuration](../docs/configuration.md#resource-server-configuration) and the
[resource-server example](../docs/examples.md#protected-resource-examples).

## Build and test

```sh
cd go               # from the repository root
go mod download
go vet ./...
go test -race -cover ./...
go build ./...
go run ./cmd/emit            # writes ../vectors/out/go.json for ./verify-interop.sh
go run ./cmd/validate-emit   # writes ../validation/out/go.json for ./verify-validation.sh
```

The SDK is compiled into the consuming application. See [Build and test](../docs/building.md#go)
for building an example binary and [Deployment](../docs/deployment.md) for runtime identity setup.
