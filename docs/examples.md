# Examples

Run commands from the repository root unless a command changes directory. Install the source
dependencies using [Build and test](building.md) first.

## Offline examples

The builder examples in the [Python](../python/README.md#build-a-credential-offline),
[TypeScript](../typescript/README.md#build-a-credential-offline),
[Go](../go/README.md#build-a-credential-offline) and
[Java](../java/README.md#build-a-credential-offline) READMEs generate temporary keys and
build credentials without a server. They demonstrate the API. A configured authorisation server
must trust the attester's public key before it accepts such a credential.

The Python SPIFFE bridge is also an offline demonstration:

```bash
python/.venv/bin/python python/examples/spiffe_bridge.py
```

It uses `SpiffeAgent`, an in-process test implementation. It does not establish production
SPIFFE identity. Its fixed selectors and generated keys belong to the demonstration.

## Obtain a token from a configured attester

1. Obtain a renewable identity token file whose audience matches the attester's evidence audience.
   The attester must already trust its issuer and map its identity to an authorised client.

2. Set the file path in the shell running the example.

   ```bash
   export CLIENT_ATTESTATION_TOKEN_FILE=/absolute/path/to/identity-token.jwt
   export EVIDENCE_AUDIENCE=https://attester.example.com/evidence   # the token's audience; discovery must name it
   ```

3. Run the example for your language with the real attester host.

   ```bash
   python/.venv/bin/python python/examples/one_call_token.py https://attester.example.com
   ```

   ```bash
   (cd typescript && npx tsx examples/one-call-token.ts https://attester.example.com)
   ```

4. Read the result. Both examples request the demo `sales_agent` authorisation for `EMEA`.
   Edit or remove that request to match the attester's policy. They print the access token's length and a
   short SHA-256 fingerprint, never the token, and assert that a second acquisition uses the cached token. Run them in a local diagnostic session.

Go and Java one-call examples are in their [language READMEs](../README.md#documentation).
The host and token path above are placeholders. The repo supplies no identity issuer or live attester.

## Protected resource examples

The Python, TypeScript and Go examples listen on port 8770. Run one at a time.
They advertise `http://localhost:8770` as the resource audience and require `mcp:call`.
They demonstrate Bearer authentication and RFC 9728 metadata.

1. Set `ISSUER` in the Python or TypeScript source, or `issuer` in the Go source, to your access-token
   issuer. Set the JWKS URL to its real endpoint. The example default is `https://issuer.example.com`.

2. Start the example for your language.

   ```bash
   python/.venv/bin/python python/examples/protected_resource_server.py
   ```

   ```bash
   (cd typescript && npx tsx examples/protected-resource-server.ts)
   ```

   ```bash
   (cd go && go run ./examples/protected-resource)
   ```

3. In another terminal, request metadata and make an unauthenticated call.

   ```bash
   curl -i http://localhost:8770/.well-known/oauth-protected-resource
   curl -i http://localhost:8770/mcp
   ```

4. Expect 200 with JSON metadata from the first request. Expect 401 with `WWW-Authenticate`
   from the second. These checks work before an issuer is configured because no token is validated.

5. Obtain a Bearer token for audience `http://localhost:8770` with scope `mcp:call` from the configured
   authorisation server. Replace the placeholder below with that local test token.

   ```bash
   curl -i -H 'Authorization: Bearer <access-token>' http://localhost:8770/mcp
   ```

6. Expect 200 with the subject and scopes when validation succeeds. A token for another audience
   returns 401. A token missing the scope returns 403. Stop the example with Ctrl-C.

All three servers listen on `127.0.0.1:8770` only.
These are local demonstrations. They implement no MCP tools or A2A methods.
There is no Java resource-server executable in `java/examples/`. The
[Java README](../java/README.md#resource-server-validate-an-access-token) shows the integration API.

## SPIFFE issuance bootstrap

The bootstrap examples require an external PingFederate issuance servlet at
`/federation/attestation` and a token endpoint at `/as/token.oauth2`.
The development SVID endpoint `/dev/svid` belongs to the separate demo harness at
`pf-oidf-modules/demo/spiffe-bootstrap`. That harness is not included here.

1. Obtain and start the demo harness using its maintainer's instructions. Its example local origin
   is `http://localhost:9031`.

2. Run the command for your language after the harness is ready.

   ```bash
   ISSUER=http://localhost:9031 USE_DEV_SVID=1 python/.venv/bin/python python/examples/attestation_issuance_bootstrap.py
   ```

   ```bash
   (cd typescript && ISSUER=http://localhost:9031 USE_DEV_SVID=1 npx tsx examples/attestation-issuance-bootstrap.ts)
   ```

   ```bash
   (cd go && ISSUER=http://localhost:9031 USE_DEV_SVID=1 go run ./cmd/issuance-bootstrap)
   ```

3. Expect a minted attestation, an instance-key identifier and a successful token response.
   The examples print only a token's length and SHA-256 fingerprint, never the token or a prefix of it.

| Example variable | Default | Purpose |
| --- | --- | --- |
| `ISSUER` | `https://pf.example.com` | Server origin used for issuance and token endpoint URLs. Plain HTTP is refused except on loopback (`ISSUER=http://localhost:9031` works); set `ALLOW_INSECURE=1` to allow it elsewhere. |
| `CLIENT_ID` | `https://payment-agent.banking.demo` | Client identifier requested at issuance. |
| `ATTESTER_ISSUER` | `https://attester.banking.demo` | Evidence audience: the audience the SVID is requested for and the `aud` of the mint instance proof. |
| `OP_ISSUER` | `https://as.banking.demo` | Audience of the token-endpoint PoP JWT. |
| `SVID_JWT` | Unset | Fixed test SVID. Takes precedence over `USE_DEV_SVID`. |
| `USE_DEV_SVID` | Unset | `1` selects the harness's unauthenticated `/dev/svid` source. Otherwise the example uses SPIRE. |

These variables belong to the examples. They are separate from the SDK's auto-detection
variables. `AttestationIssuanceClient` is Experimental. Use a real SPIRE source for deployment.
Java provides the issuance API and interop tests, but no bootstrap example executable.
