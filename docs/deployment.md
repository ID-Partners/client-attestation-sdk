# Deployment

The SDK runs inside your application. Deploy the application with the SDK dependency and a
workload identity that the attester accepts. The repository contains libraries and demonstration
programs. It does not contain a production service or an attester deployment.

## Deploy a consuming application

1. Add a released SDK version to your application's dependency file. The package names and install
   commands are in the [root README](../README.md#install). Pin the version used by your build.

2. Obtain the attester base URL, evidence audience and workload identity mapping from the attester
   administrator. The authorisation server must accept `attest_jwt_client_auth` and the selected
   PoP method. Confirm the identity mapping grants access to the API your application calls.

3. Pass the attester URL and the evidence audience into `ClientAttestation` at application startup. The
   language READMEs show examples using application-defined `ATTESTER_URL` and `EVIDENCE_AUDIENCE`
   variables. Retain the client instance so
   it can reuse the token cache.

4. Provide renewable evidence through a mounted token file, SPIRE or a supported metadata source.
   See [Configuration](configuration.md#workload-identity). SPIRE evidence requires socket access
   and the `spire-agent` executable in the application's runtime.

5. Build the application with its normal build process. Include the SDK's runtime dependencies.
   For a container, install dependencies while building the image. Mount evidence at runtime.
   Keep the attester and discovered endpoints on HTTPS. The SDK permits HTTP on loopback for
   local examples.

6. Allow outbound connections to discovery, mint, challenge and token endpoints. Also allow the
   identity source's calls where applicable. Configure the runtime's trusted certificate
   authorities for your deployment's TLS certificates.

7. Call the API through `requests_auth` / `httpx_auth`, `fetch`, `RoundTripper` or `send`, according
   to the language. These adapters attach the token and generate resource-request DPoP proofs
   when the token is DPoP-bound. Raw token strings do not include those proofs.

8. Verify one successful API request in the deployed runtime. Repeat it to exercise token reuse.
   Run another request after the token's refresh margin to exercise renewal. Enable the SDK's
   [logging](logging.md) to distinguish cache hits, new tokens and failed HTTP calls.

The attester's identity rules, authorisation policy and server configuration are external to
this repository. Use the attester administrator's deployment instructions for those settings.

## What happens at runtime

For each new token, the one-call client:

1. discovers the attester (once per client instance; static metadata skips this);
2. reads the workload's evidence for the attester's `evidence_audience`;
3. generates a fresh instance key, held only in memory;
4. fetches a challenge, when the attester advertises a `challenge_endpoint`;
5. mints a Client Attestation bound to the instance key;
6. sends `grant_type=client_credentials` to the token endpoint with the attestation and a proof of
   possession, and caches the token until `expires_in` minus the refresh margin.

The workload holds no client secret and sends no `client_id`. The attester maps its evidence to a
client, which becomes the attestation's `sub`.

## Requirements on the attester and authorisation server

The [values to obtain](configuration.md#values-to-obtain-from-the-attester-administrator) say what to
ask for. With the default PingFederate profile, the servers must also provide:

| Requirement | Why |
| --- | --- |
| A discovery document at `/.well-known/client-attester` with `evidence_audience` and `attestation_endpoint` | The client finds every other endpoint from it. Without one, configure static metadata. |
| Client authentication method `attest_jwt_client_auth` at the token endpoint, for the PoP method in use | The token request carries no client secret. |
| `expires_in` in the token response, longer than the 30-second refresh margin | Without it the client cannot cache the token, and every call repeats evidence, mint and token requests. |
| A working `challenge_endpoint`, if one is advertised | The client fails by default when an advertised challenge cannot be fetched. |
| `use_dpop_nonce` with a `DPoP-Nonce` header, if the AS requires DPoP nonces | The client retries the token request once with the server's nonce in `dpop_combined` mode. |
| HTTPS on every endpoint, including those in the discovery document | The client refuses plain HTTP on non-loopback hosts before sending anything. |

## Network egress

| Destination | When | Notes |
| --- | --- | --- |
| Attester discovery, challenge and attestation endpoints | Discovery once per client; challenge and mint once per new token | HTTPS required by the one-call client. |
| Authorisation server token endpoint | Once per new token, plus at most one DPoP nonce retry | HTTPS required by the one-call client. |
| GCP or Azure instance metadata service | When auto-detection probes it, and for each token on that platform | Plain HTTP to the link-local metadata service. Probes run on every acquisition while auto-detection is in use. |
| AWS STS | Each new token with the Python AWS source | Through boto3. |
| OpenBao or Vault Transit | Signer construction and each attestation it signs | HTTPS required unless the host is loopback or the signer's insecure option is set. |
| Issuer JWKS and introspection endpoints | From resource servers | HTTPS required at validator construction unless the host is loopback or `allow_insecure` is set. |
| Protected APIs | Each API call | Through the application's HTTP client and the SDK adapter. |

SDK endpoint calls never follow redirects. A 3xx response is a failure, so configure each endpoint's
final URL. Proxy support differs by port; see [Transport](configuration/transport.md#environment-and-configuration-files).

## Kubernetes projected token example

A projected ServiceAccount token is a Kubernetes-issued identity token mounted in a pod.
Kubernetes rotates the file. The SDK reads it again when it needs new evidence. The token's
`audience` must equal the attester's `evidence_audience`.
See [Kubernetes projected volumes](https://kubernetes.io/docs/concepts/storage/projected-volumes/)
for the projection fields and rotation behaviour.

1. Configure the attester to trust your cluster's token issuer and signing keys. Ask the attester
   administrator to map `system:serviceaccount:default:payment-agent` to the required client.
   This identity applies to the `default` namespace used below.

2. Save the following as `payment-agent.yaml`. Replace the image with your built application image.
   Replace the attester URLs with your deployment's values. Your application must read
   `ATTESTER_URL` and `EVIDENCE_AUDIENCE` and pass them to the SDK. `EVIDENCE_AUDIENCE` must equal the
   projected token's `audience` and the `evidence_audience` in the attester's discovery document.

   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: payment-agent
     namespace: default
   ---
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: payment-agent
     namespace: default
   spec:
     replicas: 1
     selector:
       matchLabels:
         app: payment-agent
     template:
       metadata:
         labels:
           app: payment-agent
       spec:
         serviceAccountName: payment-agent
         automountServiceAccountToken: false
         containers:
           - name: application
             image: registry.example.com/payment-agent:1.0.0
             env:
               - name: ATTESTER_URL
                 value: "https://attester.example.com"
               - name: EVIDENCE_AUDIENCE
                 value: "https://attester.example.com/evidence"
               - name: CLIENT_ATTESTATION_TOKEN_FILE
                 value: "/var/run/secrets/tokens/attester-token"
             volumeMounts:
               - name: attester-evidence
                 mountPath: /var/run/secrets/tokens
                 readOnly: true
         volumes:
           - name: attester-evidence
             projected:
               sources:
                 - serviceAccountToken:
                     audience: "https://attester.example.com/evidence"
                     expirationSeconds: 3600
                     path: attester-token
   ```

3. Apply the manifest to the intended cluster and check the rollout.

   ```bash
   kubectl apply -f payment-agent.yaml
   kubectl rollout status deployment/payment-agent -n default
   kubectl logs deployment/payment-agent -n default
   ```

4. Verify that the application obtains a token and calls its API. A successful pod rollout checks
   container startup. It does not prove that the attester accepts the identity.

This manifest supplies identity to an existing application image. Configure the application's
ports, health probes and resource requests according to that application's deployment requirements.
Mount the projected directory as shown so Kubernetes token rotation remains visible.

## Deploy a protected resource

1. Configure the validator with the access-token issuer, its JWKS URL, your API's audience and
   required scopes. Obtain these values from the authorisation server administrator and API owner.
   See [Configuration](configuration.md#resource-server-configuration).

2. Create `ProtectedResource` with your API's externally visible resource URI. The validator's
   accepted audiences must include that URI. A resource URI with `/mcp` produces the metadata
   path `/.well-known/oauth-protected-resource/mcp`.

3. Serve metadata at the path returned by `metadata_path` / `metadataPath` / `MetadataPath`.
   Send protected requests through `authenticate` / `Authenticate`, or for opaque tokens checked by
   introspection, `authenticate_active` / `authenticateActive` / `AuthenticateActive`. On refusal, return the
   decision's status and `WWW-Authenticate` value before calling the application handler.

4. Configure the reverse proxy to preserve the `Authorization` request header and the
   `WWW-Authenticate` response header. Keep the advertised resource URI equal to the public
   audience used in issued tokens.

5. Check that a request without a token returns 401. Check that a token for a different audience
   is refused. Check that a token missing a required scope returns 403. Check that a valid
   Bearer token for this resource reaches the handler.

`ProtectedResource` provides a Bearer guard. It refuses a token whose `cnf` claim is non-null (DPoP-bound, mTLS-bound or malformed) with 401, because
it receives no sender proof. To accept sender-constrained tokens, verify the proof in the resource's
authentication layer and call `validate` directly. See the
[resource reference](configuration/resource.md).

The supplied resource-server programs demonstrate metadata and authentication.
They do not implement MCP tools or A2A methods. Their issuers are placeholders.
See [Examples](examples.md#protected-resource-examples) for local commands and expected results.

## Publish SDK packages

Publishing a package is a maintainer release operation. It does not deploy a consuming application.

1. Follow [Contributing](../CONTRIBUTING.md#releasing) to set the shared version and run release
   checks. Maintainers of the private source repository also follow its internal release guide.

2. Publish a GitHub release for an existing `vX.Y.Z` tag in `ID-Partners/client-attestation-sdk`.
   The [release workflow](../.github/workflows/release.yml) requires that tagged commit to be
   an ancestor of `main`. It checks every version copy and runs the full CI matrix.

3. Approve the package jobs in the public repository's `release` environment. The workflow
   publishes Python to PyPI, TypeScript to npm and Java to Maven Central. It pushes `go/vX.Y.Z`
   for the Go submodule.

4. Check each workflow job's result. A successful source sync alone does not publish packages.

The workflow comments describe required trusted publishers and release-environment secrets.
This repository cannot confirm their current configuration in the registries or GitHub settings.

## Runtime requirements by component

| Component | Runtime input | Connections or access | State and renewal |
| --- | --- | --- | --- |
| One-call client | Attester URL or static metadata; optional authorisation details and proof method | Discovery, challenge, mint and token endpoints | Keep one client per configuration. Token and instance key remain in process memory. |
| File evidence | Mounted token path with the required evidence audience | Read permission on the projected directory | Platform rotates the file. SDK reads it again at acquisition. |
| SPIRE evidence | Socket path and `spire-agent` executable | Socket access for the application identity | SPIRE issues a JWT-SVID on each fetch. |
| Cloud evidence | Identity available through the selected source | Runtime metadata or STS endpoint | Source requests evidence for each acquisition. Verify Experimental Azure/AWS integrations with the deployment administrator. |
| External signer | Vault address, token and Transit key name | Read key metadata and sign through Transit | Static token and pinned key version. Reconstruct the signer when changing either. |
| JWT validator | Access-token issuer, resource audience and static JWKS or URI | JWKS endpoint when remote keys are configured | In-memory cache refreshes on validation. Static keys require application replacement. |
| Introspection | Endpoint and resource-server credentials | Introspection endpoint | Every active-validation call contacts the server. Credentials come from the application. |
| Protected resource | Public resource URI, server identifiers and configured validator | Serve the calculated metadata path | Apply each decision before the handler. Proof verification belongs to the resource's authentication layer. |
| Python approval resolvers | CIBA client, deployment hooks and store | Approval site, device channel or credential verifier as configured | Default store is in memory. Replica coordination needs shared atomic storage. |

The repository cannot confirm your live endpoint URLs, trusted CA configuration or identity mapping.
Obtain those values from the attester and authorisation server administrators.
The API owner supplies its audience and required scopes.
The runtime operator supplies identity access and secret injection.

## Monitoring

Turn on [logging](logging.md) in production at `info` or above to see failures and rejected tokens, and
at `debug` while diagnosing. At `warn` you see only the failures.
Event names and attributes are the same in every port, and no credential is ever logged.

| Event | Level | What it usually means |
| --- | --- | --- |
| `http.failed` with `step` `discover`, `challenge`, `mint` or `token` | warn | The attester or authorisation server is unreachable, slow or refusing. `reason` is `timeout`, `network`, `redirect`, `too_large`, `status` or `malformed`. |
| `challenge.skipped` | warn | The challenge endpoint failed and the client was configured not to require a challenge. |
| `jwks.fetch_failed` | warn | A resource server cannot refresh the issuer's keys. Tokens signed with a new key fail as `key_not_found` until a fetch succeeds. |
| `token.validated` with a `result` other than `valid` | info | Rejected tokens. A rise in `expired` suggests clock drift; in `invalid_audience`, a client or resource configured for the wrong audience. |
| `token.refreshing` much more often than the token lifetime | debug | The token response has no usable `expires_in`, or the application creates a new client per request. |

## Upgrades and support

All four ports share one version and follow semver from 1.0.0. Security fixes land on the latest
1.x minor release; see [SECURITY.md](../SECURITY.md). Read the [CHANGELOG](../CHANGELOG.md) entry
before upgrading: a release that changes what some callers see says so at the top. The SDK implements
draft -10 of the attestation draft, exported as `DRAFT_REVISION` (`DraftRevision` in Go), and a move
to a new revision is always called out in the changelog.
