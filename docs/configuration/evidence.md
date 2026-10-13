# Evidence sources

[Configuration index](../configuration.md)

An evidence source supplies the workload identity token sent to the attester.
`SvidSource.fetch(audience)` returns that token. Go names the method `Fetch`.
SVID means SPIFFE Verifiable Identity Document.
The same source interface also accepts platform identity tokens.
The attester must trust the token issuer and map the identity to a client.

## Automatic selection

The SDK uses the first applicable source in this order.
Passing `evidence` explicitly bypasses this selection.

| Order | Input | Result |
| --- | --- | --- |
| 1 | `CLIENT_ATTESTATION_SVID` | Fixed token. It is not renewed. |
| 2 | `CLIENT_ATTESTATION_TOKEN_FILE` | File read on each fetch. A missing configured file is an error. |
| 3 | `/var/run/secrets/tokens/attester-token` exists | File read on each fetch. A path that is not a regular file (a FIFO, a device) or is larger than 64 KiB is refused with the evidence-not-found error. |
| 4 | `SPIFFE_ENDPOINT_SOCKET` | SPIRE CLI source. A missing configured path is an error. The value can start with `unix://`. |
| 5 | `/tmp/spire-agent/public/api.sock` exists | SPIRE CLI source. |
| 6 | GCP metadata probe succeeds | GCP metadata identity source. The probe timeout is 300 milliseconds. The probe and the source require HTTP 200 and the `Metadata-Flavor: Google` response header, so another host answering `metadata.google.internal` is not used. |
| 7 | Azure IMDS probe succeeds - Python only | Azure source. The probe timeout is 300 milliseconds and it requires HTTP 200 with the instance-metadata JSON. `AZURE_CLIENT_ID` selects a user-assigned identity. `CLIENT_ATTESTATION_AZURE_RESOURCE` names the only Entra resource it may request; without it, fetching fails. |
| 8 | AWS credential environment signals exist - Python only | AWS source. `AWS_REGION` is passed as its region. EC2 instance profiles are not detected. |

Python's AWS signals are `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (ECS),
`AWS_CONTAINER_CREDENTIALS_FULL_URI` (EKS Pod Identity, among others: ECS Anywhere, Greengrass, SnapStart
Lambda and aws-vault's `--server` mode set it too), or both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
These select the source. Boto3 resolves the credentials for the later STS call.
The SDK does not read `AWS_WEB_IDENTITY_TOKEN_FILE` as a static SVID through this branch.
EC2 instance profiles are not auto-detected: that would add an IMDS probe to every host that isn't on AWS.
On EC2, pass `evidence=AwsWebIdentitySvidSource()` explicitly; boto3's default credential chain then
finds the instance-profile credentials.

If no source is found, acquisition raises `EvidenceNotFound` or returns that error in Go.
A configured missing file or socket stops selection.
The SDK does not substitute a later identity for that configuration error.

## Source configuration by port

| Source | Python | TypeScript | Go | Java |
| --- | --- | --- | --- | --- |
| Fixed token | `StaticSvidSource(svid)` | `new StaticSvidSource(svid)` | `StaticSvidSource{SVID: token}` | `new SvidSource.Static(token)` |
| Token file | `FileTokenSvidSource(path)` | `new FileTokenSvidSource(path)` | `FileTokenSvidSource{Path: path}` | `new SvidSource.File(path)` |
| GCP metadata | `GoogleMetadataSvidSource(timeout=5.0)` | `new GoogleMetadataSvidSource(timeoutMs=5000, identityUrl=...)` | `GoogleMetadataSvidSource{Timeout: duration, Client: client}` | `new SvidSource.GoogleMetadata()` |
| SPIRE CLI | `SpireWorkloadApiSvidSource(socket_path=..., spire_agent="spire-agent")` | `new SpireWorkloadApiSvidSource(socketPath, spireAgentBin)` | `SpireWorkloadAPISvidSource{SocketPath: path, SpireAgentBin: binary}` | `new SvidSource.SpireWorkloadApi(socketPath, spireAgentBin)` or the no-argument constructor |
| HTTP demo endpoint | `HttpSvidSource(url)` | `new HttpSvidSource(url)` | `HTTPSvidSource{URL: url, Client: client}` | `new SvidSource.Http(url)` |

The file and fixed-token sources ignore the requested audience.
Their token must already contain the required evidence audience.
A file is read and whitespace is trimmed on every fetch.
The SDK does not create, rotate or refresh that file.

The GCP source requests `audience=<audience>&format=full` with `Metadata-Flavor: Google`.
Its fixed endpoint is
`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity`.
The source's timeout defaults to 5 seconds.
Go treats a zero or negative `Timeout` as that default and accepts an optional HTTP client.
Java has no supported timeout or endpoint setter for this source.
TypeScript's second constructor argument overrides the identity URL for tests.

The SPIRE source defaults to `/tmp/spire-agent/public/api.sock` and executable `spire-agent`.
It runs `spire-agent api fetch jwt -audience <audience> -socketPath <path>`.
Its subprocess deadline is 30 seconds in every port; a `spire-agent` still running then is killed.
While `spire-agent` is running, more than 1 MiB of stdout kills it and fails the fetch; that includes what it wrote just before exiting, which is still in the pipe when its exit is seen.
Once it has exited, its stdout is read for at most 250 ms more and at most 1 MiB in all, then closed, so a helper that holds stdout open or keeps writing to it cannot fail or delay the fetch; on exit status 0 what was read is parsed, and any other status fails.
If reading stopped at the 1 MiB or the 250 ms, the last line may be cut off, so a token is only taken from a line that ends in a newline.
The socket must be accessible to the process and the executable must be on `PATH`, unless its path is supplied.
Changing the client HTTP timeout does not change this deadline.
This CLI source is Experimental.

The HTTP source GETs its URL and expects `{"svid": "<JWT>"}`.
Its default timeout is 20 seconds.
Go accepts a custom client, with the [custom-client rules](client.md#controls-specific-to-a-port).
This source is Experimental and has no caller authentication.
Use it for the supplied local demonstration endpoints.

## Python-only cloud sources

| Source | Argument | Default | Behaviour |
| --- | --- | --- | --- |
| `AzureImdsSvidSource` | `timeout` | `5.0` seconds | Timeout for the IMDS HTTP request. |
| `AzureImdsSvidSource` | `client_id` | `None` | Optional user-assigned managed identity selector. Auto-detection supplies `AZURE_CLIENT_ID`. |
| `AzureImdsSvidSource` | `resource` (keyword) | `None` | Required. The only Entra resource the source requests, for example `api://attester`. The attester's `evidence_audience` must equal it. Auto-detection supplies `CLIENT_ATTESTATION_AZURE_RESOURCE`. |
| `AwsWebIdentitySvidSource` | `region` | `None` | Passed to `boto3.client("sts", region_name=region)`. With `None`, boto3 resolves the region itself. Auto-detection supplies `AWS_REGION`. |

Azure uses `http://169.254.169.254/metadata/identity/oauth2/token`.
It sends `api-version=2018-02-01`, `resource=<audience>` and `Metadata: true`.
It calls IMDS only when the requested audience equals the configured `resource`. Without `resource`, or
for any other audience, `fetch` raises `ClientAttestationError` and IMDS is not called. IMDS issues a
token for any resource it is asked for, so this stops an attester from obtaining a token for another
Azure resource.
It extracts `access_token` from the JSON response.
AWS requires the `aws` package extra. Without boto3, `fetch` raises `EvidenceNotFound`.
The source uses boto3's default credential chain, so constructed explicitly it also works with an EC2
instance profile, which auto-detection does not pick up.
The implementation calls `get_web_identity_token(Audience=[audience], SigningAlgorithm="RS256")`.
It extracts `WebIdentityToken` from the response.
Both integrations are Experimental and have not been verified against a live attester.
Check the selected runtime's identity endpoint and the installed Boto3 API with the cloud administrator.
The SDK exposes no separate AWS HTTP timeout setting.

## Python in-process SPIFFE demonstration

`SpiffeAgent(trust_domain, signing_key, entries=None)` creates the in-process demonstration agent.
`entries` supplies registration entries.
`register(selectors, spiffe_id, attributes=None)` adds a workload registration.
`SpiffeAgentSvidSource(agent, selectors)` fetches JWT-SVIDs for that registration.
`fetch_jwt_svid(selectors, audience, ttl=300)` sets a lifetime in seconds.
`trust_bundle()` returns the verifying keys.
`verify_jwt_svid(token, trust_bundle, audience, trust_domain=None)` checks the issued token.
A supplied `trust_domain` adds a trust-domain check.
These demonstration helpers are Experimental.
They do not replace the SPIRE Workload API.

## Runtime and extension rules

TypeScript file and SPIRE sources load Node APIs.
Edge runtimes must pass a source that works in their runtime.
A custom source must return renewable evidence for the supplied audience or fail the fetch.
Do not return an expired fixed token after the provider fails.
A custom source owns its transport timeout and credential handling.

TypeScript contains internal `AutoDetectOptions` for tests.
`defaultTokenFile`, `defaultSpiffeSocket`, `gcpMetadataBase` and `gcpProbeTimeoutMs`
replace its default paths, metadata origin and probe timeout.
They are excluded from the supported package API.
Configure a supported explicit source in application code.

## Rotating file example

Run from the repository root after installing the Python dependencies.
This offline example confirms that the source reads a replacement token.
The strings stand in for tokens - it makes no attester request.

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from client_attestation_sdk import FileTokenSvidSource

with TemporaryDirectory() as directory:
    path = Path(directory) / "evidence.jwt"
    path.write_text("first-token\n", encoding="utf-8")
    source = FileTokenSvidSource(str(path))
    assert source.fetch("https://attester.example/evidence") == "first-token"
    path.write_text("second-token\n", encoding="utf-8")
    assert source.fetch("https://attester.example/evidence") == "second-token"
print("file evidence rotation passed")
```

See [Deployment](../deployment.md#kubernetes-projected-token-example) for the mounted file configuration.

Source: [Python cloud sources](../../python/src/client_attestation_sdk/evidence.py),
[Python SPIFFE helpers](../../python/src/client_attestation_sdk/spiffe.py),
[TypeScript](../../typescript/src/evidence.ts), [Go](../../go/evidence.go),
[Go CLI and HTTP sources](../../go/svidsource.go),
[Java](../../java/src/main/java/global/idpartners/clientattestation/SvidSource.java).
