/*
 * Auto-detect the workload's platform identity — the evidence it presents to the attester.
 *
 * The workload proves *what it is* with a token its runtime already issues. Which token, and where it
 * comes from, depends on the runtime:
 *
 *   - an explicit token in an environment variable (any runtime that injects one),
 *   - a projected/mounted token file (Kubernetes, GKE),
 *   - a SPIRE Workload API socket (SPIRE / SPIFFE),
 *   - the GCP metadata server (GCE, GKE, Cloud Run, Vertex AI Agent Engine).
 *
 * {@link #autoDetect()} tries these in order and returns the first that applies, so a caller can write
 * {@code new ClientAttestation(pfHost)} and have it work without naming the source. Override by passing an
 * explicit {@link SvidSource} to {@link ClientAttestation}.
 */
package global.idpartners.clientattestation;

import java.net.URI;
import java.net.http.HttpRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.function.Function;

/** Auto-detection of the runtime's evidence source (mirrors the Python {@code evidence.py}). */
public final class Evidence {

    /** The token itself, static. */
    public static final String ENV_SVID = "CLIENT_ATTESTATION_SVID";
    /** Path to a projected token file. */
    public static final String ENV_TOKEN_FILE = "CLIENT_ATTESTATION_TOKEN_FILE";
    /** SPIRE Workload API socket (standard SPIFFE var). */
    public static final String ENV_SPIFFE_SOCKET = "SPIFFE_ENDPOINT_SOCKET";

    /** Default projected-token path used by the Kubernetes/GKE serviceAccountToken volume convention. */
    public static final String DEFAULT_TOKEN_FILE = "/var/run/secrets/tokens/attester-token";
    /** Default SPIRE agent socket path. */
    public static final String DEFAULT_SPIFFE_SOCKET = "/tmp/spire-agent/public/api.sock";

    /** GCP metadata server root, probed (with a short timeout) as the last auto-detect option. */
    static final String GCP_METADATA_URL = "http://metadata.google.internal/computeMetadata/v1/";
    static final Duration GCP_PROBE_TIMEOUT = Duration.ofMillis(300);

    private Evidence() {
    }

    /**
     * Return the first evidence source that applies to this runtime, or throw with guidance.
     *
     * <p>Order: explicit env token, projected token file, SPIRE socket, GCP metadata server.
     *
     * <p>Fails closed: if {@value #ENV_TOKEN_FILE} or {@value #ENV_SPIFFE_SOCKET} is set but points at a
     * missing path, this throws {@link EvidenceNotFoundException} naming the variable instead of falling
     * through to the next source. Unset variables keep auto-detection.
     */
    public static SvidSource autoDetect() {
        return autoDetect(System::getenv, DEFAULT_TOKEN_FILE, DEFAULT_SPIFFE_SOCKET, GCP_METADATA_URL);
    }

    /** {@link #autoDetect()} with the environment and the well-known locations injectable, for tests. */
    static SvidSource autoDetect(Function<String, String> getenv, String defaultTokenFile,
            String defaultSpiffeSocket, String gcpMetadataUrl) {
        String staticToken = getenv.apply(ENV_SVID);
        if (staticToken != null && !staticToken.isBlank()) {
            return new SvidSource.Static(staticToken.strip());
        }

        // An explicitly configured source is authoritative: if it points at nothing, fail naming the variable
        // rather than silently presenting some other identity this runtime happens to have.
        String tokenFile = getenv.apply(ENV_TOKEN_FILE);
        if (tokenFile != null && !tokenFile.isBlank()) {
            if (!Files.isRegularFile(Path.of(tokenFile.strip()))) {
                throw new EvidenceNotFoundException(ENV_TOKEN_FILE + " is set to " + tokenFile.strip()
                        + " but no such file exists");
            }
            return new SvidSource.File(tokenFile.strip());
        }

        if (Files.isRegularFile(Path.of(defaultTokenFile))) {
            return new SvidSource.File(defaultTokenFile);
        }

        String socket = getenv.apply(ENV_SPIFFE_SOCKET);
        if (socket != null && !socket.isBlank()) {
            String socketPath = socket.strip().replace("unix://", "");
            if (!Files.exists(Path.of(socketPath))) {
                throw new EvidenceNotFoundException(ENV_SPIFFE_SOCKET + " is set to " + socket.strip()
                        + " but no such socket exists");
            }
            return new SvidSource.SpireWorkloadApi(socketPath, "spire-agent");
        }
        if (Files.exists(Path.of(defaultSpiffeSocket))) {
            // The module ships a subprocess-based SpireWorkloadApi source; a native java-spiffe client can
            // be dropped in by implementing SvidSource. If the CLI is absent, fetch() surfaces the error.
            return new SvidSource.SpireWorkloadApi(defaultSpiffeSocket, "spire-agent");
        }

        if (gcpMetadataAvailable(gcpMetadataUrl, GCP_PROBE_TIMEOUT)) {
            return new SvidSource.GoogleMetadata();
        }

        throw new EvidenceNotFoundException(
                "Could not auto-detect the workload's platform identity. Set one of "
                        + ENV_SVID + " (the token), " + ENV_TOKEN_FILE + " (a token file), or "
                        + ENV_SPIFFE_SOCKET + " (SPIRE socket), or pass an SvidSource to ClientAttestation "
                        + "explicitly.");
    }

    static boolean gcpMetadataAvailable(String url, Duration timeout) {
        try {
            HttpTransport.Response r = HttpTransport.send(HttpTransport.client(timeout),
                    HttpRequest.newBuilder(URI.create(url)).header("Metadata-Flavor", "Google").GET(), timeout);
            return r.status() >= 200 && r.status() < 500;
        } catch (RuntimeException e) {
            // TransportException (unreachable, timeout, redirect, oversize) or a malformed URL: not on GCP.
            return false;
        }
    }

    /** No platform identity could be detected and none was supplied. */
    public static final class EvidenceNotFoundException extends RuntimeException {
        public EvidenceNotFoundException(String message) {
            super(message);
        }
    }
}
