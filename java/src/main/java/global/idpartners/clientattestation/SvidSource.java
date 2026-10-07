/*
 * Pluggable sources for a workload's SPIFFE JWT-SVID — the infra-identity input to attestation
 * bootstrapping (AttestationIssuanceClient).
 */
package global.idpartners.clientattestation;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Produces a workload's compact JWT-SVID for an audience. The default {@link SpireWorkloadApi} source
 * fetches it from a real SPIRE agent's Workload API; {@link Static} and {@link Http} cover tests and dev;
 * {@link File} reads a projected token file (Kubernetes/GKE) and {@link GoogleMetadata} calls the GCP
 * metadata server. {@link Evidence#autoDetect()} picks one of these from the runtime automatically.
 */
public interface SvidSource {

    String fetch(String audience) throws Exception;

    /** A fixed, pre-fetched SVID — for tests, or when the caller already holds one. */
    final class Static implements SvidSource {
        private final String svid;

        public Static(String svid) {
            this.svid = svid;
        }

        @Override
        public String fetch(String audience) {
            return this.svid;
        }
    }

    /**
     * GET a URL returning {@code {"svid":"<jwt>"}} — e.g. the demo harness {@code /dev/svid} endpoint.
     *
     * <p>For development and testing only. It trusts whatever the URL returns and the endpoint has no caller
     * authentication, so anyone who can reach it can obtain the workload's SVID. In production use a SPIRE,
     * file or cloud source.
     */
    final class Http implements SvidSource {
        static final Duration TIMEOUT = Duration.ofSeconds(20);

        private final String url;
        private final HttpClient http = HttpTransport.client(TIMEOUT);

        public Http(String url) {
            this.url = url;
        }

        @Override
        public String fetch(String audience) throws Exception {
            Object svid;
            try {
                HttpTransport.Response r = HttpTransport.send(this.http, HttpRequest.newBuilder(URI.create(this.url)).GET(), TIMEOUT);
                if (r.status() != 200) {
                    throw new IllegalStateException("GET " + this.url + " -> " + r.status());
                }
                svid = HttpTransport.jsonOk(r).get("svid");
            } catch (TransportException e) {
                throw new IllegalStateException("GET " + this.url + " failed: " + e.getMessage(), e);
            }
            if (svid == null) {
                throw new IllegalStateException("no svid in response from " + this.url);
            }
            return String.valueOf(svid);
        }
    }

    /**
     * Reads the evidence token from a file on every fetch. Kubernetes and GKE mount a short-lived,
     * auto-rotated service-account token into the pod as a projected {@code serviceAccountToken} volume;
     * reading it fresh each call picks up the rotation. The file's audience must already be the attester's
     * evidence audience — set it when the volume is declared, so the {@code audience} argument is ignored.
     */
    final class File implements SvidSource {
        private final Path path;

        public File(String path) {
            this.path = Path.of(path);
        }

        @Override
        public String fetch(String audience) throws Exception {
            return Files.readString(this.path, StandardCharsets.UTF_8).strip();
        }
    }

    /**
     * Fetches a Google-signed ID token for the runtime service account from the GCP metadata server.
     * Works on any Google runtime that exposes the metadata server (GCE, GKE, Cloud Run, Vertex AI Agent
     * Engine). The token's {@code aud} is the audience passed here; {@code sub} is the service account.
     * No google-auth dependency — a plain metadata call.
     */
    final class GoogleMetadata implements SvidSource {
        static final String IDENTITY_URL =
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity";

        private final Duration timeout;
        private final String identityUrl;
        private final HttpClient http;

        public GoogleMetadata() {
            this(Duration.ofSeconds(5), IDENTITY_URL);
        }

        GoogleMetadata(Duration timeout, String identityUrl) {
            this.timeout = timeout;
            this.identityUrl = identityUrl;
            this.http = HttpTransport.client(timeout);
        }

        @Override
        public String fetch(String audience) throws Exception {
            String url = this.identityUrl + "?audience="
                    + URLEncoder.encode(audience, StandardCharsets.UTF_8) + "&format=full";
            HttpTransport.Response r;
            try {
                r = HttpTransport.send(this.http, HttpRequest.newBuilder(URI.create(url))
                        .header("Metadata-Flavor", "Google").GET(), this.timeout);
            } catch (TransportException e) {
                throw new IllegalStateException("GCP metadata identity failed: " + e.getMessage(), e);
            }
            if (r.status() != 200) {
                throw new IllegalStateException("GCP metadata identity -> " + r.status());
            }
            return r.body().strip();
        }
    }

    /**
     * The default source: fetch a JWT-SVID from a real SPIRE agent's Workload API via the
     * {@code spire-agent} CLI. Swap for a native java-spiffe client by implementing {@link SvidSource}
     * if you prefer no subprocess.
     *
     * <p>The subprocess is bounded: if {@code spire-agent} has not exited within the timeout (default 30s)
     * it is killed and {@link IllegalStateException} is thrown. Its output (stderr merged into stdout) is
     * drained on a separate thread, capped at 1 MiB, so a chatty or hung agent cannot block the wait.
     */
    final class SpireWorkloadApi implements SvidSource {
        static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

        private final String socketPath;
        private final String spireAgentBin;
        private final Duration timeout;

        public SpireWorkloadApi() {
            this("/tmp/spire-agent/public/api.sock", "spire-agent");
        }

        public SpireWorkloadApi(String socketPath, String spireAgentBin) {
            this(socketPath, spireAgentBin, DEFAULT_TIMEOUT);
        }

        SpireWorkloadApi(String socketPath, String spireAgentBin, Duration timeout) {
            this.socketPath = socketPath;
            this.spireAgentBin = spireAgentBin;
            this.timeout = timeout;
        }

        @Override
        public String fetch(String audience) throws Exception {
            Process p = new ProcessBuilder(this.spireAgentBin, "api", "fetch", "jwt",
                    "-audience", audience, "-socketPath", this.socketPath)
                    .redirectErrorStream(true).start();
            p.getOutputStream().close();
            CompletableFuture<String> output = new CompletableFuture<>();
            Thread drain = new Thread(() -> {
                try {
                    output.complete(readCapped(p.getInputStream(), HttpTransport.DEFAULT_MAX_BYTES));
                } catch (Throwable t) {
                    output.completeExceptionally(t);
                }
            }, "spire-agent-output");
            drain.setDaemon(true);
            drain.start();
            String out;
            try {
                if (!p.waitFor(this.timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                    p.destroyForcibly();
                    throw new IllegalStateException(
                            "spire-agent did not exit within " + this.timeout.toMillis() + "ms; killed");
                }
                // The process has exited; its output pipe closes with it (bounded in case a child holds it).
                out = output.get(this.timeout.toMillis(), TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                p.destroyForcibly();
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted waiting for spire-agent", e);
            } catch (TimeoutException e) {
                throw new IllegalStateException("spire-agent output was not closed after exit", e);
            } catch (ExecutionException e) {
                throw new IllegalStateException("could not read spire-agent output: " + e.getCause(), e.getCause());
            }
            for (String line : out.split("\n")) {
                line = line.trim();
                if (line.startsWith("token(")) {                 // "token(spiffe://…): eyJ…"
                    int i = line.indexOf("):");
                    if (i >= 0) {
                        return line.substring(i + 2).trim();
                    }
                }
                if (line.chars().filter(c -> c == '.').count() == 2) {   // a bare compact JWT line
                    return line;
                }
            }
            throw new IllegalStateException("could not parse SVID from spire-agent output:\n" + out);
        }

        /** Read {@code in} to EOF, keeping at most {@code max} bytes (the rest is drained and dropped). */
        private static String readCapped(InputStream in, long max) throws IOException {
            ByteArrayOutputStream kept = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                int room = (int) Math.max(0, Math.min(n, max - kept.size()));
                kept.write(buf, 0, room);
            }
            return kept.toString(StandardCharsets.UTF_8);
        }
    }
}
