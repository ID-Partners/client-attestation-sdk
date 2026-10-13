/*
 * Pluggable sources for a workload's SPIFFE JWT-SVID — the infra-identity input to attestation
 * bootstrapping (AttestationIssuanceClient).
 */
package global.idpartners.clientattestation;

import global.idpartners.clientattestation.internal.HttpTransport;
import global.idpartners.clientattestation.internal.StrictJson;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
      *
      * <p><b>Experimental</b> (see docs/api.md): a development and test source with no caller
      * authentication.
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
     * The path must be a regular file of at most 64 KiB; anything else is an
     * {@link Evidence.EvidenceNotFoundException}.
     */
    final class File implements SvidSource {
        static final int MAX_BYTES = 64 * 1024;

        private final Path path;

        public File(String path) {
            this.path = Path.of(path);
        }

        @Override
        public String fetch(String audience) throws Exception {
            // Checked before opening: opening a FIFO blocks, and a device such as /dev/zero never ends.
            if (!Files.readAttributes(this.path, BasicFileAttributes.class).isRegularFile()) {
                throw new Evidence.EvidenceNotFoundException("token file " + this.path + " is not a regular file");
            }
            byte[] data;
            try (InputStream in = Files.newInputStream(this.path)) {
                data = in.readNBytes(MAX_BYTES + 1);
            }
            if (data.length > MAX_BYTES) {
                throw new Evidence.EvidenceNotFoundException(
                        "token file " + this.path + " is larger than " + MAX_BYTES + " bytes");
            }
            return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(data)).toString().strip();
        }
    }

    /**
     * Fetches a Google-signed ID token for the runtime service account from the GCP metadata server.
     * Works on any Google runtime that exposes the metadata server (GCE, GKE, Cloud Run, Vertex AI Agent
     * Engine). The token's {@code aud} is the audience passed here; {@code sub} is the service account.
     * No google-auth dependency — a plain metadata call, never through a proxy. The answer must be HTTP 200
     * carrying the {@code Metadata-Flavor: Google} response header, as the real metadata server sends.
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
            this.http = Evidence.metadataClient(timeout);
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
            if (!Evidence.fromGoogleMetadata(r)) {
                throw new IllegalStateException("GCP metadata identity answered without Metadata-Flavor: Google");
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
     * it is killed and {@link IllegalStateException} is thrown. Its stdout is read on a separate thread so a
     * chatty or hung agent cannot block the wait. Its stderr is discarded, never read as output or held in
     * memory. {@code fetch} returns the first JWT-SVID on stdout and throws
     * {@link Evidence.EvidenceNotFoundException} if there is none, or {@link IllegalStateException} if the
     * agent exits with a non-zero status.
     *
     * <p>The agent's exit decides the outcome, as in the other ports. While the agent is running, more than
     * 1 MiB of stdout kills it and {@link IllegalStateException} is thrown; that includes what it wrote just
     * before exiting, which is still in the pipe when its exit is seen. Once it has exited, stdout is read
     * for at most 250 ms more and at most 1 MiB in all (a helper the agent started can inherit the pipe and
     * keep writing to it or hold it open), then the pipe is closed. On exit status 0 what was read is parsed;
     * on any other status the fetch fails. So output a helper writes after the agent has exited never turns a
     * success into a failure, and never keeps {@code fetch} waiting longer than that. If reading stopped at
     * the 1 MiB or at the end of the 250 ms, the last line may be cut off, so a token is only taken from a
     * line that ends in a newline.
     *
     * <p>In Java the reader never blocks on the pipe: it reads only what is available, so it cannot be left
     * stuck in a read after the agent has exited. On Linux and macOS the JDK itself closes the pipe when the
     * agent exits, keeping what was in it at that moment, so a helper's later output is not read at all, and
     * once that has been read the output is complete.
      *
      * <p><b>Experimental</b> (see docs/api.md): it shells out to the spire-agent CLI, and its constructor
      * will change when it moves to the Workload API socket.
     */
    final class SpireWorkloadApi implements SvidSource {
        static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
        /**
         * The most stdout read from {@code spire-agent} (as in the other ports). More while the agent is running
         * fails the fetch; once it has exited, reading stops there.
         */
        static final int MAX_OUTPUT_BYTES = 1 << 20;
        /**
         * How long stdout is still read after {@code spire-agent} has exited (as in the other ports). A helper the
         * agent started can inherit the pipe and hold it open; after this the pipe is closed.
         */
        static final Duration STDOUT_GRACE = Duration.ofMillis(250);

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
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start();
            p.getOutputStream().close();
            StdoutReader stdout = new StdoutReader(p.getInputStream(), p::isAlive, p::destroyForcibly);
            Thread drain = new Thread(stdout, "spire-agent-output");
            drain.setDaemon(true);
            drain.start();
            try {
                if (!p.waitFor(this.timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                    p.destroyForcibly();
                    stdout.stop();
                    throw new IllegalStateException(
                            "spire-agent did not exit within " + this.timeout.toMillis() + "ms; killed");
                }
                // The agent has exited. What it wrote is in the pipe; give the reader the grace period to finish,
                // then take what it has and close the pipe, whether or not a helper still holds it open.
                drain.join(STDOUT_GRACE.toMillis());
            } catch (InterruptedException e) {
                p.destroyForcibly();
                stdout.stop();
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted waiting for spire-agent", e);
            }
            StdoutReader.Output output = stdout.stop();
            if (output.over()) {
                throw new IllegalStateException(
                        "spire-agent fetch failed: output is larger than " + MAX_OUTPUT_BYTES + " bytes");
            }
            if (p.exitValue() != 0) {
                throw new IllegalStateException("spire-agent fetch failed: exit status " + p.exitValue());
            }
            IOException readError = stdout.error();
            if (readError != null) {
                throw new IllegalStateException("could not read spire-agent output: " + readError, readError);
            }
            String out = new String(output.bytes(), StandardCharsets.UTF_8);
            String svid = parseJwtOutput(completeLines(out, output.complete()));
            if (svid != null) {
                return svid;
            }
            // The output may hold a token or bundle that failed to parse, so the error gives only its size.
            long lines = out.isEmpty() ? 0 : out.chars().filter(c -> c == '\n').count() + (out.endsWith("\n") ? 0 : 1);
            throw new Evidence.EvidenceNotFoundException("could not parse a JWT-SVID from spire-agent output ("
                    + out.getBytes(StandardCharsets.UTF_8).length + " bytes, " + lines + " lines; not shown)");
        }

        /**
         * {@code out}, or, if reading stopped before the end of the output (at the cap or the end of the grace
         * period), {@code out} up to its last newline: the line after that may have been cut off.
         */
        static String completeLines(String out, boolean complete) {
            return complete ? out : out.substring(0, out.lastIndexOf('\n') + 1);
        }

        /**
         * Reads the agent's stdout on its own thread, keeping at most {@link #MAX_OUTPUT_BYTES}. It never blocks
         * in a read: it reads only what {@link InputStream#available()} reports and otherwise sleeps briefly,
         * so it always notices {@link #stop} (closing a pipe does not wake a read blocked on it on every
         * platform) and never holds the stream's lock while the JDK takes what is left in the pipe as the agent
         * exits. Once the agent has exited and nothing more is available, everything it wrote has been read and
         * the output is complete. Output counts as the running agent's if it was read before the reader first
         * saw the agent's exit, or was available at that moment (the agent wrote it before exiting, though it
         * may be read after); past the cap, that kills the agent and nothing is kept. Only output that arrives
         * after that moment is post-exit output: reading stops at the cap, keeping exactly the first
         * {@link #MAX_OUTPUT_BYTES}, and the exit status decides.
         * {@link #stop} hands back what has been read and closes the pipe.
         */
        static final class StdoutReader implements Runnable {
            /** How long the reader sleeps when nothing is available. */
            private static final long POLL_MILLIS = 5;

            /** What was read; {@code over} if the cap was passed while the agent was running. */
            record Output(byte[] bytes, boolean over, boolean complete) {
            }

            private final InputStream in;
            private final BooleanSupplier alive;
            private final Runnable kill;
            private final ByteArrayOutputStream kept = new ByteArrayOutputStream();
            private boolean over;
            private boolean complete;
            private boolean stopped;
            private IOException error;

            StdoutReader(InputStream in, BooleanSupplier alive, Runnable kill) {
                this.in = in;
                this.alive = alive;
                this.kill = kill;
            }

            @Override
            public void run() {
                byte[] chunk = new byte[65536];
                boolean exitSeen = false;
                try {
                    while (!isStopped()) {
                        // Whether the agent had exited is read before what is available: if it had, everything
                        // it wrote is already in the pipe, so nothing available then means nothing more to read.
                        boolean exited = !this.alive.getAsBoolean();
                        int available = this.in.available();
                        if (exited && !exitSeen) {
                            // The first time the exit is seen, what is available then was written before it:
                            // with what was read already, past the cap is the running agent's overflow, read
                            // either side of its exit. Only what arrives after this is post-exit output.
                            exitSeen = true;
                            if (!keepAtExit(available)) {
                                return;
                            }
                        }
                        if (available > 0) {
                            int n = this.in.read(chunk, 0, Math.min(available, chunk.length));
                            if (n < 0) {
                                finished();
                                return;
                            }
                            if (!keep(chunk, n, !exitSeen)) {
                                return;
                            }
                        } else if (exited) {
                            finished();
                            return;
                        } else {
                            Thread.sleep(POLL_MILLIS);
                        }
                    }
                } catch (IOException e) {
                    synchronized (this) {
                        if (!this.stopped) {   // a read cut short by stop() is not an error
                            this.error = e;
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            private synchronized boolean isStopped() {
                return this.stopped;
            }

            private synchronized void finished() {
                this.complete = !this.stopped;
            }

            /**
             * At the first sight of the agent's exit, with {@code available} bytes readable then: false (and
             * {@code over}) if those and what was read already pass the cap.
             */
            private synchronized boolean keepAtExit(int available) {
                if (this.stopped) {
                    return false;
                }
                if ((long) this.kept.size() + available > MAX_OUTPUT_BYTES) {
                    overflow();
                    return false;
                }
                return true;
            }

            /**
             * Adds a chunk, read while the agent was {@code running} (before its exit was first seen) or after;
             * false once reading should stop.
             */
            private synchronized boolean keep(byte[] chunk, int n, boolean running) {
                if (this.stopped) {
                    return false;
                }
                int room = MAX_OUTPUT_BYTES - this.kept.size();
                if (n > room) {
                    if (running) {
                        overflow();   // too much output while running: stop the agent rather than read on
                    } else {
                        this.kept.write(chunk, 0, room);   // output after the agent's exit: stop at the cap
                    }
                    return false;
                }
                this.kept.write(chunk, 0, n);
                return true;
            }

            private void overflow() {
                this.over = true;
                this.kept.reset();
                this.kill.run();
            }

            /** Stops reading and closes the pipe (a helper may hold it open), returning what was read. */
            Output stop() {
                Output result;
                synchronized (this) {
                    this.stopped = true;
                    result = new Output(this.over ? new byte[0] : this.kept.toByteArray(), this.over, this.complete);
                }
                try {
                    this.in.close();
                } catch (IOException ignored) {
                    // closing is best effort: what was read is already taken
                }
                return result;
            }

            synchronized IOException error() {
                return this.error;
            }
        }

        private static final Pattern SECTION = Pattern.compile("(token|hint|bundle)\\(.*?\\):(.*)", Pattern.DOTALL);
        private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");

        /**
         * The first JWT-SVID in the output of {@code spire-agent api fetch jwt}, or {@code null}. SPIRE prints
         * each SVID as {@code token(<spiffe id>):} with the JWT on the next, tab-indented line, then
         * {@code hint(<spiffe id>):} and {@code bundle(<trust domain>):} sections laid out the same way. The
         * single-line form {@code token(<spiffe id>): <jwt>} and a bare JWT line are accepted too. Only a
         * syntactically valid compact JWS is returned; the values of hint and bundle sections are skipped. A
         * label with no value takes the next line as its value only if that line is not itself a label. Only
         * ASCII space, tab and CR around a line or value are ignored.
         */
        static String parseJwtOutput(String out) {
            String[] lines = out.split("\n", -1);
            for (int i = 0; i < lines.length; i++) {
                String line = trimSpace(lines[i]);
                Matcher section = SECTION.matcher(line);
                if (!section.matches()) {
                    if (isCompactJws(line)) {                          // a bare compact JWT line
                        return line;
                    }
                    continue;
                }
                String value = trimSpace(section.group(2));
                if (value.isEmpty() && i + 1 < lines.length) {          // the value is on the next line,
                    String following = trimSpace(lines[i + 1]);         // unless that is another label
                    if (!SECTION.matcher(following).matches()) {
                        value = following;
                        i++;
                    }
                }
                if (section.group(1).equals("token") && isCompactJws(value)) {
                    return value;
                }
            }
            return null;
        }

        /**
         * {@code s} without the ASCII spaces, tabs and CRs around it, and nothing else: not a BOM, an NBSP or
         * other Unicode space, so every port reads the same output the same way.
         */
        private static String trimSpace(String s) {
            int start = 0;
            int end = s.length();
            while (start < end && isSpace(s.charAt(start))) {
                start++;
            }
            while (end > start && isSpace(s.charAt(end - 1))) {
                end--;
            }
            return s.substring(start, end);
        }

        private static boolean isSpace(char c) {
            return c == ' ' || c == '\t' || c == '\r';
        }

        /**
         * Three non-empty base64url segments whose first is the canonical encoding of a strict JSON object (the
         * token validator's reader) with a non-empty string {@code alg}. It verifies nothing; it tells a JWT from
         * a version string or log line.
         */
        static boolean isCompactJws(String s) {
            String[] parts = s.split("\\.", -1);
            if (parts.length != 3) {
                return false;
            }
            for (String part : parts) {
                if (!BASE64URL.matcher(part).matches()) {
                    return false;
                }
            }
            try {
                Map<String, Object> header = StrictJson.parseObject(StrictJson.decodeSegment(parts[0]), "header");
                return header.get("alg") instanceof String alg && !alg.isEmpty();
            } catch (StrictJson.Malformed e) {
                return false;
            }
        }
    }
}
