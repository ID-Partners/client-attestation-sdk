package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;

/** The HTTP and subprocess {@link SvidSource}s against loopback servers and stand-in spire-agent scripts. */
class SvidSourceTest {

    @TempDir
    Path dir;

    private StubHttpServer server;

    @BeforeEach
    void start() throws Exception {
        this.server = new StubHttpServer();
    }

    @AfterEach
    void stop() {
        this.server.close();
    }

    // ── Http ────────────────────────────────────────────────────────────────────────────────────────

    @Test
    void httpSourceReturnsTheSvidField() throws Exception {
        this.server.respond("/dev/svid", 200, "{\"svid\":\"a.b.c\"}");
        assertEquals("a.b.c", new SvidSource.Http(this.server.url("/dev/svid")).fetch("aud"));
    }

    @Test
    void httpSourceRejectsNon200MissingSvidMalformedJsonAndRedirects() {
        this.server.respond("/err", 500, "{}");
        this.server.respond("/empty", 200, "{}");
        this.server.respond("/garbage", 200, "nope");
        this.server.respond("/target", 200, "{\"svid\":\"stolen\"}");
        this.server.redirect("/hop", this.server.url("/target"));

        assertTrue(assertThrows(IllegalStateException.class,
                () -> new SvidSource.Http(this.server.url("/err")).fetch("a")).getMessage().contains("500"));
        assertTrue(assertThrows(IllegalStateException.class,
                () -> new SvidSource.Http(this.server.url("/empty")).fetch("a")).getMessage().contains("no svid"));
        assertInstanceOf(TransportException.class, assertThrows(IllegalStateException.class,
                () -> new SvidSource.Http(this.server.url("/garbage")).fetch("a")).getCause());
        IllegalStateException redirect = assertThrows(IllegalStateException.class,
                () -> new SvidSource.Http(this.server.url("/hop")).fetch("a"));
        assertEquals(302, ((TransportException) redirect.getCause()).status());
        assertEquals(0, this.server.hits("/target"));
    }

    // ── GoogleMetadata ──────────────────────────────────────────────────────────────────────────────

    @Test
    void googleMetadataSendsAudienceAndFlavorHeaderAndStripsTheToken() throws Exception {
        this.server.route("/identity", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            exchange.getResponseHeaders().set("Metadata-Flavor", "Google");
            StubHttpServer.send(exchange, 200, query.contains("audience=https%3A%2F%2Fattester.example")
                    && query.contains("format=full") ? "id.token.sig\n" : "wrong");
        });
        SvidSource.GoogleMetadata source =
                new SvidSource.GoogleMetadata(Duration.ofSeconds(2), this.server.url("/identity"));
        assertEquals("id.token.sig", source.fetch("https://attester.example"));
        assertEquals("Google", this.server.lastHeaders.get("/identity").getFirst("Metadata-Flavor"));
    }

    @Test
    void googleMetadataFailuresAreIllegalState() {
        this.server.respond("/forbidden", 403, "no");
        this.server.slow("/slow", 3000);
        assertTrue(assertThrows(IllegalStateException.class,
                () -> new SvidSource.GoogleMetadata(Duration.ofSeconds(2), this.server.url("/forbidden")).fetch("a"))
                .getMessage().contains("403"));
        IllegalStateException timeout = assertThrows(IllegalStateException.class,
                () -> new SvidSource.GoogleMetadata(Duration.ofMillis(200), this.server.url("/slow")).fetch("a"));
        assertTrue(timeout.getMessage().contains("timed out"), timeout.getMessage());
    }

    @Test
    void googleMetadataNeedsTheFlavorHeader() {
        this.server.respond("/plain", 200, "id.token.sig");
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new SvidSource.GoogleMetadata(Duration.ofSeconds(2), this.server.url("/plain")).fetch("a"));
        assertTrue(e.getMessage().contains("Metadata-Flavor"), e.getMessage());
    }

    // ── File / Static ───────────────────────────────────────────────────────────────────────────────

    @Test
    void fileAndStaticSources() throws Exception {
        Path token = Files.writeString(this.dir.resolve("token"), "  file.jwt.sig \n");
        assertEquals("file.jwt.sig", new SvidSource.File(token.toString()).fetch("ignored"));
        assertEquals("s.v.id", new SvidSource.Static("s.v.id").fetch("ignored"));
    }

    @Test
    void fileSourceRefusesAFileOver64KiB() throws Exception {
        Path big = Files.write(this.dir.resolve("big"), new byte[SvidSource.File.MAX_BYTES + 1]);
        Evidence.EvidenceNotFoundException e = assertThrows(Evidence.EvidenceNotFoundException.class,
                () -> new SvidSource.File(big.toString()).fetch("a"));
        assertTrue(e.getMessage().contains("larger than"), e.getMessage());
        Path max = Files.writeString(this.dir.resolve("max"), "b".repeat(SvidSource.File.MAX_BYTES));
        assertEquals(SvidSource.File.MAX_BYTES, new SvidSource.File(max.toString()).fetch("a").length());
    }

    @Test
    void fileSourceRefusesAFifoAndDevZeroWithoutBlocking() throws Exception {
        assumeTrue(Files.exists(Path.of("/dev/zero")), "needs POSIX");
        Path fifo = this.dir.resolve("fifo");
        assumeTrue(new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor() == 0, "needs mkfifo");
        for (String path : new String[] {fifo.toString(), "/dev/zero"}) {
            Evidence.EvidenceNotFoundException e = org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(
                    Duration.ofSeconds(5), () -> assertThrows(Evidence.EvidenceNotFoundException.class,
                            () -> new SvidSource.File(path).fetch("a")));
            assertTrue(e.getMessage().contains("not a regular file"), e.getMessage());
        }
    }

    @Test
    void fileSourceMissingFileIsStillAnIoError() {
        assertThrows(java.nio.file.NoSuchFileException.class,
                () -> new SvidSource.File(this.dir.resolve("nope").toString()).fetch("a"));
    }

    // ── SpireWorkloadApi ────────────────────────────────────────────────────────────────────────────

    private String script(String name, String body) throws Exception {
        assumeTrue(Files.isExecutable(Path.of("/bin/sh")), "needs /bin/sh");
        Path p = this.dir.resolve(name);
        Files.writeString(p, "#!/bin/sh\n" + body + "\n");
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwx------"));
        return p.toString();
    }

    // Two JWT-SVIDs shaped like real ones: an ES256 header with a kid, a SPIFFE sub, a 64-byte signature.
    private static final String SVID = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0"
            + ".eyJhdWQiOlsiaHR0cHM6Ly9hdWQiXSwiZXhwIjo0MTAyNDQ0ODAwLCJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy93bCJ9"
            + ".AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw";
    private static final String OTHER_SVID = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0"
            + ".eyJhdWQiOlsiaHR0cHM6Ly9hdWQiXSwiZXhwIjo0MTAyNDQ0ODAwLCJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy9vdGhlciJ9"
            + ".QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-fw";
    private static final String BUNDLE = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k1\",\"crv\":\"P-256\","
            + "\"x\":\"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis\",\"y\":\"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE\"}]}";
    // What `spire-agent api fetch jwt` prints for two SVIDs, one with a hint, and a bundle: the layout of
    // printPrettyResult in SPIRE's cmd/spire-agent/cli/api/fetch_jwt.go (v1.5 to v1.15),
    // "token(%s):\n\t%s\n", "hint(%s):\n\t%s\n" and "bundle(%s):\n\t%s\n".
    private static final String OUTPUT = "token(spiffe://example.org/wl):\n\t" + SVID + "\n"
            + "hint(spiffe://example.org/wl):\n\texternal\n"
            + "token(spiffe://example.org/other):\n\t" + OTHER_SVID + "\n"
            + "bundle(spiffe://example.org):\n\t" + BUNDLE + "\n";

    /** A stand-in spire-agent that writes {@code stderr}, then {@code stdout}, and exits with {@code exit}. */
    private String agent(String name, String stdout, String stderr, int exit) throws Exception {
        Path out = Files.writeString(this.dir.resolve(name + ".out"), stdout);
        Path err = Files.writeString(this.dir.resolve(name + ".err"), stderr);
        return script(name, "cat '" + err + "' >&2\ncat '" + out + "'\nexit " + exit);
    }

    @Test
    void spireParsesTheTwoLineOutputAndPassesTheCommandLine() throws Exception {
        Path args = this.dir.resolve("args");
        Path out = Files.writeString(this.dir.resolve("out"), OUTPUT);
        String bin = script("spire-agent", "echo \"$*\" > '" + args + "'\n"
                + "echo 'warning: something' >&2\ncat '" + out + "'");
        String svid = new SvidSource.SpireWorkloadApi("/tmp/agent.sock", bin).fetch("https://attester.example");
        assertEquals(SVID, svid);
        assertEquals("api fetch jwt -audience https://attester.example -socketPath /tmp/agent.sock",
                Files.readString(args).strip());
    }

    @Test
    void spireAcceptsTheSingleLineFormAndABareJwtLine() throws Exception {
        String single = agent("single", "token(spiffe://example.org/w): " + SVID + "\n", "", 0);
        assertEquals(SVID, new SvidSource.SpireWorkloadApi("/s", single).fetch("aud"));
        String bare = agent("bare", "some banner\n  " + SVID + "  \n", "", 0);
        assertEquals(SVID, new SvidSource.SpireWorkloadApi("/s", bare).fetch("aud"));
    }

    @Test
    void spireDoesNotReadStderrAsOutput() throws Exception {
        assertEquals(SVID, new SvidSource.SpireWorkloadApi("/s", agent("both", OUTPUT, "1.9.6\n", 0)).fetch("aud"));
        String versionOnly = agent("version", "", "1.9.6\n", 0);
        assertThrows(Evidence.EvidenceNotFoundException.class,
                () -> new SvidSource.SpireWorkloadApi("/s", versionOnly).fetch("aud"));
    }

    @Test
    void spireRefusesOutputWithoutACompactJws() throws Exception {
        String[] outputs = {
            "1.9.6\n",
            "level=info msg=starting version=v1.9.6\n",
            "a.b.c\n",
            "token(spiffe://example.org/wl):\n\t1.9.6\n",
            "token(spiffe://example.org/wl):\n",
            "eyJ0eXAiOiJKV1QifQ.e30.c2ln\n",   // a JSON header with no alg
            "bnVsbA.e30.c2ln\n",              // a header of null
            "eyJhbGciOiJFUzI1NiJ9.e30.\n",     // no signature
            "no token here\n",
            "eyJhbGciOiJFUzI1NiIsfQ.e30.c2ln\n",                    // {"alg":"ES256",}: not strict JSON
            "eyJhbGciOiJFUzI1NiIsImFsZyI6IkVTMjU2In0.e30.c2ln\n",   // a duplicate "alg"
            "77u_eyJhbGciOiJFUzI1NiJ9.e30.c2ln\n",                  // a header with a BOM
            "\ufeff" + SVID + "\n",                                 // a BOM is not whitespace
            "\u00a0" + SVID + "\u00a0\n",                          // nor is an NBSP
            "token(spiffe://example.org/wl):\n\u00a0" + SVID + "\n",
            "token(spiffe://example.org/wl): \ufeff" + SVID + "\n",
            "\u000b" + SVID + "\f\n",
        };
        List<Executable> checks = new ArrayList<>();
        for (int i = 0; i < outputs.length; i++) {
            String output = outputs[i];
            String bin = agent("bad" + i, output, "", 0);
            checks.add(() -> {
                Evidence.EvidenceNotFoundException e = assertThrows(Evidence.EvidenceNotFoundException.class,
                        () -> new SvidSource.SpireWorkloadApi("/s", bin).fetch("aud"), output);
                assertTrue(e.getMessage().contains("could not parse a JWT-SVID"), e.getMessage());
            });
        }
        assertAll(checks);
    }

    @Test
    void spireErrorDoesNotShowTheOutput() throws Exception {
        String output = "secret-not-a-jwt\nbundle(spiffe://example.org):\n\t" + BUNDLE + "\n";
        String bin = agent("leak", output, SVID, 0);
        Evidence.EvidenceNotFoundException e = assertThrows(Evidence.EvidenceNotFoundException.class,
                () -> new SvidSource.SpireWorkloadApi("/s", bin).fetch("aud"));
        assertFalse(e.getMessage().contains("secret-not-a-jwt"), e.getMessage());
        assertFalse(e.getMessage().contains("WKn-ZIG"), e.getMessage());
        assertFalse(e.getMessage().contains(SVID), e.getMessage());
        assertTrue(e.getMessage().contains(output.length() + " bytes, 3 lines"), e.getMessage());
    }

    @Test
    void spireAgentFailureIsIllegalStateWithoutItsOutput() throws Exception {
        String bin = agent("broken", OUTPUT, "error: no identity issued " + SVID + "\n", 1);
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new SvidSource.SpireWorkloadApi("/s", bin).fetch("aud"));
        assertEquals("spire-agent fetch failed: exit status 1", e.getMessage());
    }

    @Test
    void hungSpireAgentIsKilledAfterTheTimeout() throws Exception {
        String bin = script("hang", "exec sleep 30");
        long start = System.nanoTime();
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new SvidSource.SpireWorkloadApi("/s", bin, Duration.ofMillis(300)).fetch("aud"));
        assertTrue(e.getMessage().contains("did not exit"), e.getMessage());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 10_000);
    }

    @Test
    void chattySpireAgentIsKilledPastOneMiB() throws Exception {
        // ~2 MiB of output, far beyond a pipe buffer: without a concurrent reader the child would block on write
        // and never exit. Past 1 MiB the agent is killed and the fetch fails, even with a token in the first MiB.
        String bin = script("chatty",
                "echo 'token(spiffe://example.org/w): " + SVID + "'\n"
                        + "i=0; while [ $i -lt 32 ]; do head -c 65536 /dev/zero | tr '\\0' 'x'; i=$((i+1)); done");
        long start = System.nanoTime();
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new SvidSource.SpireWorkloadApi("/s", bin, Duration.ofSeconds(20)).fetch("aud"));
        assertEquals("spire-agent fetch failed: output is larger than 1048576 bytes", e.getMessage());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 10_000);
    }

    @Test
    void spireStdoutIsCappedAtOneMiB() throws Exception {
        String line = "token(spiffe://example.org/wl): " + SVID + "\n";
        String atCap = line + "x".repeat((1 << 20) - line.length());
        assertEquals(SVID, new SvidSource.SpireWorkloadApi("/s", agent("atcap", atCap, "", 0)).fetch("aud"));
        // One byte more while the agent is still running fails the fetch.
        Path overOut = Files.writeString(this.dir.resolve("over.out"), atCap + "x");
        String over = script("over", "cat '" + overOut + "'\nexec sleep 5");
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new SvidSource.SpireWorkloadApi("/s", over).fetch("aud"));
        assertEquals("spire-agent fetch failed: output is larger than 1048576 bytes", e.getMessage());
    }

    @Test
    void anAgentThatWritesPastTheCapAndExitsAlwaysFails() throws Exception {
        // The agent itself writes 1 MiB + 1 byte and exits at once, so the last bytes may be read either side
        // of its exit. They were written while it ran, so the fetch fails every time, as in the other ports.
        String bin = script("overexit", "exec head -c 1048577 /dev/zero");
        int ok = 0;
        for (int i = 0; i < 50; i++) {
            try {
                new SvidSource.SpireWorkloadApi("/s", bin).fetch("aud");
                ok++;
            } catch (IllegalStateException e) {
                assertEquals("spire-agent fetch failed: output is larger than 1048576 bytes", e.getMessage());
            } catch (Evidence.EvidenceNotFoundException e) {
                ok++;   // read as post-exit output: cut at the cap, no token in it
            }
        }
        assertEquals(0, ok, ok + " of 50 runs did not fail with the size error");
    }

    @Test
    void spireLastLineWithoutANewlineCountsWhenTheOutputEnds() throws Exception {
        String bin = script("unterminated", "printf 'token(spiffe://example.org/wl): %s' '" + SVID + "'");
        assertEquals(SVID, new SvidSource.SpireWorkloadApi("/s", bin).fetch("aud"));
    }

    // The reader on its own, fed from memory: whether the agent has exited when output passes the cap is not
    // something a script can arrange in Java (the JDK closes the pipe as the agent exits), so these cases
    // are not in vectors/spire-cli.json for Java; the other ports run them against a real helper process.

    /** 1 MiB of output that ends part-way through a token line, then 2 MB more. */
    private static byte[] tokenCutAtTheCap() {
        String head = "token(spiffe://example.org/wl): ";
        String cut = SVID.substring(0, SVID.lastIndexOf('.') + 11);   // the signature's first 10 characters
        String filler = "x".repeat((1 << 20) - 1 - head.length() - cut.length());
        return (filler + "\n" + head + SVID + "\n" + "x".repeat(2_000_000)).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * {@code data} as a pipe gives it: at most 64 KiB available at a time, so when the reader first sees the
     * agent's exit only that much is in the pipe, and the rest arrives after it (as a helper's output).
     */
    private static InputStream pipeLike(byte[] data) {
        return new ByteArrayInputStream(data) {
            @Override
            public synchronized int available() {
                return Math.min(super.available(), 65536);
            }
        };
    }

    @Test
    void spireOutputPastTheCapAfterTheAgentExitedIsCutThereAndACutLineIsNotATokenSource() {
        boolean[] killed = {false};
        var reader = new SvidSource.SpireWorkloadApi.StdoutReader(
                pipeLike(tokenCutAtTheCap()), () -> false, () -> killed[0] = true);
        reader.run();
        var output = reader.stop();
        assertFalse(output.over());
        assertFalse(output.complete());
        assertFalse(killed[0]);
        assertEquals(1 << 20, output.bytes().length);
        String out = new String(output.bytes(), StandardCharsets.UTF_8);
        assertTrue(out.endsWith(SVID.substring(0, SVID.lastIndexOf('.') + 11)));
        // The cut token still looks like a compact JWS; only the guard keeps it out.
        assertEquals(SVID.substring(0, SVID.lastIndexOf('.') + 11), SvidSource.SpireWorkloadApi.parseJwtOutput(out));
        assertEquals(null, SvidSource.SpireWorkloadApi.parseJwtOutput(
                SvidSource.SpireWorkloadApi.completeLines(out, output.complete())));
    }

    @Test
    void spireOutputPastTheCapWhileTheAgentRunsKillsIt() {
        boolean[] killed = {false};
        var reader = new SvidSource.SpireWorkloadApi.StdoutReader(
                new ByteArrayInputStream(tokenCutAtTheCap()), () -> true, () -> killed[0] = true);
        reader.run();
        var output = reader.stop();
        assertTrue(output.over());
        assertTrue(killed[0]);
        assertEquals(0, output.bytes().length);
    }

    @Test
    void spireOutputAvailableWhenTheExitIsFirstSeenIsTheAgentsAndPastTheCapKillsIt() {
        // Everything readable at the first sight of the exit was written before it: at the cap, all of it is
        // kept; one byte more is the agent's overflow, even though the agent has exited.
        for (int extra : new int[] {0, 1}) {
            boolean[] killed = {false};
            byte[] data = new byte[(1 << 20) + extra];
            var reader = new SvidSource.SpireWorkloadApi.StdoutReader(
                    new ByteArrayInputStream(data), () -> false, () -> killed[0] = true);
            reader.run();
            var output = reader.stop();
            assertEquals(extra == 1, output.over());
            assertEquals(extra == 1, killed[0]);
            assertEquals(extra == 1 ? 0 : 1 << 20, output.bytes().length);
            assertEquals(extra == 0, output.complete());
        }
        // Read partly while running and the rest available at the exit: the same.
        boolean[] alive = {true};
        boolean[] killed = {false};
        byte[] data = new byte[(1 << 20) + 1];
        var reader = new SvidSource.SpireWorkloadApi.StdoutReader(new ByteArrayInputStream(data) {
            @Override
            public synchronized int read(byte[] b, int off, int len) {
                int n = super.read(b, off, Math.min(len, 1000));
                alive[0] = false;   // the agent exits after the first chunk is read
                return n;
            }
        }, () -> alive[0], () -> killed[0] = true);
        reader.run();
        assertTrue(reader.stop().over());
        assertTrue(killed[0]);
    }

    @Test
    void spireOutputReadToItsEndKeepsALastLineWithoutANewline() {
        byte[] data = ("token(spiffe://example.org/wl): " + SVID).getBytes(StandardCharsets.UTF_8);
        var reader = new SvidSource.SpireWorkloadApi.StdoutReader(new ByteArrayInputStream(data), () -> false, () -> { });
        reader.run();
        var output = reader.stop();
        assertTrue(output.complete());
        String out = new String(output.bytes(), StandardCharsets.UTF_8);
        assertEquals(SVID, SvidSource.SpireWorkloadApi.parseJwtOutput(
                SvidSource.SpireWorkloadApi.completeLines(out, output.complete())));
        assertEquals("a\nb\n", SvidSource.SpireWorkloadApi.completeLines("a\nb\nc", false));
        assertEquals("", SvidSource.SpireWorkloadApi.completeLines("abc", false));
    }

    @Test
    void spireDiscardsAFloodOfStderr() throws Exception {
        String bin = agent("noisy", OUTPUT, "e".repeat(4 << 20), 0);
        assertEquals(SVID, new SvidSource.SpireWorkloadApi("/s", bin).fetch("aud"));
    }

    @Test
    void spireIgnoresOnlyAsciiSpaceTabAndCrAroundAValue() throws Exception {
        String bin = agent("crlf", "token(spiffe://example.org/wl):\r\n \t" + SVID + "\t \r\n", "", 0);
        assertEquals(SVID, new SvidSource.SpireWorkloadApi("/s", bin).fetch("aud"));
    }

    @Test
    void spireLabelWithNoValueDoesNotTakeTheNextLabel() throws Exception {
        String[] outputs = {
            "hint(spiffe://example.org/wl):\ntoken(spiffe://example.org/wl): " + SVID + "\n",
            "token(spiffe://example.org/wl):\ntoken(spiffe://example.org/other): " + SVID + "\n",
            "bundle(spiffe://example.org):\n\ttoken(spiffe://example.org/wl): " + SVID + "\n",
        };
        List<Executable> checks = new ArrayList<>();
        for (int i = 0; i < outputs.length; i++) {
            String output = outputs[i];
            String bin = agent("labels" + i, output, "", 0);
            checks.add(() -> assertEquals(SVID, new SvidSource.SpireWorkloadApi("/s", bin).fetch("aud"), output));
        }
        assertAll(checks);
    }

    @Test
    void missingSpireBinaryFails() {
        assertThrows(Exception.class,
                () -> new SvidSource.SpireWorkloadApi("/s", this.dir.resolve("nope").toString()).fetch("aud"));
    }
}
