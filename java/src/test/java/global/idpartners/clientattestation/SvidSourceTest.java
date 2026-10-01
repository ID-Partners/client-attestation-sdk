package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

    // ── File / Static ───────────────────────────────────────────────────────────────────────────────

    @Test
    void fileAndStaticSources() throws Exception {
        Path token = Files.writeString(this.dir.resolve("token"), "  file.jwt.sig \n");
        assertEquals("file.jwt.sig", new SvidSource.File(token.toString()).fetch("ignored"));
        assertEquals("s.v.id", new SvidSource.Static("s.v.id").fetch("ignored"));
    }

    // ── SpireWorkloadApi ────────────────────────────────────────────────────────────────────────────

    private String script(String name, String body) throws Exception {
        assumeTrue(Files.isExecutable(Path.of("/bin/sh")), "needs /bin/sh");
        Path p = this.dir.resolve(name);
        Files.writeString(p, "#!/bin/sh\n" + body + "\n");
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwx------"));
        return p.toString();
    }

    @Test
    void spireParsesTheTokenLineAndPassesTheCommandLine() throws Exception {
        Path args = this.dir.resolve("args");
        String bin = script("spire-agent", "echo \"$*\" > '" + args + "'\n"
                + "echo 'warning: something' >&2\necho 'token(spiffe://example.org/w): x.y.z'");
        String svid = new SvidSource.SpireWorkloadApi("/tmp/agent.sock", bin).fetch("https://attester.example");
        assertEquals("x.y.z", svid);
        assertEquals("api fetch jwt -audience https://attester.example -socketPath /tmp/agent.sock",
                Files.readString(args).strip());
    }

    @Test
    void spireAcceptsABareJwtLine() throws Exception {
        String bin = script("bare", "echo 'some banner'\necho 'aa.bb.cc'");
        assertEquals("aa.bb.cc", new SvidSource.SpireWorkloadApi("/s", bin).fetch("aud"));
    }

    @Test
    void spireUnparseableOutputIsIllegalState() throws Exception {
        String bin = script("broken", "echo 'error: no identity issued' >&2\nexit 1");
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new SvidSource.SpireWorkloadApi("/s", bin).fetch("aud"));
        assertTrue(e.getMessage().contains("no identity issued"), e.getMessage());
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
    void chattySpireAgentCannotDeadlockTheWait() throws Exception {
        // ~2 MiB of output, far beyond a pipe buffer: without a concurrent reader the child would block
        // on write and never exit. Output beyond the cap is drained and dropped; the token line still wins.
        String bin = script("chatty",
                "echo 'token(spiffe://example.org/w): t.o.k'\n"
                        + "i=0; while [ $i -lt 32 ]; do head -c 65536 /dev/zero | tr '\\0' 'x'; i=$((i+1)); done");
        assertEquals("t.o.k", new SvidSource.SpireWorkloadApi("/s", bin, Duration.ofSeconds(20)).fetch("aud"));
    }

    @Test
    void missingSpireBinaryFails() {
        assertThrows(Exception.class,
                () -> new SvidSource.SpireWorkloadApi("/s", this.dir.resolve("nope").toString()).fetch("aud"));
    }
}
