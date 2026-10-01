package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** {@link Evidence#autoDetect()}'s ordering and the GCP metadata probe, with env and locations injected. */
class EvidenceTest {

    @TempDir
    Path dir;

    private StubHttpServer metadata;
    private final Map<String, String> env = new HashMap<>();
    private String missingFile;
    private String missingSocket;

    @BeforeEach
    void setUp() throws Exception {
        this.metadata = new StubHttpServer();
        this.missingFile = this.dir.resolve("no-token").toString();
        this.missingSocket = this.dir.resolve("no.sock").toString();
    }

    @AfterEach
    void tearDown() {
        this.metadata.close();
    }

    private SvidSource detect(String metadataUrl) throws Exception {
        return Evidence.autoDetect(this.env::get, this.missingFile, this.missingSocket, metadataUrl);
    }

    /** A loopback port nothing listens on: the probe's connection is refused, i.e. "not on GCP". */
    private static String unreachableMetadata() throws java.io.IOException {
        try (java.net.ServerSocket s = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            return "http://127.0.0.1:" + s.getLocalPort() + "/computeMetadata/v1/";
        }
    }

    @Test
    void explicitEnvTokenWinsAndIsStripped() throws Exception {
        this.env.put(Evidence.ENV_SVID, "  env-token \n");
        this.env.put(Evidence.ENV_TOKEN_FILE, Files.writeString(this.dir.resolve("t"), "file").toString());
        SvidSource source = detect(unreachableMetadata());
        assertInstanceOf(SvidSource.Static.class, source);
        assertEquals("env-token", source.fetch("aud"));
    }

    @Test
    void blankEnvTokenFallsThroughToTheTokenFile() throws Exception {
        this.env.put(Evidence.ENV_SVID, "   ");
        Path file = Files.writeString(this.dir.resolve("projected"), "file-token\n");
        this.env.put(Evidence.ENV_TOKEN_FILE, file.toString());
        SvidSource source = detect(unreachableMetadata());
        assertInstanceOf(SvidSource.File.class, source);
        assertEquals("file-token", source.fetch("ignored"));
    }

    @Test
    void missingEnvTokenFileFailsClosedNamingTheVariable() throws Exception {
        String missing = this.dir.resolve("does-not-exist").toString();
        this.env.put(Evidence.ENV_TOKEN_FILE, missing);
        // Even with a usable default token file present, an explicit setting that points nowhere is an error.
        Path dflt = Files.writeString(this.dir.resolve("default-token"), "default-token");
        Evidence.EvidenceNotFoundException e = assertThrows(Evidence.EvidenceNotFoundException.class,
                () -> Evidence.autoDetect(this.env::get, dflt.toString(), this.missingSocket, unreachableMetadata()));
        assertTrue(e.getMessage().contains(Evidence.ENV_TOKEN_FILE), e.getMessage());
        assertTrue(e.getMessage().contains(missing), e.getMessage());
    }

    @Test
    void blankEnvTokenFileIsTreatedAsUnset() throws Exception {
        this.env.put(Evidence.ENV_TOKEN_FILE, "  ");
        Path dflt = Files.writeString(this.dir.resolve("default-token"), "default-token");
        SvidSource source = Evidence.autoDetect(this.env::get, dflt.toString(), this.missingSocket,
                unreachableMetadata());
        assertInstanceOf(SvidSource.File.class, source);
        assertEquals("default-token", source.fetch("aud"));
    }

    @Test
    void missingEnvSpiffeSocketFailsClosedNamingTheVariable() throws Exception {
        this.env.put(Evidence.ENV_SPIFFE_SOCKET, "unix://" + this.dir.resolve("gone.sock"));
        // A reachable metadata server must not be used as a silent fallback.
        this.metadata.respond("/computeMetadata/v1/", 200, "");
        Evidence.EvidenceNotFoundException e = assertThrows(Evidence.EvidenceNotFoundException.class,
                () -> detect(this.metadata.url("/computeMetadata/v1/")));
        assertTrue(e.getMessage().contains(Evidence.ENV_SPIFFE_SOCKET), e.getMessage());
        assertEquals(0, this.metadata.hits("/computeMetadata/v1/"));
    }

    @Test
    void blankEnvSpiffeSocketIsTreatedAsUnset() throws Exception {
        this.env.put(Evidence.ENV_SPIFFE_SOCKET, " ");
        Path socket = Files.createFile(this.dir.resolve("default.sock"));
        SvidSource source = Evidence.autoDetect(this.env::get, this.missingFile, socket.toString(),
                unreachableMetadata());
        assertInstanceOf(SvidSource.SpireWorkloadApi.class, source);
    }

    @Test
    void spiffeSocketFromEnvSelectsSpire() throws Exception {
        Path socket = Files.createFile(this.dir.resolve("agent.sock"));
        this.env.put(Evidence.ENV_SPIFFE_SOCKET, "unix://" + socket);
        assertInstanceOf(SvidSource.SpireWorkloadApi.class, detect(unreachableMetadata()));
    }

    @Test
    void defaultSpiffeSocketSelectsSpire() throws Exception {
        Path socket = Files.createFile(this.dir.resolve("default.sock"));
        SvidSource source = Evidence.autoDetect(this.env::get, this.missingFile, socket.toString(),
                unreachableMetadata());
        assertInstanceOf(SvidSource.SpireWorkloadApi.class, source);
    }

    @Test
    void reachableMetadataServerSelectsGoogleMetadata() throws Exception {
        this.metadata.respond("/computeMetadata/v1/", 200, "");
        assertInstanceOf(SvidSource.GoogleMetadata.class, detect(this.metadata.url("/computeMetadata/v1/")));
        assertEquals("Google", this.metadata.lastHeaders.get("/computeMetadata/v1/").getFirst("Metadata-Flavor"));
    }

    @Test
    void envTokenFileBeatsSpireAndMetadata() throws Exception {
        Path file = Files.writeString(this.dir.resolve("projected"), "file-token");
        Path socket = Files.createFile(this.dir.resolve("agent.sock"));
        this.env.put(Evidence.ENV_TOKEN_FILE, file.toString());
        this.env.put(Evidence.ENV_SPIFFE_SOCKET, "unix://" + socket);
        this.metadata.respond("/computeMetadata/v1/", 200, "");
        SvidSource source = Evidence.autoDetect(this.env::get, this.missingFile, socket.toString(),
                this.metadata.url("/computeMetadata/v1/"));
        assertInstanceOf(SvidSource.File.class, source);
        assertEquals("file-token", source.fetch("aud"));
        assertEquals(0, this.metadata.hits("/computeMetadata/v1/"));
    }

    @Test
    void defaultTokenFileBeatsSpireAndMetadata() throws Exception {
        Path dflt = Files.writeString(this.dir.resolve("default-token"), "default-token");
        Path socket = Files.createFile(this.dir.resolve("agent.sock"));
        this.env.put(Evidence.ENV_SPIFFE_SOCKET, socket.toString());
        this.metadata.respond("/computeMetadata/v1/", 200, "");
        SvidSource source = Evidence.autoDetect(this.env::get, dflt.toString(), socket.toString(),
                this.metadata.url("/computeMetadata/v1/"));
        assertInstanceOf(SvidSource.File.class, source);
        assertEquals("default-token", source.fetch("aud"));
        assertEquals(0, this.metadata.hits("/computeMetadata/v1/"));
    }

    @Test
    void spireSocketBeatsMetadata() throws Exception {
        Path socket = Files.createFile(this.dir.resolve("default.sock"));
        this.metadata.respond("/computeMetadata/v1/", 200, "");
        SvidSource source = Evidence.autoDetect(this.env::get, this.missingFile, socket.toString(),
                this.metadata.url("/computeMetadata/v1/"));
        assertInstanceOf(SvidSource.SpireWorkloadApi.class, source);
        assertEquals(0, this.metadata.hits("/computeMetadata/v1/"));
    }

    @Test
    void envTokenBeatsEverySource() throws Exception {
        Path file = Files.writeString(this.dir.resolve("projected"), "file-token");
        Path socket = Files.createFile(this.dir.resolve("agent.sock"));
        this.env.put(Evidence.ENV_SVID, "env-token");
        this.env.put(Evidence.ENV_TOKEN_FILE, file.toString());
        this.env.put(Evidence.ENV_SPIFFE_SOCKET, socket.toString());
        this.metadata.respond("/computeMetadata/v1/", 200, "");
        SvidSource source = Evidence.autoDetect(this.env::get, file.toString(), socket.toString(),
                this.metadata.url("/computeMetadata/v1/"));
        assertEquals("env-token", source.fetch("aud"));
        assertEquals(0, this.metadata.hits("/computeMetadata/v1/"));
    }

    @Test
    void nothingDetectedThrowsWithGuidance() {
        Evidence.EvidenceNotFoundException e = assertThrows(Evidence.EvidenceNotFoundException.class,
                () -> detect(unreachableMetadata()));
        assertTrue(e.getMessage().contains(Evidence.ENV_SVID));
        assertTrue(e.getMessage().contains(Evidence.ENV_SPIFFE_SOCKET));
    }

    @Test
    void metadataProbeTreatsServerErrorsRedirectsAndTimeoutsAsAbsent() {
        Duration t = Duration.ofMillis(300);
        this.metadata.respond("/err/", 500, "{}");
        this.metadata.respond("/notfound/", 404, "{}");
        this.metadata.respond("/target/", 200, "{}");
        this.metadata.redirect("/hop/", this.metadata.url("/target/"));
        this.metadata.slow("/slow/", 3000);

        assertFalse(Evidence.gcpMetadataAvailable(this.metadata.url("/err/"), t));
        assertTrue(Evidence.gcpMetadataAvailable(this.metadata.url("/notfound/"), t));   // a 4xx still means "a server answered"
        assertFalse(Evidence.gcpMetadataAvailable(this.metadata.url("/hop/"), t));
        assertEquals(0, this.metadata.hits("/target/"));
        assertFalse(Evidence.gcpMetadataAvailable(this.metadata.url("/slow/"), t));
        assertFalse(Evidence.gcpMetadataAvailable("not a url", t));
    }
}
