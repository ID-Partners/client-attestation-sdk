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
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The SPIRE CLI source against the shared cases (vectors/spire-cli.json): a fake spire-agent that starts a
 * helper holding its stdout. Every port must agree.
 */
class SpireCliVectorsTest {

    @TempDir
    Path dir;

    @SuppressWarnings("unchecked")
    static Stream<Arguments> cases() throws Exception {
        Map<String, Object> file = JsonUtil.parseJson(Files.readString(Path.of("..", "vectors", "spire-cli.json")));
        return ((List<Map<String, Object>>) file.get("cases")).stream().map(c -> Arguments.of(c.get("name"), c));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void vector(String name, Map<String, Object> c) throws Exception {
        assumeTrue(!System.getProperty("os.name").toLowerCase().contains("win"), "fake spire-agent is a shell script");
        Path bin = Files.writeString(this.dir.resolve("spire-agent"), "#!/bin/sh\n" + c.get("script"));
        Files.setPosixFilePermissions(bin, PosixFilePermissions.fromString("rwx------"));
        long started = System.nanoTime();
        Object outcome;
        try {
            outcome = new SvidSource.SpireWorkloadApi("/s", bin.toString()).fetch("aud");
        } catch (Exception e) {
            outcome = e;
        }
        long elapsed = Duration.ofNanos(System.nanoTime() - started).toMillis();
        System.out.println(name + ": " + elapsed + "ms");
        if (c.containsKey("token")) {
            assertEquals(c.get("token"), outcome);
        } else if (c.containsKey("error")) {
            assertEquals(c.get("error"), assertInstanceOf(IllegalStateException.class, outcome).getMessage());
        } else {
            assertEquals(c.get("not_found"),
                    assertInstanceOf(Evidence.EvidenceNotFoundException.class, outcome).getMessage());
        }
        long max = ((Number) c.get("max_ms")).longValue();
        assertTrue(elapsed <= max, "took " + elapsed + "ms, want at most " + max + "ms");
    }

    @Test
    void aHungAgentIsKilledAtTheTimeoutWithAHelperHoldingStdout() throws Exception {
        // Not in spire-cli.json: it shortens the 30 s timeout.
        assumeTrue(!System.getProperty("os.name").toLowerCase().contains("win"), "fake spire-agent is a shell script");
        Path bin = Files.writeString(this.dir.resolve("spire-agent"),
                "#!/bin/sh\nsleep 60 &\nprintf 'token(spiffe://example.org/wl): x.y.z\\n'\nexec sleep 60\n");
        Files.setPosixFilePermissions(bin, PosixFilePermissions.fromString("rwx------"));
        long started = System.nanoTime();
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new SvidSource.SpireWorkloadApi("/s", bin.toString(), Duration.ofMillis(300)).fetch("aud"));
        long elapsed = Duration.ofNanos(System.nanoTime() - started).toMillis();
        System.out.println("killed at the timeout: " + elapsed + "ms");
        assertEquals("spire-agent did not exit within 300ms; killed", e.getMessage());
        assertTrue(elapsed < 3000, "took " + elapsed + "ms");
    }
}
