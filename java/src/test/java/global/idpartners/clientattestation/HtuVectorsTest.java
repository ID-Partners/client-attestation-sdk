package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** DPoP htu and nonce-origin normalisation against the shared vectors (vectors/htu.json). Every port must agree. */
class HtuVectorsTest {

    private static final SigningKeyPair KEY = SigningKeyPair.generate("ES256");

    @SuppressWarnings("unchecked")
    static Stream<Arguments> cases() throws Exception {
        Map<String, Object> file = JsonUtil.parseJson(Files.readString(Path.of("..", "vectors", "htu.json")));
        return ((List<Map<String, Object>>) file.get("cases")).stream().map(c -> Arguments.of(c.get("name"), c));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void vector(String name, Map<String, Object> c) throws Exception {
        String url = (String) c.get("url");
        DpopProofBuilder builder = new DpopProofBuilder(KEY).uri(url);
        if (c.containsKey("error")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, builder::build);
            assertEquals(c.get("error"), e.getMessage());
            assertEquals(url, ClientAttestation.nonceKey(url));   // a refused URL is its own nonce key
            return;
        }
        assertEquals(c.get("htu"), JwtTestSupport.claims(builder.build()).get("htu"));
        assertEquals(c.get("htu"), DpopProofBuilder.normalizeHtu(url));
        assertEquals(c.get("origin"), ClientAttestation.nonceKey(url));
    }

    @Test
    void aLoneSurrogateInThePathIsRefused() {
        // Not in htu.json: JSON parsers disagree on a lone surrogate.
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> DpopProofBuilder.normalizeHtu("https://as.example.com/a\ud800"));
        assertEquals("uri (htu) has an invalid path", e.getMessage());
    }
}
