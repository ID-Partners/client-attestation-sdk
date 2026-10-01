package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** {@link DpopProofBuilder} unit coverage: required htu, htm default, nonce handling, embedded jwk header. */
class DpopProofBuilderTest {

    private static final String TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2";

    private static final SigningKeyPair INSTANCE_KEY = SigningKeyPair.generate("ES256");

    @Test
    void instanceKeyIsRequired() {
        assertThrows(NullPointerException.class, () -> new DpopProofBuilder(null));
    }

    @Test
    void uriIsRequired() {
        assertThrows(IllegalArgumentException.class, () -> new DpopProofBuilder(INSTANCE_KEY).build());
        assertThrows(IllegalArgumentException.class, () -> new DpopProofBuilder(INSTANCE_KEY).uri("  ").build());
    }

    @Test
    void defaultsMethodToPostAndMintsJtiAndIat() throws Exception {
        long before = Instant.now().getEpochSecond();
        String proof = new DpopProofBuilder(INSTANCE_KEY).uri(TOKEN_ENDPOINT).build();
        long after = Instant.now().getEpochSecond();
        Map<String, Object> claims = JwtTestSupport.claims(proof);
        assertEquals("POST", claims.get("htm"));
        assertEquals(TOKEN_ENDPOINT, claims.get("htu"));
        assertNotNull(claims.get("jti"));
        assertFalse(claims.containsKey("nonce"));
        long iat = ((Number) claims.get("iat")).longValue();
        assertTrue(iat >= before && iat <= after, "iat must default to now");
    }

    @Test
    void explicitValuesAreCarried() throws Exception {
        Instant iat = Instant.parse("2026-07-19T10:00:00Z");
        String proof = new DpopProofBuilder(INSTANCE_KEY)
                .method("GET")
                .uri(TOKEN_ENDPOINT)
                .nonce("server-nonce")
                .jwtId("jti-789")
                .issuedAt(iat)
                .build();
        Map<String, Object> claims = JwtTestSupport.claims(proof);
        assertEquals("GET", claims.get("htm"));
        assertEquals("server-nonce", claims.get("nonce"));
        assertEquals("jti-789", claims.get("jti"));
        assertEquals(iat.getEpochSecond(), ((Number) claims.get("iat")).longValue());
    }

    @Test
    void nullOrBlankMethodKeepsDefault() throws Exception {
        String proof = new DpopProofBuilder(INSTANCE_KEY)
                .method(null)
                .method("  ")
                .uri(TOKEN_ENDPOINT)
                .build();
        assertEquals("POST", JwtTestSupport.claims(proof).get("htm"));
    }

    @Test
    void blankNonceIsOmitted() throws Exception {
        String proof = new DpopProofBuilder(INSTANCE_KEY).uri(TOKEN_ENDPOINT).nonce("  ").build();
        assertFalse(JwtTestSupport.claims(proof).containsKey("nonce"));
    }

    @Test
    void headerEmbedsInstancePublicJwkAndTyp() throws Exception {
        String proof = new DpopProofBuilder(INSTANCE_KEY).uri(TOKEN_ENDPOINT).build();
        Map<String, Object> header = JwtTestSupport.header(proof);
        assertEquals(DpopProofBuilder.TYP, header.get("typ"));
        assertEquals("ES256", header.get("alg"));
        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = (Map<String, Object>) header.get("jwk");
        Map<String, Object> expected = INSTANCE_KEY.publicJwk();
        assertEquals(expected.get("kty"), jwk.get("kty"));
        assertEquals(expected.get("x"), jwk.get("x"));
        assertEquals(expected.get("y"), jwk.get("y"));
        assertFalse(jwk.containsKey("d"), "the embedded jwk must be public-only");
    }

    @Test
    void methodIsUpperCasedAndHtuDropsQueryAndFragment() throws Exception {
        String proof = new DpopProofBuilder(INSTANCE_KEY)
                .method("get")
                .uri("HTTPS://API.Example.com:443/v1/Accounts?limit=5#top")
                .build();
        Map<String, Object> claims = JwtTestSupport.claims(proof);
        assertEquals("GET", claims.get("htm"));
        assertEquals("https://api.example.com/v1/Accounts", claims.get("htu"));
    }

    @Test
    void htuNormalisation() {
        assertEquals("http://127.0.0.1:8080/r", DpopProofBuilder.normalizeHtu("http://127.0.0.1:8080/r?x=1"));
        assertEquals("http://h.example/r", DpopProofBuilder.normalizeHtu("http://h.example:80/r"));
        assertEquals("https://h.example:8443", DpopProofBuilder.normalizeHtu("https://user@h.example:8443"));
        assertEquals("http://[::1]:9/p", DpopProofBuilder.normalizeHtu("http://[::1]:9/p#f"));
        assertEquals("ftp://h.example:21/f", DpopProofBuilder.normalizeHtu("ftp://h.example:21/f"));
        // Not an absolute URL: just cut query / fragment.
        assertEquals("/relative", DpopProofBuilder.normalizeHtu("/relative?x#y"));
        assertEquals("/relative", DpopProofBuilder.normalizeHtu("/relative#y?x"));
        assertEquals("not a url", DpopProofBuilder.normalizeHtu("not a url?q"));
        assertEquals("plain", DpopProofBuilder.normalizeHtu("plain"));
    }

    @Test
    void accessTokenAddsAth() throws Exception {
        // RFC 9449 section 7.1 example: ath for this access token.
        String token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
        assertEquals("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", DpopProofBuilder.accessTokenHash(token));
        String proof = new DpopProofBuilder(INSTANCE_KEY).uri(TOKEN_ENDPOINT).accessToken(token).build();
        assertEquals(DpopProofBuilder.accessTokenHash(token), JwtTestSupport.claims(proof).get("ath"));
        String none = new DpopProofBuilder(INSTANCE_KEY).uri(TOKEN_ENDPOINT).accessToken(token).accessToken(" ")
                .build();
        assertFalse(JwtTestSupport.claims(none).containsKey("ath"));
        assertFalse(JwtTestSupport.claims(new DpopProofBuilder(INSTANCE_KEY).uri(TOKEN_ENDPOINT).accessToken(null)
                .build()).containsKey("ath"));
    }
}
