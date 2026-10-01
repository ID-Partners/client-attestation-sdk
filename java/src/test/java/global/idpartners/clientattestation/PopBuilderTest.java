package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** {@link PopBuilder} unit coverage: required audience, explicit claims, optional-claim omission. */
class PopBuilderTest {

    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String AUDIENCE = "https://as.example.com";

    private static final SigningKeyPair INSTANCE_KEY = SigningKeyPair.generate("ES256");

    @Test
    void instanceKeyIsRequired() {
        assertThrows(NullPointerException.class, () -> new PopBuilder(null));
    }

    @Test
    void audienceIsRequired() {
        assertThrows(IllegalArgumentException.class, () -> new PopBuilder(INSTANCE_KEY).build());
        assertThrows(IllegalArgumentException.class, () -> new PopBuilder(INSTANCE_KEY).audience("  ").build());
    }

    @Test
    void explicitClaimsAreCarried() throws Exception {
        Instant iat = Instant.parse("2026-07-19T10:00:00Z");
        String pop = new PopBuilder(INSTANCE_KEY)
                .clientId(CLIENT_ID)
                .audience(AUDIENCE)
                .challenge("challenge-123")
                .jwtId("jti-456")
                .issuedAt(iat)
                .build();
        Map<String, Object> claims = JwtTestSupport.claims(pop);
        assertEquals(CLIENT_ID, claims.get("iss"));
        assertEquals(AUDIENCE, claims.get("aud"));
        assertEquals("challenge-123", claims.get("challenge"));
        assertEquals("jti-456", claims.get("jti"));
        assertEquals(iat.getEpochSecond(), ((Number) claims.get("iat")).longValue());
    }

    @Test
    void optionalClaimsAreOmittedAndDefaultsMinted() throws Exception {
        long before = Instant.now().getEpochSecond();
        String pop = new PopBuilder(INSTANCE_KEY).audience(AUDIENCE).build();
        long after = Instant.now().getEpochSecond();
        Map<String, Object> claims = JwtTestSupport.claims(pop);
        assertFalse(claims.containsKey("iss"), "iss must be omitted when clientId is unset");
        assertFalse(claims.containsKey("challenge"));
        assertNotNull(claims.get("jti"), "a jti must be minted by default");
        long iat = ((Number) claims.get("iat")).longValue();
        assertTrue(iat >= before && iat <= after, "iat must default to now");
    }

    @Test
    void blankClientIdAndChallengeAreOmitted() throws Exception {
        String pop = new PopBuilder(INSTANCE_KEY)
                .clientId("  ")
                .audience(AUDIENCE)
                .challenge("  ")
                .build();
        Map<String, Object> claims = JwtTestSupport.claims(pop);
        assertFalse(claims.containsKey("iss"));
        assertFalse(claims.containsKey("challenge"));
    }

    @Test
    void headerCarriesTypAndInstanceKid() throws Exception {
        String pop = new PopBuilder(INSTANCE_KEY).audience(AUDIENCE).build();
        Map<String, Object> header = JwtTestSupport.header(pop);
        assertEquals(PopBuilder.TYP, header.get("typ"));
        assertEquals(INSTANCE_KEY.keyId(), header.get("kid"));
    }
}
