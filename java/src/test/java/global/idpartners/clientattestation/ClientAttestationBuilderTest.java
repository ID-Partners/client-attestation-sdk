package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@link ClientAttestationBuilder} unit coverage: required-field enforcement, iat/exp arithmetic and the
 * optional {@code authorization_details} / {@code workload} claims.
 */
class ClientAttestationBuilderTest {

    private static final String ATTESTER_ISS = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";

    private static final SigningKeyPair ATTESTER_KEY = SigningKeyPair.generate("ES256");
    private static final SigningKeyPair INSTANCE_KEY = SigningKeyPair.generate("ES256");

    private ClientAttestationBuilder builder() {
        return new ClientAttestationBuilder(ATTESTER_KEY, ATTESTER_ISS)
                .clientId(CLIENT_ID)
                .confirmationKey(INSTANCE_KEY);
    }

    @Test
    void nullAttesterKeyIsRejected() {
        assertThrows(NullPointerException.class,
                () -> new ClientAttestationBuilder((SigningKeyPair) null, ATTESTER_ISS));
    }

    @Test
    void nullAttesterSignerIsRejected() {
        assertThrows(NullPointerException.class,
                () -> new ClientAttestationBuilder((JwsSigner) null, ATTESTER_ISS));
    }

    @Test
    void issuerIsRequired() {
        assertThrows(IllegalArgumentException.class, () -> new ClientAttestationBuilder(ATTESTER_KEY, null));
        assertThrows(IllegalArgumentException.class, () -> new ClientAttestationBuilder(ATTESTER_KEY, "  "));
    }

    @Test
    void clientIdIsRequired() {
        ClientAttestationBuilder missing = new ClientAttestationBuilder(ATTESTER_KEY, ATTESTER_ISS)
                .confirmationKey(INSTANCE_KEY)
                .expiresIn(Duration.ofMinutes(5));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, missing::build);
        assertTrue(e.getMessage().contains("clientId"));
        assertThrows(IllegalArgumentException.class, () -> builder().clientId("  ")
                .expiresIn(Duration.ofMinutes(5)).build());
    }

    @Test
    void confirmationKeyIsRequired() {
        ClientAttestationBuilder missing = new ClientAttestationBuilder(ATTESTER_KEY, ATTESTER_ISS)
                .clientId(CLIENT_ID)
                .expiresIn(Duration.ofMinutes(5));
        NullPointerException e = assertThrows(NullPointerException.class, missing::build);
        assertTrue(e.getMessage().contains("cnf.jwk"));
    }

    @Test
    void expiryIsRequired() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> builder().build());
        assertTrue(e.getMessage().contains("expiry is required"));
    }

    @Test
    void explicitIatAndExpAreCarried() throws Exception {
        Instant iat = Instant.parse("2026-07-19T10:00:00Z");
        Instant exp = Instant.parse("2026-07-19T10:05:00Z");
        String jwt = builder().issuedAt(iat).expiresAt(exp).build();
        Map<String, Object> claims = JwtTestSupport.claims(jwt);
        assertEquals(ATTESTER_ISS, claims.get("iss"));
        assertEquals(CLIENT_ID, claims.get("sub"));
        assertEquals(iat.getEpochSecond(), ((Number) claims.get("iat")).longValue());
        assertEquals(exp.getEpochSecond(), ((Number) claims.get("exp")).longValue());
        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) claims.get("cnf");
        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");
        assertEquals(INSTANCE_KEY.keyId(), jwk.get("kid"));
    }

    @Test
    void expiresInAddsTtlToIssuedAt() throws Exception {
        Instant iat = Instant.parse("2026-07-19T10:00:00Z");
        String jwt = builder().issuedAt(iat).expiresIn(Duration.ofSeconds(300)).build();
        Map<String, Object> claims = JwtTestSupport.claims(jwt);
        assertEquals(iat.getEpochSecond() + 300, ((Number) claims.get("exp")).longValue());
    }

    @Test
    void expiresAtWinsOverExpiresIn() throws Exception {
        Instant iat = Instant.parse("2026-07-19T10:00:00Z");
        Instant exp = Instant.parse("2026-07-19T11:00:00Z");
        String jwt = builder().issuedAt(iat).expiresIn(Duration.ofSeconds(10)).expiresAt(exp).build();
        Map<String, Object> claims = JwtTestSupport.claims(jwt);
        assertEquals(exp.getEpochSecond(), ((Number) claims.get("exp")).longValue());
    }

    @Test
    void defaultIssuedAtIsNow() throws Exception {
        long before = Instant.now().getEpochSecond();
        String jwt = builder().expiresIn(Duration.ofMinutes(5)).build();
        long after = Instant.now().getEpochSecond();
        Map<String, Object> claims = JwtTestSupport.claims(jwt);
        long iat = ((Number) claims.get("iat")).longValue();
        assertTrue(iat >= before && iat <= after, "iat must default to now");
        assertEquals(iat + 300, ((Number) claims.get("exp")).longValue());
    }

    @Test
    void authorizationDetailsAndWorkloadAreCarried() throws Exception {
        List<Map<String, Object>> details = List.of(Map.of("type", "payment_initiation", "actions", List.of("initiate")));
        Map<String, Object> workload = Map.of("platform", "railway", "region", "us-west1");
        String jwt = builder()
                .expiresIn(Duration.ofMinutes(5))
                .authorizationDetails(details)
                .workload(workload)
                .build();
        Map<String, Object> claims = JwtTestSupport.claims(jwt);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> carried = (List<Map<String, Object>>) claims.get("authorization_details");
        assertEquals(1, carried.size());
        assertEquals("payment_initiation", carried.get(0).get("type"));
        @SuppressWarnings("unchecked")
        Map<String, Object> carriedWorkload = (Map<String, Object>) claims.get("workload");
        assertEquals("railway", carriedWorkload.get("platform"));
    }

    @Test
    void emptyAuthorizationDetailsAndWorkloadAreOmitted() throws Exception {
        String jwt = builder()
                .expiresIn(Duration.ofMinutes(5))
                .authorizationDetails(List.of())
                .workload(Map.of())
                .build();
        Map<String, Object> claims = JwtTestSupport.claims(jwt);
        assertFalse(claims.containsKey("authorization_details"));
        assertFalse(claims.containsKey("workload"));
    }

    @Test
    void operatorClaimMirrorsMayActShape() throws Exception {
        // The operator names who ANSWERS for the client, distinct from the client (sub) and from any
        // principal it acts for. Shaped like RFC 8693 may_act so an AS can lift it straight in.
        String jwt = builder()
                .expiresIn(Duration.ofMinutes(5))
                .operator("ops-team@example.com", "https://op.example.com")
                .build();
        Map<String, Object> claims = JwtTestSupport.claims(jwt);
        @SuppressWarnings("unchecked")
        Map<String, Object> operator = (Map<String, Object>) claims.get("operator");
        assertEquals(Map.of("sub", "ops-team@example.com", "iss", "https://op.example.com"), operator);
        // Top-level, NOT tucked inside workload: workload describes the running software, the operator
        // is an accountability statement about who answers for it.
        @SuppressWarnings("unchecked")
        Map<String, Object> workload = (Map<String, Object>) claims.get("workload");
        assertTrue(workload == null || !workload.containsKey("operator"));
    }

    @Test
    void operatorIssuerIsOptional() throws Exception {
        String jwt = builder()
                .expiresIn(Duration.ofMinutes(5))
                .operator("ops-team@example.com", null)
                .build();
        Map<String, Object> claims = JwtTestSupport.claims(jwt);
        assertEquals(Map.of("sub", "ops-team@example.com"), claims.get("operator"));
    }

    @Test
    void operatorIsOmittedWhenNeverCalled() throws Exception {
        // Every existing caller must be byte-for-byte unaffected.
        String jwt = builder().expiresIn(Duration.ofMinutes(5)).build();
        Map<String, Object> claims = JwtTestSupport.claims(jwt);
        assertFalse(claims.containsKey("operator"));
    }

    @Test
    void operatorRequiresANonBlankSubject() {
        assertThrows(IllegalArgumentException.class, () -> builder().operator("", "https://op.example.com"));
        assertThrows(IllegalArgumentException.class, () -> builder().operator("   ", "https://op.example.com"));
        assertThrows(IllegalArgumentException.class, () -> builder().operator(null, "https://op.example.com"));
    }

    @Test
    void headerCarriesTypAlgAndAttesterKid() throws Exception {
        String jwt = builder().expiresIn(Duration.ofMinutes(5)).build();
        Map<String, Object> header = JwtTestSupport.header(jwt);
        assertEquals(ClientAttestationBuilder.TYP, header.get("typ"));
        assertEquals("ES256", header.get("alg"));
        assertEquals(ATTESTER_KEY.keyId(), header.get("kid"));
        assertNotNull(header.get("kid"));
    }
}
