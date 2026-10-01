package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link AttestationIssuanceClient.IssuedAttestation}'s post-issuance proof methods ({@code pop}
 * and its DPoP-combined sibling {@code dpop}) — both mint a fresh proof signed by the instance key the
 * issuance endpoint bound into the attestation's {@code cnf}, so a workload can call the token endpoint
 * without re-running bootstrap. Mirrors {@code python/tests/test_issuance.py}.
 */
class AttestationIssuanceClientTest {

    private static final String TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2";
    private static final String CLIENT_ID = "https://rp.example.com";

    private static AttestationIssuanceClient.IssuedAttestation issued() {
        SigningKeyPair instanceKey = SigningKeyPair.generate("ES256");
        return new AttestationIssuanceClient.IssuedAttestation("h.attestation.sig", 300L, instanceKey);
    }

    @Test
    void popBuildsAPopJwtWithAudienceClientIdAndChallenge() throws Exception {
        String pop = issued().pop(TOKEN_ENDPOINT, CLIENT_ID, "as-issued-challenge");
        Map<String, Object> claims = JwtTestSupport.claims(pop);
        assertEquals(TOKEN_ENDPOINT, claims.get("aud"));
        assertEquals(CLIENT_ID, claims.get("iss"));
        assertEquals("as-issued-challenge", claims.get("challenge"));
    }

    @Test
    void popOmitsOptionalClaimsWhenNotGiven() throws Exception {
        String pop = issued().pop(TOKEN_ENDPOINT, null, null);
        Map<String, Object> claims = JwtTestSupport.claims(pop);
        assertEquals(TOKEN_ENDPOINT, claims.get("aud"));
        assertFalse(claims.containsKey("iss"));
        assertFalse(claims.containsKey("challenge"));
    }

    @Test
    void dpopBuildsADpopProofWithMethodUriAndNonce() throws Exception {
        String dpop = issued().dpop("POST", TOKEN_ENDPOINT, "as-issued-challenge");
        Map<String, Object> claims = JwtTestSupport.claims(dpop);
        assertEquals("POST", claims.get("htm"));
        assertEquals(TOKEN_ENDPOINT, claims.get("htu"));
        assertEquals("as-issued-challenge", claims.get("nonce"));
    }

    @Test
    void dpopOmitsNonceWhenNoChallengeGiven() throws Exception {
        String dpop = issued().dpop("POST", TOKEN_ENDPOINT, null);
        assertNull(JwtTestSupport.claims(dpop).get("nonce"));
    }

    @Test
    void dpopIsBoundToTheSameInstanceKeyAsPop() throws Exception {
        // Both proofs must be signed by (and, for DPoP, embed the public half of) the SAME instance key
        // the issuance endpoint bound into the attestation's cnf — that's the whole point of
        // dpop_combined: it lets a token endpoint verify possession without a PoP JWT.
        AttestationIssuanceClient.IssuedAttestation issued = issued();
        String pop = issued.pop(TOKEN_ENDPOINT, null, null);
        String dpop = issued.dpop("POST", TOKEN_ENDPOINT, null);
        Map<String, Object> dpopHeader = JwtTestSupport.header(dpop);
        assertEquals(issued.instanceKey().publicJwk(), dpopHeader.get("jwk"));
        // A PoP JWT doesn't embed the jwk (the AS already has it from the attestation's cnf) — sanity
        // check the two proofs are otherwise independent per-call mints (different jti).
        assertNotEquals(JwtTestSupport.claims(pop).get("jti"), JwtTestSupport.claims(dpop).get("jti"));
    }
}
