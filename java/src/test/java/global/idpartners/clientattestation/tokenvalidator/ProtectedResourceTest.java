package global.idpartners.clientattestation.tokenvalidator;

import static global.idpartners.clientattestation.tokenvalidator.Fixtures.b64;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

/** RFC 9728 metadata, RFC 6750 bearer extraction and challenges, and the request guard. */
class ProtectedResourceTest {

    private static final Map<String, Object> V = Fixtures.vectors();
    private static final String RESOURCE = (String) V.get("audience");
    private static final String AS = (String) V.get("issuer");

    private static AccessTokenValidator validator(String... audiences) {
        ValidatorConfig.Builder b = Fixtures.vectorConfig(V);
        if (audiences.length > 0) {
            b.audiences(audiences);
        }
        return new AccessTokenValidator(b.build());
    }

    private static ProtectedResource fixture() {
        return new ProtectedResource(RESOURCE, List.of(AS), validator(), List.of("read", "write"));
    }

    private static boolean hasControl(String s) {
        return s.chars().anyMatch(c -> c < 0x20 || c == 0x7f);
    }

    @Test
    void bearerToken() {
        assertEquals("abc.def", ProtectedResource.bearerToken("Bearer abc.def"));
        assertEquals("abc", ProtectedResource.bearerToken("bearer abc"));
        assertEquals("abc", ProtectedResource.bearerToken("  BEARER   abc  "));
        assertNull(ProtectedResource.bearerToken("Basic abc"));
        assertNull(ProtectedResource.bearerToken(""));
        assertNull(ProtectedResource.bearerToken("Bearer "));
        assertNull(ProtectedResource.bearerToken(null));
    }

    @Test
    void metadata() {
        ProtectedResource pr = fixture();
        Map<String, Object> md = pr.metadata();
        assertEquals(RESOURCE, md.get("resource"));
        assertEquals(List.of(AS), md.get("authorization_servers"));
        assertEquals(List.of("header"), md.get("bearer_methods_supported"));
        assertEquals(List.of("read", "write"), md.get("scopes_supported"));
        assertEquals("/.well-known/oauth-protected-resource", pr.metadataPath());
        assertEquals("https://api.example.com/.well-known/oauth-protected-resource", pr.metadataUrl());
        assertTrue(pr.metadataJson().contains("\"bearer_methods_supported\":[\"header\"]"), pr.metadataJson());
        assertEquals(RESOURCE, pr.resource());
        assertEquals(List.of(AS), pr.authorizationServers());
        assertEquals(List.of("read", "write"), pr.scopesSupported());
    }

    @Test
    void metadataLeavesOutEmptyScopes() {
        ProtectedResource pr = new ProtectedResource(RESOURCE, null, validator());
        assertFalse(pr.metadata().containsKey("scopes_supported"));
        assertEquals(List.of(), pr.metadata().get("authorization_servers"));
    }

    @Test
    void metadataPathWithResourcePathAndPort() {
        ProtectedResource pr = new ProtectedResource("https://mcp.example.com:8443/mcp", List.of(AS),
                validator("https://mcp.example.com:8443/mcp"));
        assertEquals("/.well-known/oauth-protected-resource/mcp", pr.metadataPath());
        assertEquals("https://mcp.example.com:8443/.well-known/oauth-protected-resource/mcp", pr.metadataUrl());
        ProtectedResource slash = new ProtectedResource("https://mcp.example.com/", List.of(AS),
                validator("https://mcp.example.com/"));
        assertEquals("/.well-known/oauth-protected-resource", slash.metadataPath());
    }

    @Test
    void metadataPathsForUnparseableResource() {
        ProtectedResource pr = new ProtectedResource("://bad", List.of(AS), validator("://bad"));
        assertEquals("/.well-known/oauth-protected-resource", pr.metadataPath());
        assertEquals("/.well-known/oauth-protected-resource", pr.metadataUrl());
        ProtectedResource relative = new ProtectedResource("relative", List.of(AS), validator("relative"));
        assertEquals("/.well-known/oauth-protected-resourcerelative", relative.metadataPath());
        assertEquals(relative.metadataPath(), relative.metadataUrl());
    }

    @Test
    void refusesAValidatorForAnotherAudience() {
        assertThrows(IllegalArgumentException.class,
                () -> new ProtectedResource("https://other.example.com", List.of(AS), validator()));
    }

    @Test
    void authenticateValid() {
        AuthDecision d = fixture().authenticate("Bearer " + Fixtures.tokenNamed(V, "valid"));
        assertTrue(d.authorized());
        assertEquals(200, d.status());
        assertEquals("agent-1", d.result().subject());
        assertNull(d.wwwAuthenticate());
        assertNull(d.error());
        assertNull(d.errorDescription());
    }

    @Test
    void authenticateMissingToken() {
        AuthDecision d = fixture().authenticate(null);
        assertFalse(d.authorized());
        assertEquals(401, d.status());
        assertNull(d.result());
        assertNull(d.error());
        assertEquals("authentication required", d.errorDescription());
        assertEquals("Bearer resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource\"",
                d.wwwAuthenticate());
    }

    @Test
    void authenticateExpiredAndWrongAudienceAre401() {
        AuthDecision expired = fixture().authenticate("Bearer " + Fixtures.tokenNamed(V, "expired"));
        assertEquals(401, expired.status());
        assertEquals("invalid_token", expired.error());
        assertEquals(ErrorCodes.EXPIRED, expired.result().error());
        assertTrue(expired.wwwAuthenticate().startsWith(
                "Bearer error=\"invalid_token\", error_description=\"token has expired\", resource_metadata="));
        AuthDecision aud = fixture().authenticate("Bearer " + Fixtures.tokenNamed(V, "wrong_audience"));
        assertEquals(401, aud.status());
        assertEquals(ErrorCodes.INVALID_AUDIENCE, aud.result().error());
    }

    @Test
    void authenticateInsufficientScopeIs403() {
        AuthDecision d = fixture().authenticate("Bearer " + Fixtures.tokenNamed(V, "valid"), List.of("read", "admin"));
        assertEquals(403, d.status());
        assertEquals("insufficient_scope", d.error());
        assertTrue(d.wwwAuthenticate().contains("error=\"insufficient_scope\""));
        assertEquals("missing scopes: admin", d.errorDescription());
    }

    // ── header safety ───────────────────────────────────────────────────────────────────────────────

    @Test
    void quoteStripsEveryControlCharacterAndEscapes() {
        StringBuilder controls = new StringBuilder();
        for (char c = 0; c < 0x20; c++) {
            controls.append(c);
        }
        controls.append('\u007f');
        assertEquals("ab", ProtectedResource.quote("a" + controls + "b"));
        assertEquals("say \\\"hi\\\" \\\\ bye", ProtectedResource.quote("say \"hi\" \\ bye"));
        assertEquals("line1Set-Cookie: x", ProtectedResource.quote("line1\r\nSet-Cookie: x"));
        assertEquals("café  tab", ProtectedResource.quote("café \t tab"));
    }

    @Test
    void challengeNeverContainsControlCharacters() {
        String header = fixture().challenge("invalid\r\n_token", "bad\r\nX-Injected: yes\u0000\u001f\u007f \"q\" \\ end");
        assertFalse(hasControl(header), header);
        assertTrue(header.contains("error=\"invalid_token\""), header);
        assertTrue(header.contains("error_description=\"badX-Injected: yes \\\"q\\\" \\\\ end\""), header);
        assertTrue(header.endsWith(
                "resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource\""), header);
        assertEquals(fixture().challenge(null, null), fixture().challenge("", "ignored without an error"));
        assertFalse(fixture().challenge("invalid_token", "").contains("error_description"));
    }

    @Test
    void authenticateEndToEndKeepsTheHeaderClean() {
        String mark = JsonUtil.toJson(Map.of("alg", "EVIL\r\nX-Injected: 1\u0000\u007f\""));
        AuthDecision d = fixture().authenticate("Bearer " + b64(mark) + "." + b64("{}") + ".sig");
        assertEquals(401, d.status());
        assertEquals("algorithm not accepted", d.errorDescription());
        assertFalse(d.wwwAuthenticate().contains("EVIL"));
        assertFalse(hasControl(d.wwwAuthenticate()));
    }
}
