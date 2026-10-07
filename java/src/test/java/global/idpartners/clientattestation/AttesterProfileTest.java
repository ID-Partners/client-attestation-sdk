package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Attester profiles: the default PingFederate profile, static metadata (no discovery), and a custom profile
 * for a made-up attester whose discovery path, proof typ and mint request/response all differ.
 */
class AttesterProfileTest {

    private static final String ATTESTATION = "e30." + Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"sub\":\"client-1\"}".getBytes(StandardCharsets.UTF_8)) + ".sig";

    private StubHttpServer server;
    private final List<String> seen = Collections.synchronizedList(new ArrayList<>());

    @BeforeEach
    void start() throws Exception {
        this.server = new StubHttpServer();
        String base = this.server.url("");
        answer("/.well-known/client-attester", 200, "{\"evidence_audience\":\"" + base + "\",\"attestation_endpoint\":\""
                + base + "/pf/mint\",\"token_endpoint\":\"" + base + "/token\"}");
        answer("/acme/config", 200, "{\"audience\":\"acme-aud\",\"mint_url\":\"" + base
                + "/acme/mint\",\"token_url\":\"" + base + "/token\"}");
        answer("/pf/mint", 200, "{\"attestation\":\"" + ATTESTATION + "\",\"expires_in\":600}");
        answer("/acme/mint", 200, "{\"client_attestation\":\"" + ATTESTATION + "\",\"ttl\":300}");
        this.server.route("/token", exchange -> {
            this.seen.add("/token");
            boolean ok = ATTESTATION.equals(exchange.getRequestHeaders().getFirst("OAuth-Client-Attestation"))
                    && exchange.getRequestHeaders().getFirst("OAuth-Client-Attestation-PoP") != null;
            StubHttpServer.send(exchange, ok ? 200 : 401,
                    ok ? "{\"access_token\":\"at-1\",\"expires_in\":60}" : "{\"error\":\"invalid_client\"}");
        });
    }

    private void answer(String path, int status, String body) {
        this.server.route(path, exchange -> {
            this.seen.add(path);
            StubHttpServer.send(exchange, status, body);
        });
    }

    @AfterEach
    void stop() {
        this.server.close();
    }

    private Map<String, Object> body(String path) throws Exception {
        return JsonUtil.parseJson(this.server.lastBodies.get(path));
    }

    /** A non-PingFederate attester: its own discovery path and fields, proof typ, and mint shapes. */
    static class AcmeProfile implements AttesterProfile {
        @Override
        public AttesterMetadata discover(AttesterTransport transport, String attesterUrl) throws Exception {
            Map<String, Object> doc = transport.requestJson("discover", "GET", attesterUrl + "/acme/config", null);
            return new AttesterMetadata((String) doc.get("audience"), (String) doc.get("mint_url"),
                    (String) doc.get("token_url"), null, null, doc);
        }

        @Override
        public MintResult mint(AttesterTransport transport, AttesterMetadata metadata, MintRequest request)
                throws Exception {
            String pop = request.instanceProof("acme-key-proof+jwt", "acme");
            Map<String, Object> res = transport.requestJson("mint", "POST", metadata.attestationEndpoint(),
                    Map.of("evidence", request.evidence(), "key", request.instanceKey().publicJwk(), "pop", pop));
            return new MintResult((String) res.get("client_attestation"), ((Number) res.get("ttl")).longValue());
        }
    }

    @Test
    void defaultProfileIsPingFederate() throws Exception {
        ClientAttestation ca = ClientAttestation.builder(this.server.url("")).evidence(new SvidSource.Static("svid"))
                .build();
        assertEquals("at-1", ca.token());
        assertEquals(List.of("/.well-known/client-attester", "/pf/mint", "/token"), this.seen);
        Map<String, Object> body = body("/pf/mint");
        assertEquals(List.of("instance_key", "svid", "proof"), new ArrayList<>(body.keySet()));
        String proof = (String) body.get("proof");
        assertEquals("oauth-attestation-instance-proof+jwt", JwtTestSupport.header(proof).get("typ"));
        assertEquals(PingFederateProfile.INSTANCE_PROOF_TYP, JwtTestSupport.header(proof).get("typ"));
        assertEquals(this.server.url(""), JwtTestSupport.claims(proof).get("aud"));
    }

    @Test
    void customProfileGetsATokenEndToEnd() throws Exception {
        ClientAttestation ca = ClientAttestation.builder(this.server.url("")).evidence(new SvidSource.Static("svid"))
                .profile(new AcmeProfile()).build();
        assertEquals("at-1", ca.token());
        assertEquals(List.of("/acme/config", "/acme/mint", "/token"), this.seen);
        Map<String, Object> body = body("/acme/mint");
        assertEquals("svid", body.get("evidence"));
        String pop = (String) body.get("pop");
        assertEquals("acme-key-proof+jwt", JwtTestSupport.header(pop).get("typ"));
        assertEquals("acme", JwtTestSupport.claims(pop).get("aud"));
        assertEquals("acme-aud", ca.discovery().get("audience"));
    }

    @Test
    void staticMetadataSkipsDiscoveryAndMintsWithTheDefaultProtocol() throws Exception {
        AttesterMetadata meta = AttesterMetadata.of("aud-1", this.server.url("/pf/mint"), this.server.url("/token"));
        ClientAttestation ca = ClientAttestation.builder().metadata(meta).evidence(new SvidSource.Static("svid"))
                .build();
        assertEquals("at-1", ca.token());
        assertEquals(List.of("/pf/mint", "/token"), this.seen);
        String proof = (String) body("/pf/mint").get("proof");
        assertEquals("oauth-attestation-instance-proof+jwt", JwtTestSupport.header(proof).get("typ"));
        assertEquals("aud-1", JwtTestSupport.claims(proof).get("aud"));
        assertEquals(Map.of("evidence_audience", "aud-1", "attestation_endpoint", this.server.url("/pf/mint"),
                "token_endpoint", this.server.url("/token")), ca.discovery());
    }

    @Test
    void staticMetadataWithACustomProfileNeverDiscovers() throws Exception {
        AttesterMetadata meta = AttesterMetadata.of("aud-1", this.server.url("/acme/mint"), this.server.url("/token"))
                .withChallengeEndpoint(null).withPopAudience("https://as.example");
        ClientAttestation ca = ClientAttestation.builder().attesterUrl(this.server.url("")).metadata(meta)
                .profile(new AcmeProfile()).evidence(new SvidSource.Static("svid")).build();
        assertEquals("at-1", ca.token());
        assertEquals(List.of("/acme/mint", "/token"), this.seen);
        assertEquals("https://as.example", ca.attesterMetadata().popAudience());
    }

    @Test
    void staticMetadataNeedsATokenEndpointAndHttps() {
        ClientAttestation noToken = ClientAttestation.builder()
                .metadata(AttesterMetadata.of("a", this.server.url("/pf/mint"), null))
                .evidence(new SvidSource.Static("svid")).build();
        assertTrue(assertThrows(ClientAttestation.ClientAttestationException.class, noToken::token).getMessage()
                .contains("no token_endpoint"));
        ClientAttestation insecure = ClientAttestation.builder()
                .metadata(AttesterMetadata.of("a", "http://attester.example/mint", "https://as.example/t"))
                .evidence(new SvidSource.Static("svid")).build();
        assertTrue(assertThrows(ClientAttestation.ClientAttestationException.class, insecure::token).getMessage()
                .contains("attestation_endpoint must use https"));
        AttesterProfile odd = new AcmeProfile() {
            @Override
            public AttesterMetadata discover(AttesterTransport transport, String attesterUrl) throws Exception {
                transport.requestJson("lookup", "GET", "http://attester.example/x", null);
                return null;
            }
        };
        ClientAttestation oddClient = ClientAttestation.builder("https://attester.example").profile(odd).build();
        assertTrue(assertThrows(ClientAttestation.ClientAttestationException.class, oddClient::discovery)
                .getMessage().contains("lookup URL must use https"));
    }

    @Test
    void attesterUrlIsRequiredWithoutMetadataOrProfile() {
        assertEquals("attesterUrl is required",
                assertThrows(IllegalArgumentException.class, () -> ClientAttestation.builder().build()).getMessage());
        ClientAttestation pf = ClientAttestation.builder().profile(new PingFederateProfile()).build();
        assertTrue(assertThrows(IllegalArgumentException.class, pf::discovery).getMessage()
                .contains("attesterUrl is required"));
    }

    @Test
    void profileReturningNothingIsAnError() {
        AttesterProfile nothing = new AttesterProfile() {
            @Override
            public AttesterMetadata discover(AttesterTransport transport, String attesterUrl) {
                return null;
            }

            @Override
            public MintResult mint(AttesterTransport transport, AttesterMetadata metadata, MintRequest request) {
                return null;
            }
        };
        assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> ClientAttestation.builder("https://attester.example").profile(nothing).build().discovery());
        ClientAttestation ca = ClientAttestation.builder().profile(nothing).evidence(new SvidSource.Static("svid"))
                .metadata(AttesterMetadata.of("a", null, "https://as.example/t")).build();
        assertTrue(assertThrows(ClientAttestation.ClientAttestationException.class, ca::token).getMessage()
                .contains("no attestation"));
    }

    @Test
    void pingFederateProfileEdges() throws Exception {
        PingFederateProfile pf = new PingFederateProfile();
        AttesterMetadata meta = pf.discover((s, m, u, b) -> Map.of("evidence_audience", "aud"), "https://pf.example");
        assertEquals("https://pf.example/as/token.oauth2", meta.tokenEndpoint());
        assertEquals(Map.of("evidence_audience", "aud"), meta.asDocument());
        assertThrows(IllegalArgumentException.class, () -> pf.discover((s, m, u, b) -> Map.of(), " "));
        MintRequest request = new MintRequest(SigningKeyPair.generate("ES256"), "svid", null, "c",
                List.of(Map.of("type", "x")), Map.of("sub", "op"));
        assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> pf.mint((s, m, u, b) -> Map.of(), AttesterMetadata.of("a", " ", "t"), request));
        MintResult minted = pf.mint((s, m, u, b) -> {
            assertEquals(List.of("client_id", "instance_key", "svid", "proof", "authorization_details", "operator"),
                    new ArrayList<>(b.keySet()));
            return Map.of("attestation", "h.p.s", "expires_in", "soon");
        }, AttesterMetadata.of("a", "https://x", "t"), request);
        assertEquals("h.p.s", minted.attestation());
        assertNull(minted.expiresIn());
    }

    @Test
    void issuanceClientTakesACustomProfile() throws Exception {
        AttestationIssuanceClient client = new AttestationIssuanceClient(this.server.url("/acme/mint"), "client-1",
                "https://attester.example", new SvidSource.Static("svid"), SigningKeyPair.generate("ES256"),
                new AcmeProfile());
        AttestationIssuanceClient.IssuedAttestation issued = client.bootstrap(null, null);
        assertEquals(ATTESTATION, issued.attestation());
        assertEquals(300L, issued.expiresIn());
        assertEquals("acme-key-proof+jwt", JwtTestSupport.header((String) body("/acme/mint").get("pop")).get("typ"));

        AttesterProfile getter = new AcmeProfile() {
            @Override
            public MintResult mint(AttesterTransport transport, AttesterMetadata metadata, MintRequest request)
                    throws Exception {
                Map<String, Object> doc = transport.requestJson("x", "GET", metadata.attestationEndpoint(), null);
                return new MintResult(ATTESTATION, ((Number) doc.get("expires_in")).longValue());
            }
        };
        AttestationIssuanceClient viaGet = new AttestationIssuanceClient(this.server.url("/pf/mint"), "c",
                "https://attester.example", new SvidSource.Static("svid"), SigningKeyPair.generate("ES256"), getter);
        assertEquals(600L, viaGet.bootstrap(null, null).expiresIn());
        AttestationIssuanceClient defaulted = new AttestationIssuanceClient(this.server.url("/pf/mint"), "c",
                "https://attester.example", new SvidSource.Static("svid"), SigningKeyPair.generate("ES256"), null);
        assertEquals(ATTESTATION, defaulted.bootstrap(null, null).attestation());
    }
}
