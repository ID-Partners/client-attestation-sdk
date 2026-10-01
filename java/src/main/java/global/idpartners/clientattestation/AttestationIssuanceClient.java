/*
 * Client for the Client Attestation issuance endpoint (POST /federation/attestation): a workload proves
 * its SPIFFE identity and the Authorization Server mints a Client Attestation bound to its instance key.
 */
package global.idpartners.clientattestation;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.json.JsonUtil;

/**
 * The inverse of {@link ClientAttestationBuilder}: instead of building an attestation locally with an
 * attester key, a workload proves its SPIFFE identity (a JWT-SVID) and PingFederate validates it and
 * <strong>mints</strong> a Client Attestation bound to the workload's own instance key — bootstrapping a
 * client credential from infra identity, no pre-shared secret.
 *
 * <pre>{@code
 * var client = new AttestationIssuanceClient(
 *         "https://pf.example/federation/attestation", "https://payment-agent.example",
 *         "https://attester.example", new SvidSource.SpireWorkloadApi());
 * IssuedAttestation issued = client.bootstrap(
 *         List.of(Map.of("type", "sales_agent", "sales_regions", List.of("EMEA"))), null);
 * // issued.attestation()       -> OAuth-Client-Attestation header
 * // issued.pop(aud, id, chal)  -> OAuth-Client-Attestation-PoP header (fresh, bound to the instance key)
 * // issued.dpop(m, uri, chal)  -> DPoP header, for PoP method dpop_combined
 * }</pre>
 */
public final class AttestationIssuanceClient {

    /** Instance-key proof typ presented at the issuance endpoint (server InstanceKeyProofValidator.TYP). */
    public static final String INSTANCE_PROOF_TYP = "oauth-attestation-instance-proof+jwt";

    private final String endpoint;
    private final String clientId;
    private final String attesterIssuer;   // the SVID audience AND the instance-proof aud
    private final SvidSource svidSource;
    private final SigningKeyPair instanceKey;
    static final Duration TIMEOUT = Duration.ofSeconds(20);
    private final HttpClient http = HttpTransport.client(TIMEOUT);

    public AttestationIssuanceClient(String endpoint, String clientId, String attesterIssuer, SvidSource svidSource) {
        this(endpoint, clientId, attesterIssuer, svidSource, SigningKeyPair.generate("ES256"));
    }

    public AttestationIssuanceClient(String endpoint, String clientId, String attesterIssuer,
                                     SvidSource svidSource, SigningKeyPair instanceKey) {
        this.endpoint = endpoint.replaceAll("/+$", "");
        this.clientId = clientId;
        this.attesterIssuer = attesterIssuer;
        this.svidSource = svidSource;
        this.instanceKey = instanceKey;
    }

    /** The workload's instance key (bound into the minted attestation's cnf; signs PoPs). */
    public SigningKeyPair instanceKey() {
        return this.instanceKey;
    }

    /**
     * Fetch the SVID, prove possession of the instance key, and exchange them for a minted attestation.
     *
     * @param authorizationDetails optional RFC 9396 entries to request (may be {@code null})
     * @param challenge            optional issuance challenge (may be {@code null})
     */
    public IssuedAttestation bootstrap(List<Map<String, Object>> authorizationDetails, String challenge)
            throws Exception {
        String svid = this.svidSource.fetch(this.attesterIssuer);

        Map<String, Object> proofClaims = new LinkedHashMap<>();
        proofClaims.put("aud", this.attesterIssuer);
        proofClaims.put("jti", UUID.randomUUID().toString());
        proofClaims.put("iat", System.currentTimeMillis() / 1000L);
        if (challenge != null && !challenge.isEmpty()) {
            proofClaims.put("challenge", challenge);
        }
        String proof = Jws.sign(JsonUtil.toJson(proofClaims), this.instanceKey, INSTANCE_PROOF_TYP, false);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("client_id", this.clientId);
        body.put("instance_key", this.instanceKey.publicJwk());
        body.put("svid", svid);
        body.put("proof", proof);
        if (authorizationDetails != null && !authorizationDetails.isEmpty()) {
            body.put("authorization_details", authorizationDetails);
        }

        HttpTransport.Response resp;
        Map<String, Object> parsed;
        try {
            resp = HttpTransport.send(this.http, HttpRequest.newBuilder(URI.create(this.endpoint))
                    .header("Content-Type", "application/json").header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(body))), TIMEOUT);
            if (!resp.ok()) {
                throw new IssuanceException(resp.status(), resp.body());
            }
            parsed = HttpTransport.jsonOk(resp);
        } catch (TransportException e) {
            throw new IssuanceException("attestation issuance failed: " + e.getMessage(), e.status(), e);
        }
        if (!(parsed.get("attestation") instanceof String attestation) || attestation.isBlank()) {
            throw new IssuanceException("attestation issuance failed: response carried no attestation",
                    resp.status(), null);
        }
        Object expiresIn = parsed.get("expires_in");
        return new IssuedAttestation(attestation,
                expiresIn instanceof Number ? ((Number) expiresIn).longValue() : null, this.instanceKey);
    }

    /** A minted Client Attestation plus the instance key it is bound to. */
    public static final class IssuedAttestation {
        private final String attestation;
        private final Long expiresIn;
        private final SigningKeyPair instanceKey;

        IssuedAttestation(String attestation, Long expiresIn, SigningKeyPair instanceKey) {
            this.attestation = attestation;
            this.expiresIn = expiresIn;
            this.instanceKey = instanceKey;
        }

        public String attestation() {
            return this.attestation;
        }

        public Long expiresIn() {
            return this.expiresIn;
        }

        public SigningKeyPair instanceKey() {
            return this.instanceKey;
        }

        /**
         * A fresh Client Attestation PoP for the token endpoint, signed by the bound instance key.
         *
         * @param audience  the AS identifier (PoP {@code aud}); required
         * @param clientId  the client id (PoP {@code iss}); may be null to omit
         * @param challenge the server challenge, or null
         */
        public String pop(String audience, String clientId, String challenge) {
            PopBuilder builder = new PopBuilder(this.instanceKey).audience(audience);
            if (clientId != null) {
                builder.clientId(clientId);
            }
            if (challenge != null) {
                builder.challenge(challenge);
            }
            return builder.build();
        }

        /**
         * A fresh DPoP proof (RFC 9449) for attestation combined mode (PoP method {@code dpop_combined}),
         * signed by the bound instance key; its embedded {@code jwk} header is that same instance key.
         *
         * @param method    the token request HTTP method (DPoP {@code htm})
         * @param uri       the token endpoint URL (DPoP {@code htu}); required
         * @param challenge the server challenge (DPoP {@code nonce}), or null
         */
        public String dpop(String method, String uri, String challenge) {
            return new DpopProofBuilder(this.instanceKey).method(method).uri(uri).nonce(challenge).build();
        }
    }

    /**
     * Thrown when the issuance endpoint rejects the request (non-2xx), or the call fails in transport
     * (timeout, I/O error, refused redirect, oversize or unparseable response — {@link #status()} is then
     * the HTTP status if one was received, else 0, and the cause is a {@link TransportException}).
     */
    public static final class IssuanceException extends RuntimeException {
        private final int status;

        IssuanceException(int status, String body) {
            super("attestation issuance failed: HTTP " + status + ": " + HttpTransport.truncate(body));
            this.status = status;
        }

        IssuanceException(String message, int status, Throwable cause) {
            super(message, cause);
            this.status = status;
        }

        public int status() {
            return this.status;
        }
    }
}
