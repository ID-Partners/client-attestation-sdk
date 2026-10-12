/*
 * Client for the Client Attestation issuance endpoint (POST /federation/attestation): a workload proves
 * its SPIFFE identity and the Authorization Server mints a Client Attestation bound to its instance key.
 */
package global.idpartners.clientattestation;

import global.idpartners.clientattestation.internal.HttpTransport;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.List;
import java.util.Map;
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
 *
 * <p>The mint protocol belongs to an {@link AttesterProfile}, by default {@link PingFederateProfile}. The
 * endpoint is given directly, so the profile's discovery is not used. See docs/attester-profiles.md.
 *
 * <p>The SVID is a bearer credential to the attester, so the endpoint, and every URL the profile calls, must
 * be https unless its host is loopback ({@code localhost}, {@code 127.0.0.1}, {@code ::1}) or
 * {@code allowInsecure} is set.
  *
  * <p><b>Experimental</b> (see docs/api.md): it calls a PingFederate demo issuance servlet
  * (/federation/attestation) whose protocol is not standardised.
 */
public final class AttestationIssuanceClient {

    /** Instance-key proof typ the PingFederate profile presents (server InstanceKeyProofValidator.TYP). */
    public static final String INSTANCE_PROOF_TYP = PingFederateProfile.INSTANCE_PROOF_TYP;

    private final String endpoint;
    private final String clientId;
    private final String attesterIssuer;   // the SVID audience AND the instance-proof aud
    private final SvidSource svidSource;
    private final SigningKeyPair instanceKey;
    private final AttesterProfile profile;
    private final boolean allowInsecure;
    static final Duration TIMEOUT = Duration.ofSeconds(20);
    private final HttpClient http = HttpTransport.client(TIMEOUT);

    public AttestationIssuanceClient(String endpoint, String clientId, String attesterIssuer, SvidSource svidSource) {
        this(endpoint, clientId, attesterIssuer, svidSource, SigningKeyPair.generate("ES256"));
    }

    public AttestationIssuanceClient(String endpoint, String clientId, String attesterIssuer,
                                     SvidSource svidSource, SigningKeyPair instanceKey) {
        this(endpoint, clientId, attesterIssuer, svidSource, instanceKey, new PingFederateProfile());
    }

    /**
     * A client whose mint request follows {@code profile} instead of the PingFederate protocol.
     *
     * @param endpoint       the attestation (mint) endpoint
     * @param clientId       the client id sent in the mint request
     * @param attesterIssuer the SVID audience and the instance proof's {@code aud}
     * @param svidSource     where the SVID comes from
     * @param instanceKey    the workload's instance key
     * @param profile        the attester profile that builds and sends the mint request
     * @throws ClientAttestation.ClientAttestationException if {@code endpoint} is not https and not loopback
     */
    public AttestationIssuanceClient(String endpoint, String clientId, String attesterIssuer,
                                     SvidSource svidSource, SigningKeyPair instanceKey, AttesterProfile profile) {
        this(endpoint, clientId, attesterIssuer, svidSource, instanceKey, profile, false);
    }

    /**
     * A client that, with {@code allowInsecure}, also accepts plain-http URLs on hosts that are not loopback,
     * for the endpoint and for every call the profile makes. The SVID then travels in cleartext.
     *
     * @param endpoint       the attestation (mint) endpoint
     * @param clientId       the client id sent in the mint request
     * @param attesterIssuer the SVID audience and the instance proof's {@code aud}
     * @param svidSource     where the SVID comes from
     * @param instanceKey    the workload's instance key
     * @param profile        the attester profile that builds and sends the mint request ({@code null}: PingFederate)
     * @param allowInsecure  allow plain http to hosts that are not loopback (default {@code false})
     */
    public AttestationIssuanceClient(String endpoint, String clientId, String attesterIssuer,
                                     SvidSource svidSource, SigningKeyPair instanceKey, AttesterProfile profile,
                                     boolean allowInsecure) {
        this.endpoint = endpoint.replaceAll("/+$", "");
        ClientAttestation.requireSecure(this.endpoint, "endpoint", allowInsecure);
        this.clientId = clientId;
        this.attesterIssuer = attesterIssuer;
        this.svidSource = svidSource;
        this.instanceKey = instanceKey;
        this.profile = profile != null ? profile : new PingFederateProfile();
        this.allowInsecure = allowInsecure;
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
        MintResult minted;
        try {
            minted = this.profile.mint(this::send,
                    new AttesterMetadata(this.attesterIssuer, this.endpoint, null, null, null, null),
                    new MintRequest(this.instanceKey, svid, challenge, this.clientId, authorizationDetails, null));
        } catch (ClientAttestation.ClientAttestationException e) {
            throw new IssuanceException("attestation issuance failed: " + e.getMessage(), e.status(), e);
        }
        if (minted == null || minted.attestation() == null || minted.attestation().isBlank()) {
            throw new IssuanceException("attestation issuance failed: attester response contained no attestation",
                    0, null);
        }
        return new IssuedAttestation(minted.attestation(), minted.expiresIn(), this.instanceKey);
    }

    /**
     * The issuance endpoint's transport: the https rule, and a non-2xx answer or a transport failure is an
     * IssuanceException.
     */
    private Map<String, Object> send(String step, String method, String url, Map<String, Object> body) {
        ClientAttestation.requireSecure(url, step + " URL", this.allowInsecure);
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(body)));
        try {
            HttpTransport.Response resp = HttpTransport.send(this.http, request, TIMEOUT);
            if (!resp.ok()) {
                throw new IssuanceException(resp.status(), resp.body());
            }
            return HttpTransport.jsonOk(resp);
        } catch (TransportException e) {
            throw new IssuanceException("attestation issuance failed: " + e.getMessage(), e.status(), e);
        }
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
