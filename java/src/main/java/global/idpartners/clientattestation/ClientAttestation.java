/*
 * One call to get an access token with client attestation.
 *
 * Point it at a PingFederate host and call {@link #token()}. It runs the whole flow:
 *
 *   discover -> get platform identity (evidence) -> get a challenge -> mint the attestation ->
 *   call the token endpoint with the attestation headers -> cache the access token
 *
 * The workload sends no client secret and no client_id. Its only credential is the attestation, built
 * from the identity its runtime already gives it (auto-detected; see {@link Evidence}).
 */
package global.idpartners.clientattestation;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
import org.jose4j.json.JsonUtil;

/**
 * Gets and caches an access token from a PingFederate host using client attestation — the whole flow in
 * one call, no client secret and no {@code client_id} sent.
 *
 * <pre>{@code
 * ClientAttestation ca = new ClientAttestation("pf.example.com");
 * String token = ca.token();                       // cached until it nears expiry
 *
 * // send a request to a resource (Bearer or DPoP-bound token; DPoP nonce challenges retried once):
 * HttpResponse<String> resp = ca.send(httpClient, HttpRequest.newBuilder(uri).GET(), "GET", uri,
 *         HttpResponse.BodyHandlers.ofString());
 *
 * // ...or take the headers for any HTTP client:
 * Map<String, String> headers = ca.requestHeaders("GET", api);  // Authorization (+ DPoP proof if bound)
 * }</pre>
 *
 * <p>Fails closed: when the attester advertises a {@code challenge_endpoint} and the challenge cannot be
 * fetched, the flow fails (opt out with {@link Builder#requireChallenge(boolean)}); and the host and every
 * endpoint taken from discovery must be https unless the host is loopback or
 * {@link Builder#allowInsecure(boolean)} is set.
 */
public final class ClientAttestation {

    /** draft-ietf-oauth-attestation-based-client-auth revision this SDK implements. */
    public static final String DRAFT_REVISION = "10";

    static final String ATTESTATION_HEADER = "OAuth-Client-Attestation";
    static final String POP_HEADER = "OAuth-Client-Attestation-PoP";
    static final String DPOP_HEADER = "DPoP";
    static final String DPOP_NONCE_HEADER = "DPoP-Nonce";
    static final String INSTANCE_PROOF_TYP = "oauth-attestation-instance-proof+jwt";
    static final String WELL_KNOWN_PATH = "/.well-known/client-attester";
    /** Default PoP method: a dedicated {@code OAuth-Client-Attestation-PoP} JWT. */
    static final String DEFAULT_POP_METHOD = "attestation_pop_jwt";
    /** PoP method that sends a single DPoP proof (RFC 9449) instead of a separate PoP JWT. */
    static final String DPOP_COMBINED_POP_METHOD = "dpop_combined";
    /** Refresh this many seconds before the token actually expires, so a token is never used at the edge. */
    static final int DEFAULT_EXPIRY_SKEW_SECONDS = 30;

    private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "::1", "[::1]");
    private static final Pattern DPOP_SCHEME = Pattern.compile("(?i)(?:^|[,\\s])DPoP(?:\\s|,|$)");
    private static final Pattern USE_DPOP_NONCE = Pattern.compile("(?i)error\\s*=\\s*\"?use_dpop_nonce\\b");

    private final String baseUrl;
    private final SvidSource evidence;                       // null => auto-detect at flow time
    private final List<Map<String, Object>> authorizationDetails;
    private final Map<String, Object> operator;              // null/empty => not sent
    private final boolean challengeAtToken;
    private final String algorithm;
    private final String popMethod;
    private final int skewSeconds;
    private final Duration timeout;
    private final boolean requireChallenge;
    private final boolean allowInsecure;
    private final HttpClient http;

    private final Object lock = new Object();
    private String cachedToken;
    private String cachedTokenType;
    private SigningKeyPair cachedKey;                        // the instance key bound to cachedToken
    private long expiresAt;                                  // epoch seconds; 0 => no cache
    private Map<String, Object> discovery;
    /** Last {@code DPoP-Nonce} each resource origin returned. */
    private final Map<String, String> dpopNonces = new ConcurrentHashMap<>();

    /**
     * @param pfHost the PingFederate host — {@code "pf.example.com"}, or a full base URL
     *               {@code "https://pf.example.com"}. Plain hostnames default to https.
     * @throws ClientAttestationException if the host is not https and not loopback
     */
    public ClientAttestation(String pfHost) {
        this(new Builder(pfHost));
    }

    private ClientAttestation(Builder b) {
        this.baseUrl = normalizeBaseUrl(b.pfHost);
        this.evidence = b.evidence;
        this.authorizationDetails = b.authorizationDetails;
        this.operator = b.operator;
        this.challengeAtToken = b.challengeAtToken;
        this.algorithm = b.algorithm;
        this.popMethod = b.popMethod;
        this.skewSeconds = b.expirySkewSeconds;
        this.timeout = b.timeout;
        this.requireChallenge = b.requireChallenge;
        this.allowInsecure = b.allowInsecure;
        requireSecure(this.baseUrl, "pf_host", this.allowInsecure);
        this.http = HttpTransport.client(b.timeout);
    }

    public static Builder builder(String pfHost) {
        return new Builder(pfHost);
    }

    // ── public API ──────────────────────────────────────────────────────────────────────────────────

    /** A valid access token, minting a new one only when the cached one is near expiry. */
    public String token() {
        return token(false);
    }

    /** As {@link #token()}, but {@code forceRefresh} always mints a fresh token. */
    public String token(boolean forceRefresh) {
        return current(forceRefresh).token();
    }

    /**
     * {@code {"Authorization": "<scheme> <token>"}} — for any HTTP client. The scheme is {@code Bearer},
     * or {@code DPoP} when the AS issued a DPoP-bound token; a DPoP-bound token also needs a fresh
     * {@code DPoP} proof on every request, which this method does not make — use
     * {@link #requestHeaders(String, String)} for that.
     */
    public Map<String, String> authorizationHeader() {
        Map<String, String> headers = new LinkedHashMap<>();
        TokenState state = current(false);
        headers.put("Authorization", state.scheme() + " " + state.token());
        return headers;
    }

    /**
     * The headers to send with a request to a resource: {@code {"Authorization": "Bearer <t>"}} for a
     * Bearer token, or {@code {"Authorization": "DPoP <t>", "DPoP": <proof>}} for a DPoP-bound one, where
     * the proof is signed by the instance key the token is bound to and carries {@code htm}/{@code htu}
     * for this request, {@code ath}, and the last {@code DPoP-Nonce} that origin returned. Gets or
     * refreshes the token like {@link #token()}.
     *
     * @param method the request's HTTP method
     * @param url    the request URL (query and fragment are not part of the proof)
     */
    public Map<String, String> requestHeaders(String method, String url) {
        TokenState state = current(false);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", state.scheme() + " " + state.token());
        if (state.dpop()) {
            headers.put(DPOP_HEADER, new DpopProofBuilder(state.key())
                    .method(method)
                    .uri(url)
                    .accessToken(state.token())
                    .nonce(this.dpopNonces.get(nonceKey(url)))
                    .build());
        }
        return headers;
    }

    /**
     * Adds {@code Authorization: <scheme> <token>} to a {@link HttpRequest.Builder} and returns it. For a
     * DPoP-bound token this is not enough on its own — use {@link #authorize(HttpRequest.Builder, String,
     * URI)}, which also adds the proof.
     */
    public HttpRequest.Builder authorize(HttpRequest.Builder request) {
        TokenState state = current(false);
        return request.setHeader("Authorization", state.scheme() + " " + state.token());
    }

    /** Sets every header from {@link #requestHeaders(String, String)} on {@code request} and returns it. */
    public HttpRequest.Builder authorize(HttpRequest.Builder request, String method, URI uri) {
        requestHeaders(method, uri.toString()).forEach(request::setHeader);
        return request;
    }

    /**
     * Sends {@code request} (whose method and body the caller has set) through {@code client} with
     * {@link #requestHeaders(String, String)} attached. If the token is DPoP-bound and the resource answers
     * with a DPoP nonce challenge — a 401 with {@code WWW-Authenticate: DPoP error="use_dpop_nonce"}, or a
     * 400 JSON {@code {"error":"use_dpop_nonce"}} — and a {@code DPoP-Nonce} header, the nonce is
     * remembered for that origin and the request is re-sent once with a new proof carrying it. Bearer
     * tokens are sent once, unchanged. The body publisher must be re-subscribable for the retry (the JDK's
     * {@code ofString}/{@code ofByteArray} publishers are).
     */
    public <T> HttpResponse<T> send(HttpClient client, HttpRequest.Builder request, String method, URI uri,
            HttpResponse.BodyHandler<T> handler) throws IOException, InterruptedException {
        HttpRequest.Builder base = request.copy();
        Map<String, String> headers = requestHeaders(method, uri.toString());
        HttpRequest.Builder first = base.copy();
        headers.forEach(first::setHeader);
        HttpResponse<T> response = client.send(first.build(), handler);
        if (!headers.containsKey(DPOP_HEADER)) {
            return response;
        }
        String nonce = response.headers().firstValue(DPOP_NONCE_HEADER).orElse(null);
        if (nonce == null) {
            return response;
        }
        this.dpopNonces.put(nonceKey(uri.toString()), nonce);   // servers may rotate the nonce on any response
        if (!isNonceChallenge(response.statusCode(), response.headers(), bodyText(response.body()))) {
            return response;
        }
        return client.send(authorize(base.copy(), method, uri).build(), handler);
    }

    /** The attester's {@code /.well-known/client-attester} document (fetched once, then cached). */
    public Map<String, Object> discovery() throws Exception {
        synchronized (this.lock) {
            if (this.discovery == null) {
                this.discovery = getJson("GET", this.baseUrl + WELL_KNOWN_PATH, null);
            }
            return this.discovery;
        }
    }

    // ── the token cache ─────────────────────────────────────────────────────────────────────────────

    /** The cached token, its type and the instance key it is bound to — read together under the lock. */
    private record TokenState(String token, String tokenType, SigningKeyPair key) {
        boolean dpop() {
            return "dpop".equalsIgnoreCase(this.tokenType);
        }

        String scheme() {
            return dpop() ? "DPoP" : "Bearer";
        }
    }

    /** A token response together with the instance key whose attestation obtained it. */
    private record Minted(Map<String, Object> response, SigningKeyPair key) {
    }

    private TokenState current(boolean forceRefresh) {
        synchronized (this.lock) {
            if (!forceRefresh && this.cachedToken != null
                    && System.currentTimeMillis() / 1000L < this.expiresAt) {
                return new TokenState(this.cachedToken, this.cachedTokenType, this.cachedKey);
            }
            Minted minted;
            try {
                minted = runFlow();
            } catch (ClientAttestationException e) {
                throw e;
            } catch (Exception e) {
                throw new ClientAttestationException("client attestation flow failed: " + e.getMessage(), e);
            }
            Map<String, Object> response = minted.response();
            this.cachedToken = (String) response.get("access_token");   // a String: checked in callTokenEndpoint
            Object tokenType = response.get("token_type");
            this.cachedTokenType = tokenType != null ? String.valueOf(tokenType) : "Bearer";
            this.cachedKey = minted.key();
            Object expiresIn = response.get("expires_in");
            this.expiresAt = expiresIn instanceof Number
                    ? System.currentTimeMillis() / 1000L + ((Number) expiresIn).longValue() - this.skewSeconds
                    : 0L;
            return new TokenState(this.cachedToken, this.cachedTokenType, this.cachedKey);
        }
    }

    // ── the flow ────────────────────────────────────────────────────────────────────────────────────

    private Minted runFlow() throws Exception {
        Map<String, Object> doc = discovery();
        String audience = optString(doc, "evidence_audience", null);
        if (audience == null) {
            throw new ClientAttestationException("attester discovery document has no evidence_audience");
        }

        SvidSource evidenceSource = this.evidence != null ? this.evidence : Evidence.autoDetect();
        String svid = evidenceSource.fetch(audience);

        SigningKeyPair instanceKey = SigningKeyPair.generate(this.algorithm);
        String challenge = fetchChallenge(doc);
        String attestation = mint(doc, instanceKey, svid, challenge);

        // token_endpoint is advertised by current attesters; fall back to the standard PF path so an older
        // discovery document still works from the host alone.
        String tokenEndpoint = optString(doc, "token_endpoint", this.baseUrl + "/as/token.oauth2");
        requireSecure(tokenEndpoint, "token_endpoint", this.allowInsecure);
        String clientId = jwtSub(attestation);
        // The PoP audience must be PF's configured issuer, which the attester advertises as pop_audience.
        // Falling back to the token endpoint URL only works when the dialed URL matches PF's issuer.
        String popAudience = optString(doc, "pop_audience", tokenEndpoint);
        // See Builder#challengeAtToken: some attesters consume the challenge the moment the mint's instance
        // proof uses it, and reject a token request that presents the same value a second time. Against one
        // of those, only the mint gets the challenge.
        String tokenChallenge = this.challengeAtToken ? challenge : null;

        Map<String, Object> response;
        if (DPOP_COMBINED_POP_METHOD.equals(this.popMethod)) {
            // The attester challenge rides as the DPoP nonce; if the AS demands its own nonce, that wins.
            response = callTokenEndpoint(tokenEndpoint, attestation, DPOP_HEADER, tokenChallenge,
                    nonce -> new DpopProofBuilder(instanceKey).method("POST").uri(tokenEndpoint).nonce(nonce)
                            .build(),
                    true);
        } else {
            String pop = new PopBuilder(instanceKey).clientId(clientId).audience(popAudience)
                    .challenge(tokenChallenge).build();
            response = callTokenEndpoint(tokenEndpoint, attestation, POP_HEADER, tokenChallenge, nonce -> pop,
                    false);
        }
        return new Minted(response, instanceKey);
    }

    private String fetchChallenge(Map<String, Object> doc) {
        String endpoint = optString(doc, "challenge_endpoint", null);
        if (endpoint == null) {
            return null;      // the attester does not issue challenges
        }
        requireSecure(endpoint, "challenge_endpoint", this.allowInsecure);
        try {
            Map<String, Object> body = getJson("POST", endpoint, null);
            String challenge = optString(body, "attestation_challenge", null);
            if (challenge == null) {
                throw new ClientAttestationException("challenge endpoint returned no attestation_challenge", 200,
                        JsonUtil.toJson(body));
            }
            return challenge;
        } catch (Exception e) {
            if (!this.requireChallenge) {
                return null;  // opted out: proceed without a challenge, as before
            }
            int status = e instanceof ClientAttestationException ? ((ClientAttestationException) e).status() : 0;
            String body = e instanceof ClientAttestationException ? ((ClientAttestationException) e).body() : null;
            throw new ClientAttestationException("attester advertises challenge_endpoint " + endpoint
                    + " but the challenge could not be fetched (" + e.getMessage()
                    + "); set requireChallenge(false) to proceed without one", status, body, e);
        }
    }

    private String mint(Map<String, Object> doc, SigningKeyPair instanceKey, String svid, String challenge)
            throws Exception {
        long now = System.currentTimeMillis() / 1000L;
        Map<String, Object> proofClaims = new LinkedHashMap<>();
        proofClaims.put("aud", doc.get("evidence_audience"));
        proofClaims.put("jti", UUID.randomUUID().toString());
        proofClaims.put("iat", now);
        if (challenge != null && !challenge.isBlank()) {
            proofClaims.put("challenge", challenge);
        }
        String proof = Jws.sign(JsonUtil.toJson(proofClaims), instanceKey, INSTANCE_PROOF_TYP, false);

        // Evidence-first: no client_id. The attester maps the identity to a client.
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("instance_key", instanceKey.publicJwk());
        body.put("svid", svid);
        body.put("proof", proof);
        if (this.authorizationDetails != null && !this.authorizationDetails.isEmpty()) {
            body.put("authorization_details", this.authorizationDetails);
        }
        if (this.operator != null && !this.operator.isEmpty()) {
            // The client's OPERATOR (who answers for this workload), asked for at mint time so the ATTESTER is
            // what states it, rather than the client asserting it about itself at the token endpoint. An
            // attester that does not know this key ignores it; one that does can refuse to name an operator
            // it cannot corroborate.
            body.put("operator", this.operator);
        }

        String attestationEndpoint = optString(doc, "attestation_endpoint", null);
        if (attestationEndpoint == null) {
            throw new ClientAttestationException("attester discovery document has no attestation_endpoint");
        }
        requireSecure(attestationEndpoint, "attestation_endpoint", this.allowInsecure);
        Map<String, Object> response = getJson("POST", attestationEndpoint, body);
        Object attestation = response.get("attestation");
        if (attestation == null) {
            throw new ClientAttestationException("attester response contained no attestation",
                    0, JsonUtil.toJson(response));
        }
        return String.valueOf(attestation);
    }

    /**
     * POSTs the client_credentials grant with the attestation and a proof from {@code proofForNonce}. In
     * DPoP mode ({@code dpop}), a 400 {@code use_dpop_nonce} answer carrying {@code DPoP-Nonce} is retried
     * once with a new proof whose nonce is the server's value.
     */
    private Map<String, Object> callTokenEndpoint(String endpoint, String attestation, String proofHeaderName,
            String nonce, UnaryOperator<String> proofForNonce, boolean dpop) {
        String form = tokenForm(this.operator);
        HttpTransport.Response resp = send(tokenRequest(endpoint, attestation, proofHeaderName,
                proofForNonce.apply(nonce), form));
        if (dpop && isNonceChallenge(resp.status(), resp.headers(), resp.body())) {
            String serverNonce = resp.headers().firstValue(DPOP_NONCE_HEADER).orElseThrow();
            resp = send(tokenRequest(endpoint, attestation, proofHeaderName, proofForNonce.apply(serverNonce),
                    form));
        }
        if (!resp.ok()) {
            // Full error body kept on the exception: callers read the OAuth error JSON from body().
            throw new ClientAttestationException("token endpoint returned HTTP " + resp.status(),
                    resp.status(), resp.body());
        }
        Map<String, Object> parsed;
        try {
            parsed = HttpTransport.jsonOk(resp);
        } catch (TransportException e) {
            throw new ClientAttestationException("token endpoint returned an unparseable response",
                    resp.status(), resp.body(), e);
        }
        if (!(parsed.get("access_token") instanceof String)) {
            throw new ClientAttestationException("token endpoint returned no access_token",
                    resp.status(), resp.body());
        }
        return parsed;
    }

    /**
     * The client_credentials form. With an operator configured, it also carries the extension parameter
     * {@code operator}: the attestation is the authoritative carrier (the attester signed it), and this repeats
     * it on the wire so an AS that wants to populate RFC 8693 {@code may_act} from it can without parsing the
     * attestation. An AS that does not know the parameter ignores it.
     */
    static String tokenForm(Map<String, Object> operator) {
        String form = "grant_type=client_credentials";
        if (operator != null && !operator.isEmpty()) {
            form += "&operator=" + java.net.URLEncoder.encode(canonicalJson(operator), StandardCharsets.UTF_8);
        }
        return form;
    }

    /**
     * Compact JSON with keys sorted at every level and non-ASCII escaped as Python's default {@code ensure_ascii} does — byte-for-byte
     * what Python's {@code json.dumps(v, separators=(",", ":"), sort_keys=True)} produces for strings,
     * integers, booleans, null, lists and maps.
     */
    @SuppressWarnings("unchecked")
    static String canonicalJson(Map<?, ?> value) {
        String json = JsonUtil.toJson((Map<String, ?>) sortedCopy(value));
        StringBuilder out = new StringBuilder(json.length());
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c > 0x7f) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    @SuppressWarnings("unchecked")
    private static Object sortedCopy(Object value) {
        if (value instanceof Map) {
            Map<String, Object> sorted = new TreeMap<>();
            ((Map<Object, Object>) value).forEach((k, v) -> sorted.put(String.valueOf(k), sortedCopy(v)));
            return sorted;
        }
        if (value instanceof List) {
            List<Object> copy = new ArrayList<>();
            ((List<Object>) value).forEach(v -> copy.add(sortedCopy(v)));
            return copy;
        }
        return value;
    }

    private static HttpRequest.Builder tokenRequest(String endpoint, String attestation, String proofHeaderName,
            String proof, String form) {
        return HttpRequest.newBuilder(URI.create(endpoint))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .header(ATTESTATION_HEADER, attestation)
                .header(proofHeaderName, proof)
                .POST(HttpRequest.BodyPublishers.ofString(form));
    }

    private Map<String, Object> getJson(String method, String url, Map<String, Object> jsonBody)
            throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .header("Accept", "application/json");
        if (jsonBody != null) {
            builder.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(jsonBody)));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpTransport.Response resp = send(builder);
        if (!resp.ok()) {
            throw new ClientAttestationException(method + " " + url + " returned HTTP " + resp.status(),
                    resp.status(), resp.body());
        }
        if (resp.body().isBlank()) {
            return new LinkedHashMap<>();
        }
        try {
            return HttpTransport.jsonOk(resp);
        } catch (TransportException e) {
            throw new ClientAttestationException(method + " " + url + " returned an unparseable response",
                    resp.status(), resp.body(), e);
        }
    }

    /** The shared transport, with transport failures surfaced as {@link ClientAttestationException}. */
    private HttpTransport.Response send(HttpRequest.Builder request) {
        try {
            return HttpTransport.send(this.http, request, this.timeout);
        } catch (TransportException e) {
            throw new ClientAttestationException(e.getMessage(), e.status(), e.body(), e);
        }
    }

    // ── DPoP nonce handling ─────────────────────────────────────────────────────────────────────────

    /**
     * True for an RFC 9449 nonce challenge: a {@code DPoP-Nonce} header plus either a 401 whose
     * {@code WWW-Authenticate} uses the DPoP scheme with {@code error="use_dpop_nonce"}, or a 400 whose JSON
     * body has {@code "error":"use_dpop_nonce"}.
     */
    static boolean isNonceChallenge(int status, HttpHeaders headers, String body) {
        if (headers.firstValue(DPOP_NONCE_HEADER).isEmpty()) {
            return false;
        }
        if (status == 401) {
            return headers.allValues("WWW-Authenticate").stream()
                    .anyMatch(v -> DPOP_SCHEME.matcher(v).find() && USE_DPOP_NONCE.matcher(v).find());
        }
        if (status == 400 && body != null) {
            try {
                return "use_dpop_nonce".equals(HttpTransport.parseObject(body, status).get("error"));
            } catch (TransportException e) {
                return false;
            }
        }
        return false;
    }

    private static String bodyText(Object body) {
        if (body instanceof String) {
            return (String) body;
        }
        if (body instanceof byte[]) {
            return new String((byte[]) body, StandardCharsets.UTF_8);
        }
        return null;
    }

    /** Nonces are kept per origin; a URL with no parseable origin is its own key. */
    private static String nonceKey(String url) {
        try {
            URI uri = URI.create(url.strip());
            if (uri.getScheme() != null && uri.getHost() != null) {
                return DpopProofBuilder.origin(uri);
            }
        } catch (IllegalArgumentException e) {
            // fall through
        }
        return DpopProofBuilder.normalizeHtu(url);
    }

    /**
     * Throws unless {@code url} is https, its host is loopback ({@code localhost}, {@code 127.0.0.1},
     * {@code ::1}), or {@code allowInsecure} is set.
     */
    static void requireSecure(String url, String what, boolean allowInsecure) {
        if (allowInsecure) {
            return;
        }
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new ClientAttestationException(what + " is not a valid URL: " + url, e);
        }
        if ("https".equalsIgnoreCase(uri.getScheme()) || isLoopback(uri.getHost())) {
            return;
        }
        throw new ClientAttestationException(what + " must use https, got " + url
                + " (only loopback hosts are exempt; set allowInsecure(true) to override)");
    }

    static boolean isLoopback(String host) {
        return host != null && LOOPBACK_HOSTS.contains(host.toLowerCase(Locale.ROOT));
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────────────

    static String normalizeBaseUrl(String pfHost) {
        if (pfHost == null) {
            throw new IllegalArgumentException("pfHost is required");
        }
        String host = pfHost.strip().replaceAll("/+$", "");
        if (host.isEmpty()) {
            throw new IllegalArgumentException("pfHost is required");
        }
        if (!host.contains("://")) {
            host = "https://" + host;
        }
        return host;
    }

    static String jwtSub(String compactJwt) {
        try {
            String[] parts = compactJwt.split("\\.");
            if (parts.length < 2) {
                throw new ClientAttestationException("minted attestation is not a compact JWT");
            }
            byte[] payload = java.util.Base64.getUrlDecoder().decode(parts[1]);
            Map<String, Object> claims = JsonUtil.parseJson(new String(payload, java.nio.charset.StandardCharsets.UTF_8));
            Object sub = claims.get("sub");
            if (sub == null || String.valueOf(sub).isBlank()) {
                throw new ClientAttestationException("minted attestation has no sub (client id)");
            }
            return String.valueOf(sub);
        } catch (ClientAttestationException e) {
            throw e;
        } catch (Exception e) {
            throw new ClientAttestationException("could not read sub from minted attestation: " + e.getMessage(), e);
        }
    }

    private static String optString(Map<String, Object> map, String key, String fallback) {
        Object v = map.get(key);
        return v != null && !String.valueOf(v).isBlank() ? String.valueOf(v) : fallback;
    }

    /** Thrown when any step of the flow fails. {@code status} and {@code body} are set for HTTP failures. */
    public static final class ClientAttestationException extends RuntimeException {
        private final int status;
        private final String body;

        public ClientAttestationException(String message) {
            this(message, 0, null);
        }

        public ClientAttestationException(String message, Throwable cause) {
            super(message, cause);
            this.status = 0;
            this.body = null;
        }

        public ClientAttestationException(String message, int status, String body) {
            super(message);
            this.status = status;
            this.body = body;
        }

        ClientAttestationException(String message, int status, String body, Throwable cause) {
            super(message, cause);
            this.status = status;
            this.body = body;
        }

        /** HTTP status for transport failures, or 0. */
        public int status() {
            return this.status;
        }

        /** Response body for transport failures, or null. */
        public String body() {
            return this.body;
        }
    }

    /** Options for {@link ClientAttestation}. */
    public static final class Builder {
        private final String pfHost;
        private SvidSource evidence;
        private List<Map<String, Object>> authorizationDetails;
        private Map<String, Object> operator;
        private boolean challengeAtToken = true;
        private String algorithm = "ES256";
        private String popMethod = DEFAULT_POP_METHOD;
        private int expirySkewSeconds = DEFAULT_EXPIRY_SKEW_SECONDS;
        private Duration timeout = Duration.ofSeconds(20);
        private boolean requireChallenge = true;
        private boolean allowInsecure;

        public Builder(String pfHost) {
            this.pfHost = pfHost;
        }

        /** Override how the workload's platform identity (evidence) is obtained. Default: auto-detect. */
        public Builder evidence(SvidSource evidence) {
            this.evidence = evidence;
            return this;
        }

        /** Optional RFC 9396 access request sent at mint time. */
        public Builder authorizationDetails(List<Map<String, Object>> authorizationDetails) {
            this.authorizationDetails = authorizationDetails;
            return this;
        }

        /**
         * The client's operator (who answers for this workload), as a JSON object. When set and non-empty it
         * is sent in the mint request body as {@code operator}, so the attester can state it in the
         * attestation, and repeated at the token endpoint as the form parameter {@code operator} (compact JSON,
         * keys sorted). Default: none, and nothing is sent.
         */
        public Builder operator(Map<String, Object> operator) {
            this.operator = operator;
            return this;
        }

        /**
         * Whether the attester-issued challenge also rides in the token-endpoint proof (the PoP's
         * {@code challenge} claim, or the DPoP {@code nonce}), on top of the mint-time instance proof it always
         * protects. Default {@code true} binds token issuance to the same challenge as the mint, so a captured
         * attestation cannot be redeemed for a token without it, but it requires an attester whose challenge
         * store tolerates being checked at both points. Some attesters treat a challenge as consumed the moment
         * the mint's instance proof uses it, and then reject a token request that presents the same value as
         * "unknown or expired"; set this {@code false} against one of those (the challenge still protects the
         * mint; only the token-endpoint copy is dropped).
         */
        public Builder challengeAtToken(boolean challengeAtToken) {
            this.challengeAtToken = challengeAtToken;
            return this;
        }

        /** Instance-key signature algorithm (default {@code ES256}). */
        public Builder algorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        /**
         * PoP method: default {@code attestation_pop_jwt} (a dedicated {@code OAuth-Client-Attestation-PoP}
         * JWT), or {@code dpop_combined} to send a single DPoP proof (RFC 9449, header {@code DPoP})
         * instead, whose embedded {@code jwk} is the instance key bound in the attestation's {@code cnf}.
         */
        public Builder popMethod(String popMethod) {
            this.popMethod = popMethod;
            return this;
        }

        /** Refresh this long before the token expires (default 30s). */
        public Builder expirySkewSeconds(int expirySkewSeconds) {
            this.expirySkewSeconds = expirySkewSeconds;
            return this;
        }

        /** Per-request HTTP timeout (default 20s). */
        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        /**
         * When the attester advertises a {@code challenge_endpoint}, fail if the challenge cannot be fetched
         * (default {@code true}). {@code false} restores the old behaviour of minting without a challenge.
         */
        public Builder requireChallenge(boolean requireChallenge) {
            this.requireChallenge = requireChallenge;
            return this;
        }

        /**
         * Allow plain-http hosts and discovery endpoints that are not loopback (default {@code false}). For
         * test rigs only: the attestation, proofs and token travel over these connections.
         */
        public Builder allowInsecure(boolean allowInsecure) {
            this.allowInsecure = allowInsecure;
            return this;
        }

        /** @throws ClientAttestationException if the host is not https, not loopback and not allowed */
        public ClientAttestation build() {
            return new ClientAttestation(this);
        }
    }
}
