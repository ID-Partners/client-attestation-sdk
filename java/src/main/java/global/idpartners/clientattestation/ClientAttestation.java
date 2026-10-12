/*
 * One call to get an access token with client attestation.
 *
 * Point it at an attester (PingFederate by default) and call {@link #token()}. It runs the whole flow:
 *
 *   discover -> get platform identity (evidence) -> get a challenge -> mint the attestation ->
 *   call the token endpoint with the attestation headers -> cache the access token
 *
 * The workload sends no client secret and no client_id. Its only credential is the attestation, built
 * from the identity its runtime already gives it (auto-detected; see {@link Evidence}).
 */
package global.idpartners.clientattestation;

import global.idpartners.clientattestation.internal.HttpTransport;
import global.idpartners.clientattestation.internal.SdkLog;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jose4j.json.JsonUtil;

/**
 * Gets and caches an access token using client attestation — the whole flow in one call, no client secret
 * and no {@code client_id} sent. The attester-specific steps (discovery and the mint request) belong to an
 * {@link AttesterProfile}, by default {@link PingFederateProfile}; see docs/attester-profiles.md.
 *
 * <pre>{@code
 * ClientAttestation ca = ClientAttestation.builder("pf.example.com")
 *         .evidenceAudience("https://pf.example.com")  // the audience your attester expects evidence for
 *         .build();
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
 * fetched, the flow fails (opt out with {@link Builder#requireChallenge(boolean)}); and the attester URL and every
 * endpoint taken from discovery must be https unless the host is loopback or
 * {@link Builder#allowInsecure(boolean)} is set.
 */
public final class ClientAttestation {

    /** draft-ietf-oauth-attestation-based-client-auth revision this SDK implements. */
    public static final String DRAFT_REVISION = "10";

    /**
     * The SDK's logger name, for {@code System.getLogger(ClientAttestation.LOGGER_NAME)}: pass the result to
     * {@link Builder#logger(System.Logger)} or {@code AccessTokenValidator.Builder#logger}.
     */
    public static final String LOGGER_NAME = "global.idpartners.clientattestation";

    static final String ATTESTATION_HEADER = "OAuth-Client-Attestation";
    static final String POP_HEADER = "OAuth-Client-Attestation-PoP";
    static final String DPOP_HEADER = "DPoP";
    static final String DPOP_NONCE_HEADER = "DPoP-Nonce";
    static final String INSTANCE_PROOF_TYP = PingFederateProfile.INSTANCE_PROOF_TYP;
    static final String WELL_KNOWN_PATH = PingFederateProfile.WELL_KNOWN_PATH;
    /** Default PoP method: a dedicated {@code OAuth-Client-Attestation-PoP} JWT. */
    static final String DEFAULT_POP_METHOD = "attestation_pop_jwt";
    /** PoP method that sends a single DPoP proof (RFC 9449) instead of a separate PoP JWT. */
    static final String DPOP_COMBINED_POP_METHOD = "dpop_combined";
    /** Refresh this many seconds before the token actually expires, so a token is never used at the edge. */
    static final int DEFAULT_EXPIRY_SKEW_SECONDS = 30;
    /** A token is cached for at most this long, whatever {@code expires_in} the token endpoint gives. */
    static final long MAX_TOKEN_LIFETIME_SECONDS = 24L * 60 * 60;
    /** At most this much of a 400 body is read to look for {@code use_dpop_nonce}; a longer one is not a challenge. */
    static final int MAX_NONCE_CHALLENGE_BODY = 64 * 1024;
    /** RFC 9449 nonces are short opaque strings: a longer {@code DPoP-Nonce} is ignored, as if there were none. */
    static final int MAX_DPOP_NONCE_LENGTH = 1024;
    /**
     * At most this many origins' nonces are remembered; a new origin over the cap replaces the one stored
     * longest ago (it costs that origin one challenge).
     */
    static final int MAX_DPOP_NONCE_ORIGINS = 256;

    /** What the https check calls the URL a profile's call goes to, by step. */
    private static final Map<String, String> STEP_LABELS = Map.of(
            "discover", "attester_url", "mint", "attestation_endpoint", "challenge", "challenge_endpoint");
    private static final String PIN_REQUIRED = "evidenceAudience is required: set it to the audience your attester"
            + " expects the workload's identity token for, so the attester's discovery document can't choose it";
    private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "::1", "[::1]");
    /** Matches {@code scheme://authority} at the start of a URL that {@link URI} does not parse. */
    private static final Pattern SCHEME_AUTHORITY = Pattern.compile("^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)");
    private static final Pattern DPOP_SCHEME = Pattern.compile("(?i)(?:^|[,\\s])DPoP(?:\\s|,|$)");
    private static final Pattern USE_DPOP_NONCE = Pattern.compile("(?i)error\\s*=\\s*\"?use_dpop_nonce\\b");
    /** The form of an {@code expires_in} sent as a JSON string that is still read as a number. */
    private static final Pattern NUMERIC_STRING = Pattern.compile("[0-9]+(?:\\.[0-9]+)?");

    private final String baseUrl;                            // null => built from static metadata alone
    private final AttesterProfile profile;
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
    private final SdkLog log;

    private final Object lock = new Object();
    private String cachedToken;
    private String cachedTokenType;
    private SigningKeyPair cachedKey;                        // the instance key bound to cachedToken
    private long cachedAtNanos;                              // nanoClock reading when cachedToken was stored
    private long cacheNanos;                                 // how long it may be served; <= 0 => no cache
    private AttesterMetadata metadata;                       // static, or discovered once
    private final boolean staticMetadata;
    private final String evidenceAudience;                   // the pin; null => only allowed with static metadata
    /** Last {@code DPoP-Nonce} each origin returned, oldest first; guarded by itself. */
    private final Map<String, String> dpopNonces = new LinkedHashMap<>();
    /** The token cache's clock: monotonic, so a wall-clock step cannot extend a token's life. */
    LongSupplier nanoClock = System::nanoTime;

    /**
     * A client for the attester at {@code attesterUrl}, with the default {@link PingFederateProfile}.
     *
     * <p>This constructor can't set the evidence audience, which a client that discovers its attester now
     * needs, so {@link #token()} on it always throws {@link ClientAttestationException}. Use
     * {@code ClientAttestation.builder(attesterUrl).evidenceAudience(...).build()}.
     *
     * @param attesterUrl the attester's host — {@code "pf.example.com"}, or a full base URL
     *                    {@code "https://pf.example.com"}. Plain hostnames default to https.
     * @throws ClientAttestationException if the host is not https and not loopback
     * @deprecated it can't set {@link Builder#evidenceAudience(String)}; use {@link #builder(String)}.
     *             Goes in the next major release.
     */
    @Deprecated
    public ClientAttestation(String attesterUrl) {
        this(new Builder(attesterUrl));
    }

    private ClientAttestation(Builder b) {
        this.profile = b.profile != null ? b.profile : new PingFederateProfile();
        this.metadata = b.metadata;
        this.staticMetadata = b.metadata != null;
        this.evidenceAudience = b.evidenceAudience;
        this.baseUrl = b.attesterUrl == null && (b.metadata != null || b.profile != null)
                ? null : normalizeBaseUrl(b.attesterUrl);
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
        this.log = new SdkLog(b.logger);
        if (this.baseUrl != null) {
            requireSecure(this.baseUrl, "attester_url", this.allowInsecure);
        }
        this.http = HttpTransport.client(b.timeout);
    }

    /**
     * Options for a client of the attester at {@code attesterUrl}.
     *
     * @param attesterUrl the attester's host or base URL
     * @return the builder
     */
    public static Builder builder(String attesterUrl) {
        return new Builder(attesterUrl);
    }

    /**
     * Options for a client with no attester URL yet: set one with {@link Builder#attesterUrl(String)}, or give
     * static {@link Builder#metadata(AttesterMetadata)} or a custom {@link Builder#profile(AttesterProfile)}.
     *
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
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
     * <p>{@code url} must be https, like every other URL the client sends a credential to (loopback hosts
     * and {@link Builder#allowInsecure(boolean)} excepted).
     *
     * <p>Pass the exact URL the HTTP client sends: the proof is only valid for the {@code htu} it names. A
     * URL with a backslash, ASCII whitespace or a control character before its query or fragment is refused
     * with a {@link ClientAttestationException}, because URL parsers disagree on where it goes. For a
     * DPoP-bound token, so is a URL that is not an absolute http(s) URL with a valid ASCII host, port and
     * path; a client built with {@code popMethod("dpop_combined")} checks that before fetching the token.
     * The path is signed as written: pass {@code request.uri().toString()} of the request you send.
     *
     * @param method the request's HTTP method
     * @param url    the request URL (query and fragment are not part of the proof)
     */
    public Map<String, String> requestHeaders(String method, String url) {
        return requestHeaders(method, url, null);
    }

    /**
     * {@link #requestHeaders(String, String)}, with the proof carrying {@code nonce} when it is not null (the
     * nonce of the challenge being answered) instead of the origin's remembered one.
     */
    private Map<String, String> requestHeaders(String method, String url, String nonce) {
        requireSecure(url, "resource URL", this.allowInsecure);
        // A client configured for DPoP checks the whole htu before fetching the token, so a URL with no htu
        // never costs a mint and token request on a cold cache. Otherwise only what parsers disagree on is
        // refused up front: a Bearer token carries no htu.
        try {
            if (DPOP_COMBINED_POP_METHOD.equals(this.popMethod)) {
                DpopProofBuilder.normalizeHtu(url);
            } else {
                DpopProofBuilder.checkHtu(url);
            }
        } catch (IllegalArgumentException e) {
            throw new ClientAttestationException(e.getMessage());
        }
        TokenState state = current(false);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", state.scheme() + " " + state.token());
        if (state.dpop()) {
            // Also for a DPoP token from a client not configured for DPoP (the AS chose the token type).
            try {
                DpopProofBuilder.normalizeHtu(url);
            } catch (IllegalArgumentException e) {
                throw new ClientAttestationException(e.getMessage());
            }
            headers.put(DPOP_HEADER, new DpopProofBuilder(state.key())
                    .method(method)
                    .uri(url)
                    .accessToken(state.token())
                    .nonce(nonce != null ? nonce : nonceFor(url))
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
     * Whatever {@code handler} is, at most 64 KiB of a 400 with a {@code DPoP-Nonce} is read first to look
     * for the challenge (a longer body is not one), and the handler still gets the whole body. A challenge
     * response that is retried is closed (an {@code InputStream} or {@code Stream} body) or cancelled (a
     * {@code Publisher} body) before the retry, so it does not hold its connection.
     * The client must use {@code HttpClient.Redirect.NEVER}; a client that follows redirects is refused
     * before attaching credentials. So is a {@code request} whose URI is on another origin than {@code uri},
     * the URL the credentials are built for.
     */
    public <T> HttpResponse<T> send(HttpClient client, HttpRequest.Builder request, String method, URI uri,
            HttpResponse.BodyHandler<T> handler) throws IOException, InterruptedException {
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("credential requests require HttpClient.Redirect.NEVER");
        }
        if (!sameOrigin(request.copy().build().uri(), uri)) {
            throw new IllegalArgumentException("the request's URI is on another origin than " + SdkLog.host(uri.toString()));
        }
        HttpRequest.Builder base = request.copy();
        Map<String, String> headers = requestHeaders(method, uri.toString());
        HttpRequest.Builder first = base.copy();
        headers.forEach(first::setHeader);
        if (!headers.containsKey(DPOP_HEADER)) {
            return client.send(first.build(), handler);
        }
        ChallengeProbe<T> probe = new ChallengeProbe<>(handler);
        HttpResponse<T> response = client.send(first.build(), probe);
        String nonce = usableNonce(response.headers());
        if (nonce == null) {
            return response;
        }
        rememberNonce(uri.toString(), nonce);   // servers may rotate the nonce on any response
        if (!isNonceChallenge(response.statusCode(), response.headers(), probe.body())) {
            return response;
        }
        this.log.info("dpop.nonce_retry", "host", SdkLog.host(uri.toString()), "status", response.statusCode(),
                "at", "resource");
        discard(response.body());   // the caller never sees this response: free its connection
        // Answer this challenge with its own nonce, not one a concurrent response stored since.
        HttpRequest.Builder retry = base.copy();
        requestHeaders(method, uri.toString(), nonce).forEach(retry::setHeader);
        return client.send(retry.build(), handler);
    }

    /**
     * The attester's discovery document (for the PingFederate profile, {@code /.well-known/client-attester}),
     * fetched once and then cached. With static metadata, the fields that were given.
     *
     * @return the document
     * @throws Exception if discovery fails
     */
    public Map<String, Object> discovery() throws Exception {
        return attesterMetadata().asDocument();
    }

    /**
     * The attester's endpoints: the static metadata, or what the profile discovered (once, then cached).
     *
     * @return the metadata
     * @throws Exception if discovery fails
     */
    public AttesterMetadata attesterMetadata() throws Exception {
        synchronized (this.lock) {
            String host = this.baseUrl != null ? SdkLog.host(this.baseUrl) : null;
            if (this.metadata == null) {
                AttesterMetadata discovered = this.profile.discover(transport(), this.baseUrl);
                if (discovered == null) {
                    throw new ClientAttestationException("attester profile returned no metadata");
                }
                this.metadata = discovered;
                this.log.debug("discovery.fetched", "host", host);
            } else {
                this.log.debug("discovery.cached", "host", host);
            }
            return this.metadata;
        }
    }

    /** The transport handed to the profile: this client's https rule, timeout and logging. */
    private AttesterTransport transport() {
        return (step, method, url, body) -> {
            requireSecure(url, STEP_LABELS.getOrDefault(step, step + " URL"), this.allowInsecure);
            return getJson(step, method, url, body);
        };
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
    private record Minted(Map<String, Object> response, SigningKeyPair key, String tokenEndpoint,
            String clientId) {
    }

    private TokenState current(boolean forceRefresh) {
        synchronized (this.lock) {
            long age = this.nanoClock.getAsLong() - this.cachedAtNanos;
            if (!forceRefresh && this.cachedToken != null && age < this.cacheNanos) {
                this.log.debug("token.cache_hit", "expires_in", TimeUnit.NANOSECONDS.toSeconds(this.cacheNanos - age));
                return new TokenState(this.cachedToken, this.cachedTokenType, this.cachedKey);
            }
            this.log.debug("token.refreshing", "reason",
                    this.cachedToken == null ? "initial" : forceRefresh ? "forced" : "expired");
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
            long lifetime = tokenLifetime(response.get("expires_in"));
            this.cachedAtNanos = this.nanoClock.getAsLong();
            this.cacheNanos = lifetime > 0 ? TimeUnit.SECONDS.toNanos(lifetime - this.skewSeconds) : 0L;
            this.log.info("token.obtained", "host", SdkLog.host(minted.tokenEndpoint()),
                    "client_id", minted.clientId(), "token_type", this.cachedTokenType,
                    "expires_in", lifetime > 0 ? lifetime : null,
                    "pop_method", this.popMethod);
            return new TokenState(this.cachedToken, this.cachedTokenType, this.cachedKey);
        }
    }

    /**
     * How long to cache a token, in whole seconds: {@code expires_in} as a JSON number, or a string of
     * decimal digits, capped at {@link #MAX_TOKEN_LIFETIME_SECONDS}. Anything else — missing, null, not a
     * number, not finite, zero or negative — is 0, and the token is not cached, as with no
     * {@code expires_in} at all.
     */
    static long tokenLifetime(Object expiresIn) {
        double seconds;
        if (expiresIn instanceof Number number) {
            seconds = number.doubleValue();
        } else if (expiresIn instanceof String text && NUMERIC_STRING.matcher(text).matches()) {
            seconds = Double.parseDouble(text);
        } else {
            return 0L;
        }
        if (!Double.isFinite(seconds) || seconds <= 0) {
            return 0L;
        }
        return (long) Math.min(seconds, MAX_TOKEN_LIFETIME_SECONDS);
    }

    // ── the flow ────────────────────────────────────────────────────────────────────────────────────

    private Minted runFlow() throws Exception {
        boolean pinned = this.evidenceAudience != null && !this.evidenceAudience.isEmpty();
        if (!pinned && !this.staticMetadata) {
            throw new ClientAttestationException(PIN_REQUIRED);
        }
        AttesterMetadata meta = attesterMetadata();
        String audience = meta.evidenceAudience();
        if (audience == null || audience.isBlank()) {
            throw new ClientAttestationException("attester discovery document has no evidence_audience");
        }
        if (pinned && !audience.equals(this.evidenceAudience)) {
            throw new ClientAttestationException("the attester asks for evidence for \"" + audience
                    + "\", but evidenceAudience is \"" + this.evidenceAudience + "\"");
        }

        SvidSource evidenceSource = this.evidence != null ? this.evidence : Evidence.autoDetect();
        String svid = evidenceSource.fetch(audience);
        this.log.debug("evidence.obtained", "source", evidenceSource.getClass().getSimpleName());

        SigningKeyPair instanceKey = SigningKeyPair.generate(this.algorithm);
        String challenge = fetchChallenge(meta.challengeEndpoint());
        MintResult minted = this.profile.mint(transport(), meta, new MintRequest(instanceKey, svid, challenge, null,
                this.authorizationDetails, this.operator));
        if (minted == null || minted.attestation() == null || minted.attestation().isBlank()) {
            throw new ClientAttestationException("attester response contained no attestation");
        }
        String attestation = minted.attestation();

        // The profile resolves the token endpoint (PingFederate: the advertised one, else the standard path on
        // the attester host).
        String tokenEndpoint = meta.tokenEndpoint();
        if (tokenEndpoint == null || tokenEndpoint.isBlank()) {
            throw new ClientAttestationException("attester metadata has no token_endpoint");
        }
        requireSecure(tokenEndpoint, "token_endpoint", this.allowInsecure);
        String clientId = jwtSub(attestation);
        this.log.debug("attestation.minted", "host", SdkLog.host(
                meta.attestationEndpoint() != null ? meta.attestationEndpoint() : ""),
                "client_id", clientId, "alg", this.algorithm);
        // The PoP audience must be PF's configured issuer, which the attester advertises as pop_audience.
        // Falling back to the token endpoint URL only works when the dialed URL matches PF's issuer.
        String popAudience = meta.popAudience() != null && !meta.popAudience().isBlank()
                ? meta.popAudience() : tokenEndpoint;
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
        return new Minted(response, instanceKey, tokenEndpoint, clientId);
    }

    private String fetchChallenge(String endpoint) {
        if (endpoint == null || endpoint.isBlank()) {
            return null;      // the attester does not issue challenges
        }
        requireSecure(endpoint, "challenge_endpoint", this.allowInsecure);
        try {
            Map<String, Object> body = getJson("challenge", "POST", endpoint, null);
            String challenge = optString(body, "attestation_challenge", null);
            if (challenge == null) {
                throw new ClientAttestationException("challenge endpoint returned no attestation_challenge", 200,
                        null);
            }
            this.log.debug("challenge.fetched", "host", SdkLog.host(endpoint));
            return challenge;
        } catch (Exception e) {
            if (!this.requireChallenge) {
                this.log.warn("challenge.skipped", "host", SdkLog.host(endpoint));
                return null;  // opted out: proceed without a challenge, as before
            }
            int status = e instanceof ClientAttestationException ? ((ClientAttestationException) e).status() : 0;
            String body = e instanceof ClientAttestationException ? ((ClientAttestationException) e).body() : null;
            throw new ClientAttestationException("attester advertises challenge_endpoint " + endpoint
                    + " but the challenge could not be fetched (" + e.getMessage()
                    + "); set requireChallenge(false) to proceed without one", status, body, e);
        }
    }

    /**
     * POSTs the client_credentials grant with the attestation and a proof from {@code proofForNonce}. In
     * DPoP mode ({@code dpop}), a {@code use_dpop_nonce} answer carrying {@code DPoP-Nonce} (a 400 JSON error
     * or a 401 DPoP challenge, see {@link #isNonceChallenge}) is retried once with a new proof whose nonce is
     * the server's value.
     */
    private Map<String, Object> callTokenEndpoint(String endpoint, String attestation, String proofHeaderName,
            String nonce, UnaryOperator<String> proofForNonce, boolean dpop) {
        String form = tokenForm(this.operator);
        HttpTransport.Response resp = send("token", "POST", endpoint, tokenRequest(endpoint, attestation,
                proofHeaderName, proofForNonce.apply(nonce), form));
        if (dpop && isNonceChallenge(resp.status(), resp.headers(), resp.body())) {
            String serverNonce = resp.headers().firstValue(DPOP_NONCE_HEADER).orElseThrow();
            this.log.info("dpop.nonce_retry", "host", SdkLog.host(endpoint), "status", resp.status(),
                    "at", "token_endpoint");
            resp = send("token", "POST", endpoint, tokenRequest(endpoint, attestation, proofHeaderName, proofForNonce.apply(serverNonce),
                    form));
        }
        if (!resp.ok()) {
            httpFailed("token", "POST", endpoint, resp.status(), "status");
            // The OAuth error JSON is kept on the exception, up to HttpTransport.ERROR_BODY_CHARS.
            throw new ClientAttestationException("token endpoint returned HTTP " + resp.status(),
                    resp.status(), HttpTransport.truncate(resp.body()));
        }
        // A 2xx body that can't be used is not kept: it may hold the access token.
        Map<String, Object> parsed;
        try {
            parsed = HttpTransport.jsonOk(resp);
        } catch (TransportException e) {
            httpFailed("token", "POST", endpoint, resp.status(), "malformed");
            throw new ClientAttestationException("token endpoint returned an unparseable response",
                    resp.status(), null, e);
        }
        if (!(parsed.get("access_token") instanceof String)) {
            throw new ClientAttestationException("token endpoint returned no access_token",
                    resp.status(), null);
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

    private Map<String, Object> getJson(String step, String method, String url, Map<String, Object> jsonBody)
            throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .header("Accept", "application/json");
        if (jsonBody != null) {
            builder.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(jsonBody)));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpTransport.Response resp = send(step, method, url, builder);
        if (!resp.ok()) {
            httpFailed(step, method, url, resp.status(), "status");
            throw new ClientAttestationException(method + " " + url + " returned HTTP " + resp.status(),
                    resp.status(), HttpTransport.truncate(resp.body()));
        }
        if (resp.body().isBlank()) {
            return new LinkedHashMap<>();
        }
        try {
            return HttpTransport.jsonOk(resp);
        } catch (TransportException e) {
            httpFailed(step, method, url, resp.status(), "malformed");
            throw new ClientAttestationException(method + " " + url + " returned an unparseable response",
                    resp.status(), null, e);
        }
    }

    /** The shared transport, with transport failures surfaced as {@link ClientAttestationException}. */
    private HttpTransport.Response send(String step, String method, String url, HttpRequest.Builder request) {
        try {
            return HttpTransport.send(this.http, request, this.timeout);
        } catch (TransportException e) {
            httpFailed(step, method, url, e.status(), failureReason(e));
            throw new ClientAttestationException(e.getMessage(), e.status(), e.body(), e);
        }
    }

    private void httpFailed(String step, String method, String url, int status, String reason) {
        this.log.warn("http.failed", "step", step, "method", method, "host", SdkLog.host(url),
                "path", SdkLog.path(url), "status", status > 0 ? status : null, "reason", reason);
    }

    /** The {@code reason} attribute for a transport failure (see docs/logging.md). */
    static String failureReason(TransportException e) {
        Throwable cause = e.getCause();
        if (cause instanceof java.util.concurrent.TimeoutException
                || cause instanceof java.net.http.HttpTimeoutException) {
            return "timeout";
        }
        if (e.status() >= 300 && e.status() < 400) {
            return "redirect";
        }
        if (String.valueOf(e.getMessage()).contains("response body exceeds")) {
            return "too_large";
        }
        return "network";
    }

    // ── DPoP nonce handling ─────────────────────────────────────────────────────────────────────────

    /**
     * True for an RFC 9449 nonce challenge: a {@code DPoP-Nonce} header of at most
     * {@link #MAX_DPOP_NONCE_LENGTH} characters plus either a 401 whose {@code WWW-Authenticate} uses the
     * DPoP scheme with {@code error="use_dpop_nonce"}, or a 400 whose JSON body has
     * {@code "error":"use_dpop_nonce"}.
     */
    static boolean isNonceChallenge(int status, HttpHeaders headers, String body) {
        if (usableNonce(headers) == null) {
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

    /** The response's {@code DPoP-Nonce}, or null when it has none or it is over {@link #MAX_DPOP_NONCE_LENGTH}. */
    private static String usableNonce(HttpHeaders headers) {
        String nonce = headers.firstValue(DPOP_NONCE_HEADER).orElse(null);
        return nonce != null && !nonce.isEmpty() && nonce.length() <= MAX_DPOP_NONCE_LENGTH ? nonce : null;
    }

    /** The last {@code DPoP-Nonce} the URL's origin returned, or null. */
    String nonceFor(String url) {
        synchronized (this.dpopNonces) {
            return this.dpopNonces.get(nonceKey(url));
        }
    }

    /**
     * Stores {@code nonce} as the origin's latest, forgetting the origin stored longest ago when a new one
     * would go over {@link #MAX_DPOP_NONCE_ORIGINS}.
     */
    void rememberNonce(String url, String nonce) {
        String key = nonceKey(url);
        synchronized (this.dpopNonces) {
            this.dpopNonces.remove(key);
            if (this.dpopNonces.size() >= MAX_DPOP_NONCE_ORIGINS) {
                this.dpopNonces.remove(this.dpopNonces.keySet().iterator().next());
            }
            this.dpopNonces.put(key, nonce);
        }
    }

    /**
     * Nonces are kept per origin: {@code scheme://host[:port]} as the request's {@code htu} names it (lower
     * case, no user info, no default port, never the path), so one origin is one key. A URL with no
     * {@code htu} is its own key.
     */
    static String nonceKey(String url) {
        return DpopProofBuilder.origin(url);
    }

    /**
     * Whether two URIs are on one origin, for {@link #send}'s guard. A URI the htu rule refuses (an IPv6 zone
     * literal, say) is its own nonce key, whole URL and all, so for those the origin is read off the URI:
     * its scheme and authority, lower-cased, without userinfo. Otherwise a same-origin request with another
     * path or query would be refused.
     */
    static boolean sameOrigin(URI a, URI b) {
        return originOf(a).equals(originOf(b));
    }

    private static String originOf(URI uri) {
        String text = uri.toString();
        String key = nonceKey(text);
        if (!key.equals(text) || uri.getScheme() == null) {
            return key;
        }
        String authority = uri.getRawAuthority() == null ? "" : uri.getRawAuthority();
        authority = authority.substring(authority.lastIndexOf('@') + 1);
        return (uri.getScheme() + "://" + authority).toLowerCase(Locale.ROOT);
    }

    /** Lets go of a response body the caller never sees, so it does not hold its connection open. */
    private static void discard(Object body) {
        if (body instanceof AutoCloseable) {   // an InputStream, or ofLines' Stream
            try {
                ((AutoCloseable) body).close();
            } catch (Exception e) {
                // nothing more to free
            }
        } else if (body instanceof Flow.Publisher) {
            ((Flow.Publisher<?>) body).subscribe(new Flow.Subscriber<Object>() {
                @Override
                public void onSubscribe(Flow.Subscription subscription) {
                    subscription.cancel();
                }

                @Override
                public void onNext(Object item) {
                }

                @Override
                public void onError(Throwable throwable) {
                }

                @Override
                public void onComplete() {
                }
            });
        }
    }

    /**
     * The caller's body handler, except that a 400 with a usable {@code DPoP-Nonce} has up to
     * {@link #MAX_NONCE_CHALLENGE_BODY} bytes of its body read first, to see whether it is a
     * {@code use_dpop_nonce} challenge. The caller's subscriber still gets the whole body.
     */
    private static final class ChallengeProbe<T> implements HttpResponse.BodyHandler<T> {
        private final HttpResponse.BodyHandler<T> handler;
        private volatile Peek<T> peek;

        ChallengeProbe(HttpResponse.BodyHandler<T> handler) {
            this.handler = handler;
        }

        @Override
        public HttpResponse.BodySubscriber<T> apply(HttpResponse.ResponseInfo info) {
            HttpResponse.BodySubscriber<T> downstream = this.handler.apply(info);
            if (info.statusCode() != 400 || usableNonce(info.headers()) == null) {
                return downstream;
            }
            Peek<T> p = new Peek<>(downstream);
            this.peek = p;
            return p;
        }

        /** The 400 body as text when it was read whole (it fit in the cap), else null. */
        String body() {
            Peek<T> p = this.peek;
            byte[] whole = p == null ? null : p.peeked.getNow(null);
            return whole == null ? null : new String(whole, StandardCharsets.UTF_8);
        }
    }

    /**
     * Reads a body up to {@link #MAX_NONCE_CHALLENGE_BODY} bytes (plus the chunk that crosses it), then hands
     * everything to {@code downstream}: what it held first, then the rest of the body as downstream asks.
     */
    private static final class Peek<T> implements HttpResponse.BodySubscriber<T> {
        private final HttpResponse.BodySubscriber<T> downstream;
        /** Completes when peeking is over: with the whole body when it fit in the cap, else with null. */
        final CompletableFuture<byte[]> peeked = new CompletableFuture<>();
        private final List<ByteBuffer> held = new ArrayList<>();
        private Flow.Subscription upstream;
        private long size;
        private volatile boolean released;   // downstream subscribed: later signals go straight to it
        private volatile boolean done;       // the body ended (or failed) while held
        private volatile Throwable failure;

        Peek(HttpResponse.BodySubscriber<T> downstream) {
            this.downstream = downstream;
        }

        @Override
        public CompletionStage<T> getBody() {
            return this.peeked.thenCompose(whole -> this.downstream.getBody());
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.upstream = subscription;
            subscription.request(1);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (this.released) {
                this.downstream.onNext(items);
                return;
            }
            for (ByteBuffer item : items) {
                this.size += item.remaining();
                this.held.add(item);
            }
            if (this.size > MAX_NONCE_CHALLENGE_BODY) {
                release(null);
            } else {
                this.upstream.request(1);
            }
        }

        @Override
        public void onError(Throwable throwable) {
            if (this.released) {
                this.downstream.onError(throwable);
                return;
            }
            this.done = true;
            this.failure = throwable;
            release(null);
        }

        @Override
        public void onComplete() {
            if (this.released) {
                this.downstream.onComplete();
                return;
            }
            this.done = true;
            byte[] whole = new byte[(int) this.size];
            int at = 0;
            for (ByteBuffer item : this.held) {
                int n = item.remaining();
                item.duplicate().get(whole, at, n);
                at += n;
            }
            release(whole);
        }

        private void release(byte[] whole) {
            this.released = true;
            this.downstream.onSubscribe(new Flow.Subscription() {
                private boolean replayed;

                @Override
                public synchronized void request(long n) {
                    if (!this.replayed && n > 0) {
                        this.replayed = true;
                        if (!Peek.this.held.isEmpty()) {
                            Peek.this.downstream.onNext(List.copyOf(Peek.this.held));
                            n--;
                        }
                        if (Peek.this.done) {
                            if (Peek.this.failure != null) {
                                Peek.this.downstream.onError(Peek.this.failure);
                            } else {
                                Peek.this.downstream.onComplete();
                            }
                            return;
                        }
                    }
                    if (n != 0 && !Peek.this.done) {
                        Peek.this.upstream.request(n);
                    }
                }

                @Override
                public void cancel() {
                    Peek.this.upstream.cancel();
                }
            });
            this.peeked.complete(whole);
        }
    }

    /**
     * Throws unless {@code url} is https, its host is loopback ({@code localhost}, {@code 127.0.0.1},
     * {@code ::1}), or {@code allowInsecure} is set.
     */
    static void requireSecure(String url, String what, boolean allowInsecure) {
        if (allowInsecure) {
            return;
        }
        String scheme;
        String host;
        try {
            URI uri = URI.create(url);
            scheme = uri.getScheme();
            host = uri.getHost();
        } catch (IllegalArgumentException e) {
            // URI.create refuses characters other clients send unencoded (`|`, `{`, a space in the query):
            // read the scheme and host off the front
            Matcher m = SCHEME_AUTHORITY.matcher(url.strip());
            if (!m.find()) {
                throw new ClientAttestationException(what + " is not a valid URL: " + url, e);
            }
            scheme = m.group(1);
            String authority = m.group(2).substring(m.group(2).lastIndexOf('@') + 1);
            host = authority.startsWith("[") ? authority.substring(0, authority.indexOf(']') + 1)
                    : authority.replaceFirst(":[^:]*$", "");
        }
        if ("https".equalsIgnoreCase(scheme) || isLoopback(host)) {
            return;
        }
        throw new ClientAttestationException(what + " must use https, got " + url
                + " (only loopback hosts are exempt; set allowInsecure(true) to override)");
    }

    static boolean isLoopback(String host) {
        return host != null && LOOPBACK_HOSTS.contains(host.toLowerCase(Locale.ROOT));
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────────────

    static String normalizeBaseUrl(String attesterUrl) {
        if (attesterUrl == null) {
            throw new IllegalArgumentException("attesterUrl is required");
        }
        String host = attesterUrl.strip().replaceAll("/+$", "");
        if (host.isEmpty()) {
            throw new IllegalArgumentException("attesterUrl is required");
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

        /**
         * Response body for HTTP failures: at most the first 512 characters of a non-2xx response, and null
         * for a 2xx response that could not be used, since that body may hold a credential.
         */
        public String body() {
            return this.body;
        }
    }

    /** Options for {@link ClientAttestation}. */
    public static final class Builder {
        private String attesterUrl;
        private AttesterProfile profile;
        private AttesterMetadata metadata;
        private String evidenceAudience;
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
        private System.Logger logger;

        /**
         * Options for a client of the attester at {@code attesterUrl}.
         *
         * @param attesterUrl the attester's host or base URL
         */
        public Builder(String attesterUrl) {
            this.attesterUrl = attesterUrl;
        }

        /** Options with no attester URL yet. */
        public Builder() {
        }

        /**
         * The attester's host or base URL. Optional when {@link #metadata(AttesterMetadata)} or a custom
         * {@link #profile(AttesterProfile)} is given.
         *
         * @param attesterUrl the attester's host or base URL
         * @return this builder
         */
        public Builder attesterUrl(String attesterUrl) {
            this.attesterUrl = attesterUrl;
            return this;
        }

        /**
         * The attester profile that discovers the attester and mints the attestation. Default
         * {@link PingFederateProfile}, the behaviour of every earlier release.
         *
         * @param profile the profile
         * @return this builder
         */
        public Builder profile(AttesterProfile profile) {
            this.profile = profile;
            return this;
        }

        /**
         * Static attester metadata, for an attester that publishes no discovery document: no discovery request
         * is made, and the profile still mints.
         *
         * @param metadata the evidence audience and endpoints
         * @return this builder
         */
        public Builder metadata(AttesterMetadata metadata) {
            this.metadata = metadata;
            return this;
        }

        /**
         * The audience the workload's platform identity token is requested for, which the attester's discovery
         * document must name. Required unless {@link #metadata(AttesterMetadata)} is given: every evidence source
         * (GCP, AWS, Azure, SPIRE) fetches a token for whatever audience it is asked for, so without a pin an
         * attester could have the workload mint a token for another service that trusts it. A missing pin or a
         * different discovered audience throws {@link ClientAttestationException} before any evidence is fetched.
         * With static metadata, the pin is optional and, when given, must match
         * {@link AttesterMetadata#evidenceAudience()}.
         *
         * @param evidenceAudience the audience your attester expects the workload's identity token for
         * @return this builder
         */
        public Builder evidenceAudience(String evidenceAudience) {
            this.evidenceAudience = evidenceAudience;
            return this;
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

        /**
         * Refresh this long before the token expires (default 30s).
         *
         * @throws IllegalArgumentException if {@code expirySkewSeconds} is negative
         */
        public Builder expirySkewSeconds(int expirySkewSeconds) {
            if (expirySkewSeconds < 0) {
                throw new IllegalArgumentException("expirySkewSeconds must not be negative: " + expirySkewSeconds);
            }
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

        /**
         * Where the SDK logs what it does (discovery, minting, the token endpoint, DPoP nonce retries, HTTP
         * failures). Default: nothing is logged. Pass {@code System.getLogger(ClientAttestation.LOGGER_NAME)} to
         * route through {@code java.util.logging} or whatever {@link System.LoggerFinder} is installed.
         * Tokens, attestations, proofs, SVIDs and key material are never logged. Events and attributes are
         * listed in docs/logging.md.
         */
        public Builder logger(System.Logger logger) {
            this.logger = logger;
            return this;
        }

        /** @throws ClientAttestationException if the host is not https, not loopback and not allowed */
        public ClientAttestation build() {
            return new ClientAttestation(this);
        }
    }
}
