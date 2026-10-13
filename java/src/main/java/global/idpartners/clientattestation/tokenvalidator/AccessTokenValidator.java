package global.idpartners.clientattestation.tokenvalidator;

import global.idpartners.clientattestation.TransportException;
import global.idpartners.clientattestation.internal.HttpTransport;
import global.idpartners.clientattestation.internal.SdkLog;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

/**
 * Validates access tokens for a resource server.
 *
 * <p>{@link #validate(String)} does local JWT validation in a fixed order: algorithm accepted, key
 * resolvable, signature, {@code typ} (when present), {@code iss}, {@code exp} present, {@code exp},
 * {@code nbf}, {@code iat} not in the future, audience, then scope. It returns the first failure's stable
 * error code (see {@link ErrorCodes}). That order is part of the cross-language contract, so every port
 * reports the same verdict. {@link #validateActive(String)} uses RFC 7662 introspection instead.
 *
 * <p>Thread-safe: one validator can serve every request.
 */
public final class AccessTokenValidator {

    /** A fetched JWKS larger than this is refused. */
    public static final long MAX_JWKS_BYTES = 512L * 1024;
    /** An introspection response larger than this is refused. */
    public static final long MAX_INTROSPECTION_BYTES = 1024L * 1024;
    /** A {@code jwks_uri} is fetched at most once per this interval, whatever tokens arrive. */
    public static final Duration DEFAULT_JWKS_MIN_REFRESH = Duration.ofSeconds(30);
    /** A fetched JWKS is refetched once it is this old. */
    public static final Duration DEFAULT_JWKS_MAX_AGE = Duration.ofHours(1);

    static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);

    /** Fetches a URL and returns its body; injectable so tests can avoid real HTTP. */
    @FunctionalInterface
    public interface HttpGet {
        /**
         * GET {@code url}.
         *
         * @param url the URL
         * @return the response body of a 2xx answer
         * @throws RuntimeException on any failure ({@link TransportException} lets it be classified in logs)
         */
        String get(String url);
    }

    /** POSTs a form and returns the parsed JSON response; injectable so tests can avoid real HTTP. */
    @FunctionalInterface
    public interface HttpPost {
        /**
         * POST {@code body} to {@code url}.
         *
         * @param url     the URL
         * @param body    the {@code application/x-www-form-urlencoded} body
         * @param headers the request headers
         * @return the JSON object of a 2xx answer
         * @throws RuntimeException on any failure ({@link TransportException} lets it be classified in logs)
         */
        Map<String, Object> post(String url, String body, Map<String, String> headers);
    }

    private final ValidatorConfig config;
    private final JwksProvider jwks;
    private final HttpPost httpPost;
    private final LongSupplier clock;
    private final ValidatorLog log;
    private HttpClient client;   // created on first use of the default transport

    /**
     * A validator with the default transport and no logging.
     *
     * @param config what this resource server accepts
     */
    public AccessTokenValidator(ValidatorConfig config) {
        this(builder(config));
    }

    private AccessTokenValidator(Builder b) {
        if (b.config == null) {
            throw new IllegalArgumentException("config is required");
        }
        this.config = b.config;
        this.clock = b.clock;
        this.log = new ValidatorLog(b.logger);
        this.httpPost = b.httpPost != null ? b.httpPost : this::defaultPost;
        HttpGet get = b.httpGet != null ? b.httpGet : this::defaultGet;
        this.jwks = new JwksProvider(b.config.jwks(), b.config.jwksUri(), get, b.jwksClock, this.log);
    }

    /**
     * A builder, for a logger or an injected transport.
     *
     * @param config what this resource server accepts
     * @return the builder
     */
    public static Builder builder(ValidatorConfig config) {
        return new Builder(config);
    }

    /**
     * The config this validator enforces.
     *
     * @return the config
     */
    public ValidatorConfig config() {
        return this.config;
    }

    JwksProvider jwksProvider() {
        return this.jwks;
    }

    /**
     * Validate a JWT access token locally against the configured required scopes.
     *
     * @param token the access token
     * @return the verdict
     */
    public ValidationResult validate(String token) {
        return validate(token, null);
    }

    /**
     * Validate a JWT access token locally.
     *
     * @param token          the access token
     * @param requiredScopes scopes the token must carry, overriding the configured ones; null uses the config
     * @return the verdict
     */
    public ValidationResult validate(String token, List<String> requiredScopes) {
        return verdict(doValidate(token, requiredScopes), "jwt");
    }

    private ValidationResult verdict(ValidationResult result, String mode) {
        String code = result.valid() ? ErrorCodes.VALID : result.error();
        if (result.valid()) {
            this.log.debug("token.validated", "result", code, "mode", mode);
        } else {
            this.log.info("token.validated", "result", code, "mode", mode);
        }
        return result;
    }

    private ValidationResult doValidate(String token, List<String> requiredScopes) {
        List<String> required = requiredScopes != null ? requiredScopes : this.config.requiredScopes();

        Strict.Compact parts;
        try {
            parts = Strict.splitCompact(token);
        } catch (Strict.Malformed e) {
            // never echo token data to the caller: the description lands in WWW-Authenticate
            return ValidationResult.failure(ErrorCodes.INVALID_TOKEN, "malformed token");
        }
        Map<String, Object> header = parts.header;

        Object alg = header.get("alg");
        if (!(alg instanceof String) || Strict.isForbiddenAlgorithm((String) alg)
                || !this.config.acceptedAlgorithms().contains(alg)) {
            // never echo the unverified header alg back to the caller (it lands in WWW-Authenticate)
            return ValidationResult.failure(ErrorCodes.UNSUPPORTED_ALGORITHM, "algorithm not accepted");
        }
        String algorithm = (String) alg;

        Object kid = header.get("kid");
        Key key = kid == null || kid instanceof String ? this.jwks.resolve((String) kid, algorithm) : null;
        if (key == null) {
            // a fetch failure's detail (internal host, dial error, IdP body) went to the logger as
            // jwks.fetch_failed; the description lands in WWW-Authenticate, in front of anyone
            return ValidationResult.failure(ErrorCodes.KEY_NOT_FOUND,
                    this.jwks.lastError() != null ? "signing keys unavailable" : "no signing key for this kid");
        }

        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(token);
            jws.setAlgorithmConstraints(
                    new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, algorithm));
            jws.setKey(key);
            if (!jws.verifySignature()) {
                return ValidationResult.failure(ErrorCodes.INVALID_SIGNATURE, "signature verification failed");
            }
        } catch (JoseException | RuntimeException e) {
            return ValidationResult.failure(ErrorCodes.INVALID_SIGNATURE, "signature verification failed");
        }
        Map<String, Object> claims;
        try {
            claims = Strict.parseObject(parts.payload, "payload");
        } catch (Strict.Malformed e) {
            return ValidationResult.failure(ErrorCodes.INVALID_TOKEN, e.getMessage());
        }

        Object typ = header.get("typ");
        List<String> types = this.config.acceptedTokenTypes();
        if (typ != null && types != null
                && (!(typ instanceof String) || !types.contains(ValidatorConfig.normaliseType((String) typ)))) {
            return ValidationResult.failure(ErrorCodes.INVALID_TOKEN_TYPE, "token is not a JWT access token");
        }

        if (!this.config.issuer().equals(claims.get("iss"))) {
            return ValidationResult.failure(ErrorCodes.INVALID_ISSUER, "unexpected issuer");
        }

        long now = Math.floorDiv(this.clock.getAsLong(), 1000L);
        long leeway = this.config.leewaySeconds();
        Long exp;
        Long nbf;
        Long iat;
        try {
            exp = Strict.numericDate(claims, "exp");
            nbf = Strict.numericDate(claims, "nbf");
            iat = Strict.numericDate(claims, "iat");
        } catch (Strict.Malformed e) {
            return ValidationResult.failure(ErrorCodes.INVALID_TOKEN, e.getMessage());
        }
        if (exp == null) {
            return ValidationResult.failure(ErrorCodes.MISSING_EXPIRY, "token has no exp claim");
        }
        if (now > exp + leeway) {
            return ValidationResult.failure(ErrorCodes.EXPIRED, "token has expired");
        }
        if (nbf != null && now + leeway < nbf) {
            return ValidationResult.failure(ErrorCodes.NOT_YET_VALID, "token is not yet valid");
        }
        if (iat != null && now + leeway < iat) {
            return ValidationResult.failure(ErrorCodes.ISSUED_IN_FUTURE, "token was issued in the future");
        }

        try {
            List<String> audience = Strict.audience(claims);
            if (!anyIn(this.config.audiences(), audience)) {
                return ValidationResult.failure(ErrorCodes.INVALID_AUDIENCE, "token audience is not accepted");
            }
            List<String> granted = Strict.scopes(claims);
            List<String> missing = missing(required, granted);
            if (!missing.isEmpty()) {
                return ValidationResult.failure(ErrorCodes.INSUFFICIENT_SCOPE,
                        "missing scopes: " + String.join(" ", missing));
            }
            Strict.subject(claims);
            return ValidationResult.success(claims, granted, audience);
        } catch (Strict.Malformed e) {
            return ValidationResult.failure(ErrorCodes.INVALID_TOKEN, e.getMessage());
        }
    }

    /**
     * RFC 7662: POST the token to the introspection endpoint (with {@code token_type_hint=access_token}) and
     * return the parsed response.
     *
     * @param token the token to introspect
     * @return the introspection response
     * @throws IllegalStateException when no introspection endpoint is configured
     * @throws TransportException    when the call fails (the default transport)
     */
    public Map<String, Object> introspect(String token) {
        return introspect(token, "access_token");
    }

    /**
     * RFC 7662: POST the token to the introspection endpoint and return the parsed response.
     *
     * @param token         the token to introspect
     * @param tokenTypeHint the {@code token_type_hint}, or null to send none
     * @return the introspection response
     * @throws IllegalStateException when no introspection endpoint is configured
     * @throws TransportException    when the call fails (the default transport)
     */
    public Map<String, Object> introspect(String token, String tokenTypeHint) {
        IntrospectionConfig cfg = this.config.introspection();
        if (cfg == null) {
            throw new IllegalStateException("no introspection endpoint configured");
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("token", token);
        if (tokenTypeHint != null) {
            form.put("token_type_hint", tokenTypeHint);
        }
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/x-www-form-urlencoded");
        headers.put("Accept", "application/json");
        if (IntrospectionConfig.CLIENT_SECRET_POST.equals(cfg.authMethod())) {
            form.put("client_id", cfg.clientId());
            form.put("client_secret", cfg.clientSecret());
        } else { // client_secret_basic: IntrospectionConfig refuses anything but the two, or unset
            headers.put("Authorization", basicAuthorization(cfg.clientId(), cfg.clientSecret()));
        }
        try {
            Map<String, Object> data = this.httpPost.post(cfg.endpoint(), formEncode(form), headers);
            if (data == null) {
                throw new IllegalStateException("introspection returned no response");
            }
            return data;
        } catch (RuntimeException e) {
            int status = e instanceof TransportException ? ((TransportException) e).status() : 0;
            this.log.warn("http.failed", "step", "introspection", "method", "POST",
                    "host", SdkLog.host(cfg.endpoint()), "path", SdkLog.path(cfg.endpoint()),
                    "status", status > 0 ? status : null, "reason", HttpTransport.failureReason(e));
            throw e;
        }
    }

    /**
     * Introspect the token and enforce {@code active}, then the configured required scopes, then the
     * audience when the response carries one.
     *
     * @param token the token
     * @return the verdict
     * @throws IllegalStateException when no introspection endpoint is configured
     * @throws TransportException    when the introspection call fails (the default transport)
     */
    public ValidationResult validateActive(String token) {
        return validateActive(token, null);
    }

    /**
     * Introspect the token and enforce {@code active}, then scope, then the audience when the response
     * carries one.
     *
     * @param token          the token
     * @param requiredScopes scopes the token must carry, overriding the configured ones; null uses the config
     * @return the verdict
     * @throws IllegalStateException when no introspection endpoint is configured
     * @throws TransportException    when the introspection call fails (the default transport)
     */
    public ValidationResult validateActive(String token, List<String> requiredScopes) {
        Map<String, Object> data = introspect(token);
        return verdict(doValidateActive(data, requiredScopes), "introspection");
    }

    private ValidationResult doValidateActive(Map<String, Object> data, List<String> requiredScopes) {
        // RFC 7662 section 2.2: active is a boolean, so only JSON true counts
        if (!Boolean.TRUE.equals(data.get("active"))) {
            return ValidationResult.failure(ErrorCodes.INACTIVE, "token is not active");
        }
        List<String> required = requiredScopes != null ? requiredScopes : this.config.requiredScopes();
        try {
            List<String> granted = Strict.scopes(data);
            List<String> missing = missing(required, granted);
            if (!missing.isEmpty()) {
                return ValidationResult.failure(ErrorCodes.INSUFFICIENT_SCOPE,
                        "missing scopes: " + String.join(" ", missing));
            }
            List<String> audience = Strict.audience(data);
            if (!audience.isEmpty() && !anyIn(this.config.audiences(), audience)) {
                return ValidationResult.failure(ErrorCodes.INVALID_AUDIENCE, "token audience is not accepted");
            }
            Strict.subject(data);
            return ValidationResult.success(data, granted, audience);
        } catch (Strict.Malformed e) {
            return ValidationResult.failure(ErrorCodes.INVALID_TOKEN, e.getMessage());
        }
    }

    // ── default transport ───────────────────────────────────────────────────────────────────────────

    private synchronized HttpClient client() {
        if (this.client == null) {
            this.client = HttpTransport.client(HTTP_TIMEOUT);
        }
        return this.client;
    }

    /** GET with the shared transport: no redirects, a 10s timeout and the JWKS size cap. */
    private String defaultGet(String url) {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(url)).GET().header("Accept", "application/json");
        return HttpTransport.textOk(HttpTransport.send(client(), req, HTTP_TIMEOUT, MAX_JWKS_BYTES));
    }

    /**
     * POST with the shared transport, which never follows a redirect (it would carry the credentials) and
     * refuses a body over {@link #MAX_INTROSPECTION_BYTES}. The JSON is parsed strictly.
     */
    private Map<String, Object> defaultPost(String url, String body, Map<String, String> headers) {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(url))
                .POST(HttpRequest.BodyPublishers.ofString(body));
        headers.forEach(req::header);
        HttpTransport.Response response =
                HttpTransport.send(client(), req, HTTP_TIMEOUT, MAX_INTROSPECTION_BYTES);
        String text = HttpTransport.textOk(response);
        try {
            return Strict.parseObject(text, "introspection response");
        } catch (Strict.Malformed e) {
            throw HttpTransport.malformed("introspection endpoint returned " + e.getMessage(), response.status());
        }
    }

    // ── claim helpers ───────────────────────────────────────────────────────────────────────────────

    private static boolean anyIn(List<String> want, List<String> have) {
        for (String w : want) {
            if (have.contains(w)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> missing(List<String> required, List<String> granted) {
        List<String> out = new ArrayList<>();
        for (String r : required) {
            if (!granted.contains(r)) {
                out.add(r);
            }
        }
        return out;
    }

    /**
     * The {@code client_secret_basic} Authorization header value (RFC 6749 section 2.3.1): the client id and the
     * secret are each form-urlencoded (Appendix B), joined with {@code :} and base64'd. The encoding is the same
     * bytes as Python's {@code urllib.parse.quote_plus(s, safe="")}: each UTF-8 byte of
     * {@code A-Z a-z 0-9 - . _ ~} stays as it is, a space becomes {@code +}, and every other byte is {@code %XX}
     * with uppercase hex (so {@code :} is {@code %3A}, {@code %} is {@code %25}, {@code +} is {@code %2B} and
     * {@code *} is {@code %2A}). Not {@link URLEncoder}, which leaves {@code *} alone and encodes {@code ~}.
     * validation/SEMANTICS.md, Introspection.
     */
    static String basicAuthorization(String clientId, String clientSecret) {
        String raw = credentialEncode(clientId) + ":" + credentialEncode(clientSecret);
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.US_ASCII));
    }

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private static String credentialEncode(String value) {
        StringBuilder out = new StringBuilder();
        for (byte raw : String.valueOf(value).getBytes(StandardCharsets.UTF_8)) {
            int b = raw & 0xff;
            if (b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
                    || b == '-' || b == '.' || b == '_' || b == '~') {
                out.append((char) b);
            } else if (b == ' ') {
                out.append('+');
            } else {
                out.append('%').append(HEX[b >> 4]).append(HEX[b & 0x0f]);
            }
        }
        return out.toString();
    }

    private static String formEncode(Map<String, String> form) {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> e : form.entrySet()) {
            if (out.length() > 0) {
                out.append('&');
            }
            out.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)).append('=')
                    .append(URLEncoder.encode(String.valueOf(e.getValue()), StandardCharsets.UTF_8));
        }
        return out.toString();
    }

    /** Options for {@link AccessTokenValidator}. */
    public static final class Builder {
        private final ValidatorConfig config;
        private HttpGet httpGet;
        private HttpPost httpPost;
        private System.Logger logger;
        private LongSupplier clock = System::currentTimeMillis;
        private LongSupplier jwksClock = JwksProvider::monotonicMillis;

        private Builder(ValidatorConfig config) {
            this.config = config;
        }

        /**
         * The transport used to fetch the {@code jwks_uri}. Default: the SDK's shared transport (10s timeout,
         * no redirects, a {@link #MAX_JWKS_BYTES} body cap).
         *
         * @param httpGet the transport
         * @return this builder
         */
        public Builder httpGet(HttpGet httpGet) {
            this.httpGet = httpGet;
            return this;
        }

        /**
         * The transport used for introspection. Default: the SDK's shared transport (10s timeout, no
         * redirects, a {@link #MAX_INTROSPECTION_BYTES} body cap). A response that is not a JSON object is a
         * {@link TransportException}.
         *
         * @param httpPost the transport
         * @return this builder
         */
        public Builder httpPost(HttpPost httpPost) {
            this.httpPost = httpPost;
            return this;
        }

        /**
         * Where the validator logs its events: {@code token.validated}, {@code jwks.fetched},
         * {@code jwks.fetch_failed}, {@code jwks.refetch_throttled} and {@code http.failed} (step
         * {@code introspection}); see docs/logging.md. Default: nothing is logged. Pass
         * {@code System.getLogger(ClientAttestation.LOGGER_NAME)} to route through {@code java.util.logging} or
         * whatever {@link System.LoggerFinder} is installed. No token or client secret is ever logged: a
         * verdict carries only its stable error code.
         *
         * @param logger the logger
         * @return this builder
         */
        public Builder logger(System.Logger logger) {
            this.logger = logger;
            return this;
        }

        /**
         * The clock {@code exp}, {@code nbf} and {@code iat} are checked against, in epoch milliseconds. Default:
         * {@link System#currentTimeMillis()}. Inject one to validate as of a fixed instant. The JWKS cache does not
         * use it: the key set ages, and refetches are spaced, on {@link System#nanoTime()}.
         *
         * @param clock the epoch-millisecond clock
         * @return this builder
         */
        public Builder clock(LongSupplier clock) {
            this.clock = clock;
            return this;
        }

        /** Tests only: the monotonic millisecond clock the JWKS cache ages by, instead of {@code nanoTime}. */
        Builder jwksClock(LongSupplier jwksClock) {
            this.jwksClock = jwksClock;
            return this;
        }

        /**
         * The validator.
         *
         * @return the validator
         */
        public AccessTokenValidator build() {
            return new AccessTokenValidator(this);
        }
    }
}
