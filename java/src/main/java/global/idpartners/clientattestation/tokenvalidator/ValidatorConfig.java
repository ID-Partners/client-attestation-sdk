package global.idpartners.clientattestation.tokenvalidator;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

/**
 * What a resource server accepts: the trusted issuer, its own audience identifier(s), the signing keys (a
 * static JWKS or a {@code jwks_uri} to fetch), required scopes, accepted algorithms, clock leeway, accepted
 * token types and optional introspection.
 *
 * <p>The issuer and at least one audience are required: {@link Builder#build()} refuses a config without
 * them, because a validator that skips either accepts tokens minted for someone else. It also refuses a
 * {@code jwks_uri} or introspection endpoint that is not https, unless its host is loopback ({@code localhost},
 * {@code 127.0.0.1}, {@code ::1}) or {@link Builder#allowInsecure(boolean)} is set: over plain http anyone on
 * the path could serve their own keys, or read the resource server's client secret.
 */
public final class ValidatorConfig {

    /** Accepted algorithms by default: ECDSA, RSA PKCS#1 and RSA-PSS at 256/384/512. */
    public static final List<String> DEFAULT_ALGORITHMS = List.of(
            "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512");

    /** Accepted {@code typ} values by default: RFC 9068 section 2.1 {@code at+jwt}. */
    public static final List<String> DEFAULT_TOKEN_TYPES = List.of("at+jwt");

    /** Clock skew allowed on {@code exp}, {@code nbf} and {@code iat} by default, in seconds. */
    public static final int DEFAULT_LEEWAY_SECONDS = 60;

    private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "::1", "[::1]");

    private final String issuer;
    private final List<String> audiences;
    private final Map<String, Object> jwks;
    private final String jwksUri;
    private final List<String> requiredScopes;
    private final List<String> acceptedAlgorithms;
    private final int leewaySeconds;
    private final List<String> acceptedTokenTypes;
    private final IntrospectionConfig introspection;
    private final boolean allowInsecure;

    private ValidatorConfig(Builder b) {
        if (b.issuer == null || b.issuer.isEmpty()) {
            throw new IllegalArgumentException("issuer is required");
        }
        if (b.audiences.isEmpty()) {
            throw new IllegalArgumentException("at least one audience is required");
        }
        if (b.leewaySeconds < 0) {
            throw new IllegalArgumentException("leewaySeconds must not be negative");
        }
        if (b.jwksUri != null && !b.jwksUri.isEmpty()) {
            requireSecure(b.jwksUri, "jwks_uri", b.allowInsecure);
        }
        if (b.introspection != null) {
            requireSecure(b.introspection.endpoint(), "introspection endpoint", b.allowInsecure);
        }
        this.issuer = b.issuer;
        this.audiences = List.copyOf(b.audiences);
        this.jwks = b.jwks == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(b.jwks));
        this.jwksUri = b.jwksUri;
        this.requiredScopes = List.copyOf(b.requiredScopes);
        this.acceptedAlgorithms = List.copyOf(b.acceptedAlgorithms);
        this.leewaySeconds = b.leewaySeconds;
        if (b.acceptedTokenTypes == null) {
            this.acceptedTokenTypes = null;
        } else {
            List<String> types = new ArrayList<>();
            for (String t : b.acceptedTokenTypes) {
                types.add(normaliseType(t));
            }
            this.acceptedTokenTypes = List.copyOf(types);
        }
        this.introspection = b.introspection;
        this.allowInsecure = b.allowInsecure;
    }

    /**
     * A new builder.
     *
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
    }

    public String issuer() {
        return this.issuer;
    }

    public List<String> audiences() {
        return this.audiences;
    }

    /**
     * The static JWKS, or null when keys come from {@link #jwksUri()}.
     *
     * @return the JWKS document ({@code {"keys":[...]}}), or null
     */
    public Map<String, Object> jwks() {
        return this.jwks;
    }

    public String jwksUri() {
        return this.jwksUri;
    }

    public List<String> requiredScopes() {
        return this.requiredScopes;
    }

    public List<String> acceptedAlgorithms() {
        return this.acceptedAlgorithms;
    }

    public int leewaySeconds() {
        return this.leewaySeconds;
    }

    /**
     * The accepted {@code typ} header values, normalised, or null when the check is off.
     *
     * @return the accepted token types, or null
     */
    public List<String> acceptedTokenTypes() {
        return this.acceptedTokenTypes;
    }

    public IntrospectionConfig introspection() {
        return this.introspection;
    }

    /**
     * Whether a plain-http {@code jwks_uri} and introspection endpoint are allowed on non-loopback hosts.
     *
     * @return true when {@link Builder#allowInsecure(boolean)} was set
     */
    public boolean allowInsecure() {
        return this.allowInsecure;
    }

    /**
     * Throws unless {@code url} is https, its host is loopback ({@code localhost}, {@code 127.0.0.1},
     * {@code ::1}), or {@code allowInsecure} is set: the rule the client applies to its own endpoints.
     */
    static void requireSecure(String url, String what, boolean allowInsecure) {
        if (allowInsecure) {
            return;
        }
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(what + " is not a valid URL: " + url, e);
        }
        String host = uri.getHost();
        if ("https".equalsIgnoreCase(uri.getScheme())
                || host != null && LOOPBACK_HOSTS.contains(host.toLowerCase(Locale.ROOT))) {
            return;
        }
        throw new IllegalArgumentException(what + " must use https, got " + url
                + " (only loopback hosts are exempt; set allowInsecure(true) to override)");
    }

    /**
     * Compare JOSE {@code typ} values the way RFC 7515 section 4.1.9 says to: case-insensitively, with an
     * optional {@code application/} prefix.
     */
    static String normaliseType(String value) {
        String lower = String.valueOf(value).toLowerCase(Locale.ROOT);
        return lower.startsWith("application/") ? lower.substring("application/".length()) : lower;
    }

    /** Builds a {@link ValidatorConfig}. */
    public static final class Builder {
        private String issuer;
        private final List<String> audiences = new ArrayList<>();
        private Map<String, Object> jwks;
        private String jwksUri;
        private List<String> requiredScopes = List.of();
        private List<String> acceptedAlgorithms = DEFAULT_ALGORITHMS;
        private int leewaySeconds = DEFAULT_LEEWAY_SECONDS;
        private List<String> acceptedTokenTypes = DEFAULT_TOKEN_TYPES;
        private IntrospectionConfig introspection;
        private boolean allowInsecure;

        private Builder() {
        }

        /**
         * The expected {@code iss} claim. Required.
         *
         * @param issuer the issuer identifier
         * @return this builder
         */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /**
         * This resource server's accepted audience identifiers, replacing any set before. At least one is
         * required.
         *
         * @param audiences the audiences
         * @return this builder
         */
        public Builder audiences(String... audiences) {
            return audiences(Arrays.asList(audiences));
        }

        /**
         * This resource server's accepted audience identifiers, replacing any set before. At least one is
         * required.
         *
         * @param audiences the audiences
         * @return this builder
         */
        public Builder audiences(List<String> audiences) {
            this.audiences.clear();
            if (audiences != null) {
                for (String a : audiences) {
                    if (a != null) {
                        this.audiences.add(a);
                    }
                }
            }
            return this;
        }

        /**
         * A static JSON Web Key Set ({@code {"keys":[...]}}). Keys that cannot be read are skipped.
         *
         * @param jwks the JWKS document
         * @return this builder
         */
        public Builder jwks(Map<String, Object> jwks) {
            this.jwks = jwks;
            return this;
        }

        /**
         * A static JSON Web Key Set as JSON text.
         *
         * @param jwksJson the JWKS document
         * @return this builder
         * @throws IllegalArgumentException if {@code jwksJson} is not a JSON object
         */
        public Builder jwks(String jwksJson) {
            try {
                this.jwks = JsonUtil.parseJson(jwksJson);
            } catch (JoseException | RuntimeException e) {
                throw new IllegalArgumentException("jwks is not a JSON object", e);
            }
            return this;
        }

        /**
         * Where to fetch the issuer's JWKS when no static {@link #jwks(Map)} is given. The set is cached, and
         * refetched on an unknown {@code kid} or once it is an hour old, but never more than once every 30
         * seconds.
         *
         * @param jwksUri the issuer's {@code jwks_uri}
         * @return this builder
         */
        public Builder jwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
            return this;
        }

        /**
         * Scopes every token must carry, unless a call passes its own list.
         *
         * @param scopes the required scopes
         * @return this builder
         */
        public Builder requiredScopes(String... scopes) {
            return requiredScopes(Arrays.asList(scopes));
        }

        /**
         * Scopes every token must carry, unless a call passes its own list.
         *
         * @param scopes the required scopes
         * @return this builder
         */
        public Builder requiredScopes(List<String> scopes) {
            this.requiredScopes = scopes == null ? List.of() : List.copyOf(scopes);
            return this;
        }

        /**
         * The accepted {@code alg} header values. Default: {@link #DEFAULT_ALGORITHMS}.
         *
         * @param algorithms the accepted algorithms
         * @return this builder
         */
        public Builder acceptedAlgorithms(String... algorithms) {
            return acceptedAlgorithms(Arrays.asList(algorithms));
        }

        /**
         * The accepted {@code alg} header values. Default: {@link #DEFAULT_ALGORITHMS}; null restores it, and an
         * empty list accepts nothing. {@code none} and the {@code HS*} algorithms are refused even when listed.
         *
         * @param algorithms the accepted algorithms
         * @return this builder
         */
        public Builder acceptedAlgorithms(List<String> algorithms) {
            this.acceptedAlgorithms = algorithms == null ? DEFAULT_ALGORITHMS : List.copyOf(algorithms);
            return this;
        }

        /**
         * Clock skew allowed on {@code exp}, {@code nbf} and {@code iat}, in seconds. Default:
         * {@link #DEFAULT_LEEWAY_SECONDS}; 0 allows none. {@link #build()} refuses a negative leeway.
         *
         * @param leewaySeconds the leeway
         * @return this builder
         */
        public Builder leewaySeconds(int leewaySeconds) {
            this.leewaySeconds = leewaySeconds;
            return this;
        }

        /**
         * The accepted {@code typ} header values, checked when a token carries one so an ID token cannot stand
         * in for an access token. Compared case-insensitively, with an optional {@code application/} prefix.
         * Default: {@link #DEFAULT_TOKEN_TYPES}.
         *
         * @param types the accepted token types
         * @return this builder
         */
        public Builder acceptedTokenTypes(String... types) {
            return acceptedTokenTypes(Arrays.asList(types));
        }

        /**
         * The accepted {@code typ} header values; null turns the check off (see
         * {@link #disableTokenTypeCheck()}).
         *
         * @param types the accepted token types, or null
         * @return this builder
         */
        public Builder acceptedTokenTypes(List<String> types) {
            this.acceptedTokenTypes = types == null ? null : List.copyOf(types);
            return this;
        }

        /**
         * Turn the {@code typ} check off, for an issuer that stamps something other than {@code at+jwt}.
         *
         * @return this builder
         */
        public Builder disableTokenTypeCheck() {
            this.acceptedTokenTypes = null;
            return this;
        }

        /**
         * Enable {@link AccessTokenValidator#validateActive(String)} through RFC 7662 introspection.
         *
         * @param introspection the introspection endpoint and credentials
         * @return this builder
         */
        public Builder introspection(IntrospectionConfig introspection) {
            this.introspection = introspection;
            return this;
        }

        /**
         * Allow a plain-http {@code jwks_uri} and introspection endpoint on non-loopback hosts. Default: false,
         * and {@link #build()} refuses them.
         *
         * @param allowInsecure whether to allow plain http
         * @return this builder
         */
        public Builder allowInsecure(boolean allowInsecure) {
            this.allowInsecure = allowInsecure;
            return this;
        }

        /**
         * The config.
         *
         * @return the config
         * @throws IllegalArgumentException without an issuer or an audience, with a negative leeway, or with a
         *                                  plain-http {@code jwks_uri} or introspection endpoint on a non-loopback
         *                                  host without {@link #allowInsecure(boolean)}
         */
        public ValidatorConfig build() {
            return new ValidatorConfig(this);
        }
    }
}
