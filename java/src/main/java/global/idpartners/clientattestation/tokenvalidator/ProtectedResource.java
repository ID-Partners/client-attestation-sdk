package global.idpartners.clientattestation.tokenvalidator;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jose4j.json.JsonUtil;

/**
 * OAuth 2.0/2.1 protected-resource conventions on top of an {@link AccessTokenValidator}.
 *
 * <p>A {@code ProtectedResource} is the resource-server side of any OAuth-protected HTTP service: an MCP
 * server (an OAuth 2.1 resource server per the MCP authorization spec), an A2A agent, or a plain REST API.
 * It adds what the validator itself does not: RFC 9728 protected-resource metadata
 * ({@code /.well-known/oauth-protected-resource}), RFC 6750 bearer extraction and {@code WWW-Authenticate}
 * challenges, and a request guard that binds the token audience to this resource (RFC 8707) and maps
 * failures to 401 or 403. Nothing here is MCP-only.
 */
public final class ProtectedResource {

    private static final String WELL_KNOWN = "/.well-known/oauth-protected-resource";
    private static final Pattern BEARER = Pattern.compile("^\\s*Bearer\\s+(.+?)\\s*$", Pattern.CASE_INSENSITIVE);

    private final String resource;
    private final List<String> authorizationServers;
    private final List<String> scopesSupported;
    private final AccessTokenValidator validator;

    /**
     * A protected resource with no advertised scopes.
     *
     * @param resource             this resource's identifier, which the validator must accept as an audience
     * @param authorizationServers the authorization servers clients can get a token from
     * @param validator            the validator
     * @throws IllegalArgumentException when the validator does not accept {@code resource} as an audience
     */
    public ProtectedResource(String resource, List<String> authorizationServers, AccessTokenValidator validator) {
        this(resource, authorizationServers, validator, null);
    }

    /**
     * A protected resource. The validator must accept {@code resource} as an audience: that binds incoming
     * tokens to this resource (RFC 8707), which MCP servers must enforce.
     *
     * @param resource             this resource's identifier, which the validator must accept as an audience
     * @param authorizationServers the authorization servers clients can get a token from
     * @param validator            the validator
     * @param scopesSupported      scopes to advertise in the metadata, or null
     * @throws IllegalArgumentException when the validator does not accept {@code resource} as an audience
     */
    public ProtectedResource(String resource, List<String> authorizationServers, AccessTokenValidator validator,
                             List<String> scopesSupported) {
        if (!validator.config().audiences().contains(resource)) {
            throw new IllegalArgumentException(
                    "the validator does not accept this resource (" + resource + ") as an audience");
        }
        this.resource = resource;
        this.authorizationServers = authorizationServers == null ? List.of() : List.copyOf(authorizationServers);
        this.scopesSupported = scopesSupported == null ? List.of() : List.copyOf(scopesSupported);
        this.validator = validator;
    }

    /**
     * The token from an {@code Authorization: Bearer <token>} header value.
     *
     * @param authorizationHeader the header value, or null
     * @return the token, or null when the header is absent, blank or not a Bearer credential
     */
    public static String bearerToken(String authorizationHeader) {
        if (authorizationHeader == null) {
            return null;
        }
        Matcher m = BEARER.matcher(authorizationHeader);
        return m.matches() ? m.group(1) : null;
    }

    public String resource() {
        return this.resource;
    }

    public List<String> authorizationServers() {
        return this.authorizationServers;
    }

    public List<String> scopesSupported() {
        return this.scopesSupported;
    }

    /**
     * The RFC 9728 protected-resource metadata. Serve it as JSON ({@link #metadataJson()}) at
     * {@link #metadataPath()}.
     *
     * @return the metadata document
     */
    public Map<String, Object> metadata() {
        Map<String, Object> md = new LinkedHashMap<>();
        md.put("resource", this.resource);
        md.put("authorization_servers", new ArrayList<>(this.authorizationServers));
        md.put("bearer_methods_supported", List.of("header"));
        if (!this.scopesSupported.isEmpty()) {
            md.put("scopes_supported", new ArrayList<>(this.scopesSupported));
        }
        return md;
    }

    /**
     * The metadata as JSON text.
     *
     * @return the metadata document
     */
    public String metadataJson() {
        return JsonUtil.toJson(metadata());
    }

    /**
     * The path to serve the metadata at, per RFC 9728 section 3: {@code /.well-known/oauth-protected-resource}
     * with the resource's path (if any) appended.
     *
     * @return the metadata path
     */
    public String metadataPath() {
        try {
            String path = new URI(this.resource).getRawPath();
            return path == null || path.isEmpty() || "/".equals(path) ? WELL_KNOWN : WELL_KNOWN + path;
        } catch (Exception e) {
            return WELL_KNOWN;
        }
    }

    /**
     * The absolute URL of the metadata document.
     *
     * @return the metadata URL
     */
    public String metadataUrl() {
        try {
            URI u = new URI(this.resource);
            if (u.getScheme() == null || u.getHost() == null) {
                return metadataPath();
            }
            String host = u.getPort() >= 0 ? u.getHost() + ":" + u.getPort() : u.getHost();
            return u.getScheme() + "://" + host + metadataPath();
        } catch (Exception e) {
            return metadataPath();
        }
    }

    /**
     * The {@code WWW-Authenticate: Bearer ...} header value (RFC 6750 and RFC 9728 section 5.1), always
     * pointing at this resource's metadata. Control characters are dropped from every value, so nothing can
     * split or forge a header.
     *
     * @param error            the RFC 6750 error, or null for a bare challenge
     * @param errorDescription the description, or null
     * @return the header value
     */
    public String challenge(String error, String errorDescription) {
        List<String> params = new ArrayList<>();
        if (error != null && !error.isEmpty()) {
            params.add("error=\"" + quote(error) + "\"");
            if (errorDescription != null && !errorDescription.isEmpty()) {
                params.add("error_description=\"" + quote(errorDescription) + "\"");
            }
        }
        params.add("resource_metadata=\"" + quote(metadataUrl()) + "\"");
        return "Bearer " + String.join(", ", params);
    }

    /**
     * Guard a request against the validator's configured required scopes.
     *
     * @param authorizationHeader the {@code Authorization} header value, or null
     * @return the decision
     */
    public AuthDecision authenticate(String authorizationHeader) {
        return authenticate(authorizationHeader, null);
    }

    /**
     * Guard a request: extract the bearer token, validate it (its audience must be this resource) and return
     * a decision. Missing, invalid, expired or wrong-audience tokens get 401; insufficient scope gets 403.
     *
     * @param authorizationHeader the {@code Authorization} header value, or null
     * @param requiredScopes      scopes this request needs, overriding the configured ones; null uses the
     *                            validator's config
     * @return the decision
     */
    public AuthDecision authenticate(String authorizationHeader, List<String> requiredScopes) {
        String token = bearerToken(authorizationHeader);
        if (token == null) {
            return new AuthDecision(false, null, 401, challenge(null, null), null, "authentication required");
        }
        ValidationResult result = this.validator.validate(token, requiredScopes);
        if (result.valid()) {
            return new AuthDecision(true, result, 200, null, null, null);
        }
        boolean scope = ErrorCodes.INSUFFICIENT_SCOPE.equals(result.error());
        String oauthError = scope ? "insufficient_scope" : "invalid_token";
        return new AuthDecision(false, result, scope ? 403 : 401, challenge(oauthError, result.errorDescription()),
                oauthError, result.errorDescription());
    }

    /**
     * Make a value safe inside a quoted-string: drop CR, LF and every other control character (0x00-0x1F,
     * 0x7F), then escape backslash and double quote.
     */
    static String quote(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                continue;
            }
            if (c == '\\' || c == '"') {
                out.append('\\');
            }
            out.append(c);
        }
        return out.toString();
    }
}
