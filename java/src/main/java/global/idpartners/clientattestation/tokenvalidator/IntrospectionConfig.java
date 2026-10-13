package global.idpartners.clientattestation.tokenvalidator;

import java.util.Objects;

/**
 * An RFC 7662 introspection endpoint and the client credentials the resource server uses to authenticate to
 * the authorization server.
 */
public final class IntrospectionConfig {

    /** HTTP Basic authentication with the client credentials (the default). */
    public static final String CLIENT_SECRET_BASIC = "client_secret_basic";
    /** The client credentials as {@code client_id} and {@code client_secret} form parameters. */
    public static final String CLIENT_SECRET_POST = "client_secret_post";

    private final String endpoint;
    private final String clientId;
    private final String clientSecret;
    private final String authMethod;

    /**
     * Introspection authenticated with {@code client_secret_basic}.
     *
     * @param endpoint     the introspection endpoint URL
     * @param clientId     the resource server's client id at the authorization server
     * @param clientSecret its client secret
     */
    public IntrospectionConfig(String endpoint, String clientId, String clientSecret) {
        this(endpoint, clientId, clientSecret, CLIENT_SECRET_BASIC);
    }

    /**
     * Introspection with an explicit client authentication method.
     *
     * @param endpoint     the introspection endpoint URL
     * @param clientId     the resource server's client id at the authorization server
     * @param clientSecret its client secret
     * @param authMethod   {@link #CLIENT_SECRET_BASIC} or {@link #CLIENT_SECRET_POST}; null or {@code ""} means
     *                     basic, so an unset environment variable can be passed straight in
     * @throws IllegalArgumentException for any other {@code authMethod}, so a typo can't move the secret from the
     *                                  {@code Authorization} header into the form body, or a null or empty
     *                                  {@code clientId} or {@code clientSecret}
     */
    public IntrospectionConfig(String endpoint, String clientId, String clientSecret, String authMethod) {
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint");
        this.clientId = requireCredential(clientId, "clientId");
        this.clientSecret = requireCredential(clientSecret, "clientSecret");
        boolean unset = authMethod == null || authMethod.isEmpty();
        if (!unset && !CLIENT_SECRET_BASIC.equals(authMethod) && !CLIENT_SECRET_POST.equals(authMethod)) {
            // never echo the value: a secret passed in the wrong argument would end up in the message
            throw new IllegalArgumentException("introspection authMethod must be \"" + CLIENT_SECRET_BASIC + "\" or \""
                    + CLIENT_SECRET_POST + "\", got a string of " + authMethod.length() + " characters");
        }
        this.authMethod = unset ? CLIENT_SECRET_BASIC : authMethod;
    }

    /** A client id or secret must be a non-empty string; the message names the field, never the value. */
    private static String requireCredential(String value, String name) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("introspection " + name + " must be a non-empty string, got "
                    + (value == null ? "null" : "an empty string"));
        }
        return value;
    }

    public String endpoint() {
        return this.endpoint;
    }

    public String clientId() {
        return this.clientId;
    }

    public String clientSecret() {
        return this.clientSecret;
    }

    public String authMethod() {
        return this.authMethod;
    }

    /** Leaves the client secret out. */
    @Override
    public String toString() {
        return "IntrospectionConfig[endpoint=" + this.endpoint + ", clientId=" + this.clientId + ", authMethod="
                + this.authMethod + "]";
    }
}
