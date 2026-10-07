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
     * @param authMethod   {@link #CLIENT_SECRET_BASIC} or {@link #CLIENT_SECRET_POST}; null means basic
     */
    public IntrospectionConfig(String endpoint, String clientId, String clientSecret, String authMethod) {
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint");
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.authMethod = authMethod == null ? CLIENT_SECRET_BASIC : authMethod;
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
