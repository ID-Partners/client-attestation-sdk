package global.idpartners.clientattestation.tokenvalidator;

import global.idpartners.clientattestation.TransportException;
import global.idpartners.clientattestation.internal.HttpTransport;
import java.net.URI;
import java.net.http.HttpRequest;
import java.util.Map;

/**
 * Minimal authorization-server metadata discovery (RFC 8414 / OpenID Connect Discovery).
 */
public final class Discovery {

    private Discovery() {
    }

    /**
     * Fetch an authorization-server metadata document, for example
     * {@code https://issuer.example.com/.well-known/oauth-authorization-server}. The result carries
     * {@code issuer}, {@code jwks_uri} and {@code introspection_endpoint} to feed into a
     * {@link ValidatorConfig}. Uses the SDK's shared transport: a 10s timeout, no redirects and a 1 MiB cap.
     *
     * @param metadataUrl the metadata document URL
     * @return the metadata
     * @throws TransportException when the fetch fails or the document is not a JSON object
     */
    public static Map<String, Object> discover(String metadataUrl) {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(metadataUrl)).GET()
                .header("Accept", "application/json");
        return HttpTransport.jsonOk(HttpTransport.send(HttpTransport.client(AccessTokenValidator.HTTP_TIMEOUT),
                req, AccessTokenValidator.HTTP_TIMEOUT));
    }

    /**
     * As {@link #discover(String)}, through an injected transport.
     *
     * @param metadataUrl the metadata document URL
     * @param httpGet     the transport
     * @return the metadata
     * @throws TransportException when the document is not a JSON object
     */
    public static Map<String, Object> discover(String metadataUrl, AccessTokenValidator.HttpGet httpGet) {
        return HttpTransport.parseObject(httpGet.get(metadataUrl), 200);
    }
}
