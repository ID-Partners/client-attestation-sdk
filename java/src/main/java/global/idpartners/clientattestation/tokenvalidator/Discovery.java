package global.idpartners.clientattestation.tokenvalidator;

import global.idpartners.clientattestation.TransportException;
import global.idpartners.clientattestation.internal.HttpTransport;
import java.net.URI;
import java.net.http.HttpRequest;
import java.util.Locale;
import java.util.Map;

/**
 * Minimal authorization-server metadata discovery (RFC 8414 / OpenID Connect Discovery).
 *
 * <p>The document is only returned when its {@code issuer} is the issuer it was asked for (RFC 8414 section
 * 3.3): the explicit one, or else the one the metadata URL was built from. Without that check, whoever can
 * answer for the metadata URL picks the issuer and keys the validator trusts. The metadata URL and the
 * returned {@code jwks_uri} and {@code introspection_endpoint} must use https unless their host is loopback
 * ({@code localhost}, {@code 127.0.0.1}, {@code ::1}) or {@code allowInsecure} is passed, as in
 * {@link ValidatorConfig}.
 */
public final class Discovery {

    private static final String[] WELL_KNOWN = {
        "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"};

    private Discovery() {
    }

    /**
     * Fetch an authorization-server metadata document, for example
     * {@code https://issuer.example.com/.well-known/oauth-authorization-server}. The result carries
     * {@code issuer}, {@code jwks_uri} and {@code introspection_endpoint} to feed into a
     * {@link ValidatorConfig}. Uses the SDK's shared transport: a 10s timeout, no redirects and a 1 MiB cap.
     *
     * <p>The expected issuer comes from the URL: {@code /.well-known/oauth-authorization-server} or
     * {@code /.well-known/openid-configuration} inserted after the host (RFC 8414 section 3.1) or appended to
     * the issuer (OpenID Connect Discovery section 4). For any other URL, pass the issuer with
     * {@link #discover(String, String, AccessTokenValidator.HttpGet)}.
     *
     * @param metadataUrl the metadata document URL
     * @return the metadata
     * @throws IllegalArgumentException when the URL is not https (loopback exempt) or names no issuer
     * @throws TransportException       when the fetch fails, the document is not a strict JSON object, its
     *                                  {@code issuer} is not the expected one, or an endpoint in it is not https
     */
    public static Map<String, Object> discover(String metadataUrl) {
        return discover(metadataUrl, null, null, false);
    }

    /**
     * As {@link #discover(String)}, through an injected transport.
     *
     * @param metadataUrl the metadata document URL
     * @param httpGet     the transport
     * @return the metadata
     * @throws IllegalArgumentException when the URL is not https (loopback exempt) or names no issuer
     * @throws TransportException       when the document is not a strict JSON object, its {@code issuer} is not
     *                                  the expected one, or an endpoint in it is not https
     */
    public static Map<String, Object> discover(String metadataUrl, AccessTokenValidator.HttpGet httpGet) {
        return discover(metadataUrl, null, httpGet, false);
    }

    /**
     * As {@link #discover(String)}, requiring the document's {@code issuer} to equal {@code issuer} exactly.
     *
     * @param metadataUrl the metadata document URL
     * @param issuer      the expected issuer, or null to derive it from {@code metadataUrl}
     * @param httpGet     the transport, or null for the SDK's shared transport
     * @return the metadata
     * @throws IllegalArgumentException when the URL is not https (loopback exempt), or {@code issuer} is null
     *                                  and the URL names no issuer
     * @throws TransportException       when the fetch fails, the document is not a strict JSON object, its
     *                                  {@code issuer} is not the expected one, or an endpoint in it is not https
     */
    public static Map<String, Object> discover(String metadataUrl, String issuer,
            AccessTokenValidator.HttpGet httpGet) {
        return discover(metadataUrl, issuer, httpGet, false);
    }

    /**
     * As {@link #discover(String, String, AccessTokenValidator.HttpGet)}, optionally allowing plain http for
     * the metadata URL and the endpoints it returns on non-loopback hosts.
     *
     * @param metadataUrl   the metadata document URL
     * @param issuer        the expected issuer, or null to derive it from {@code metadataUrl}
     * @param httpGet       the transport, or null for the SDK's shared transport
     * @param allowInsecure allow plain http on non-loopback hosts
     * @return the metadata
     * @throws IllegalArgumentException when the URL is not https (loopback exempt) and {@code allowInsecure} is
     *                                  false, or {@code issuer} is null and the URL names no issuer
     * @throws TransportException       when the fetch fails, the document is not a strict JSON object, its
     *                                  {@code issuer} is not the expected one, or an endpoint in it is not https
     */
    public static Map<String, Object> discover(String metadataUrl, String issuer,
            AccessTokenValidator.HttpGet httpGet, boolean allowInsecure) {
        ValidatorConfig.requireSecure(metadataUrl, "metadata URL", allowInsecure);
        String derived = issuer == null ? expectedIssuer(metadataUrl) : null;
        if (issuer == null && derived == null) {
            throw new IllegalArgumentException("cannot tell which issuer " + metadataUrl
                    + " belongs to: it is not a .well-known/oauth-authorization-server or"
                    + " .well-known/openid-configuration URL, so pass the expected issuer");
        }
        int status = 200;
        String text;
        if (httpGet != null) {
            text = httpGet.get(metadataUrl);
        } else {
            HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(metadataUrl)).GET()
                    .header("Accept", "application/json");
            HttpTransport.Response response = HttpTransport.send(
                    HttpTransport.client(AccessTokenValidator.HTTP_TIMEOUT), req, AccessTokenValidator.HTTP_TIMEOUT);
            text = HttpTransport.textOk(response);
            status = response.status();
        }
        Map<String, Object> metadata;
        try {
            metadata = Strict.parseObject(text == null ? "" : text, "metadata");
        } catch (Strict.Malformed e) {
            throw HttpTransport.malformed("metadata endpoint returned " + e.getMessage(), status);
        }
        Object got = metadata.get("issuer");
        // the issuer a URL was built from may have lost a terminating "/" (RFC 8414 section 3.1)
        boolean matches = got instanceof String && (issuer != null ? issuer.equals(got)
                : derived.equals(got) || (derived + "/").equals(got));
        if (!matches) {
            String shown = got instanceof String ? HttpTransport.truncate((String) got) : "(missing)";
            throw HttpTransport.malformed("metadata issuer " + shown + " is not the expected issuer "
                    + (issuer != null ? issuer : derived), status);
        }
        for (String name : new String[] {"jwks_uri", "introspection_endpoint"}) {
            Object value = metadata.get(name);
            if (value == null) {
                continue;
            }
            if (!(value instanceof String)) {
                throw HttpTransport.malformed("metadata " + name + " is not a string", status);
            }
            try {
                ValidatorConfig.requireSecure((String) value, "metadata " + name, allowInsecure);
            } catch (IllegalArgumentException e) {
                throw HttpTransport.malformed(e.getMessage(), status);
            }
        }
        return metadata;
    }

    /**
     * The issuer a standard metadata URL was built from, or null when the URL isn't one: the well-known path
     * inserted after the host (RFC 8414 section 3.1, also used for {@code openid-configuration}) or appended
     * to the issuer's path (OpenID Connect Discovery section 4, also seen for
     * {@code oauth-authorization-server}). An issuer has no query or fragment.
     */
    static String expectedIssuer(String metadataUrl) {
        URI uri;
        try {
            uri = URI.create(metadataUrl);
        } catch (IllegalArgumentException e) {
            return null;
        }
        String path = uri.getRawPath();
        if (uri.getScheme() == null || uri.getRawAuthority() == null || path == null
                || uri.getRawQuery() != null && !uri.getRawQuery().isEmpty()
                || uri.getRawFragment() != null && !uri.getRawFragment().isEmpty()) {
            return null;
        }
        String origin = uri.getScheme().toLowerCase(Locale.ROOT) + "://" + uri.getRawAuthority();
        for (String wk : WELL_KNOWN) {
            if (path.equals(wk) || path.startsWith(wk + "/")) {
                return origin + path.substring(wk.length());
            }
        }
        for (String wk : WELL_KNOWN) {
            if (path.endsWith(wk)) {
                return origin + path.substring(0, path.length() - wk.length());
            }
        }
        return null;
    }
}
