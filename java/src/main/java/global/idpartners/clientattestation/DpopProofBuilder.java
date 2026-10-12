package global.idpartners.clientattestation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * Builds a DPoP proof JWT (RFC 9449, header {@code typ=dpop+jwt}) for attestation "combined mode"
 * (PoP method {@code dpop_combined}): a single DPoP proof doubles as the attestation proof of
 * possession, so its embedded {@code jwk} header MUST be the instance key bound in the attestation's
 * {@code cnf}. Carries {@code htm}/{@code htu}/{@code iat}/{@code jti} and, when the AS issued one, the
 * challenge in {@code nonce}. Sign with the client instance key.
 *
 * <p>The same builder makes resource-request proofs: set {@link #accessToken(String)} to add the RFC 9449
 * section 4.2 {@code ath} claim. {@code htm} is always upper-cased and {@code htu} normalised to
 * scheme + host + port + path (no user info, query or fragment), as RFC 9449 requires.
 */
public final class DpopProofBuilder {

    static final String TYP = "dpop+jwt";

    private final SigningKeyPair instanceKey;
    private String htm = "POST";
    private String htu;
    private String nonce;
    private String ath;
    private String jwtId;
    private Instant issuedAt;

    public DpopProofBuilder(SigningKeyPair instanceKey) {
        this.instanceKey = Objects.requireNonNull(instanceKey, "instanceKey");
    }

    /** The request's HTTP method ({@code htm}, upper-cased); defaults to {@code POST}. */
    public DpopProofBuilder method(String htm) {
        if (htm != null && !htm.isBlank()) {
            this.htm = htm.strip().toUpperCase(Locale.ROOT);
        }
        return this;
    }

    /**
     * The target URL ({@code htu}) — required. Normalised when the proof is built (RFC 9449 section 4.2) by
     * the rule in vectors/README.md: user info, query, fragment and a default port are dropped, and scheme
     * and host lower-cased. {@link #build()} refuses a URL that is not an absolute http(s) URL with a valid
     * ASCII host, port and path, or that has a backslash, ASCII whitespace or a control character before
     * its query or fragment.
     */
    public DpopProofBuilder uri(String htu) {
        this.htu = htu;
        return this;
    }

    /** The server challenge, carried in DPoP {@code nonce}. */
    public DpopProofBuilder nonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    /**
     * The access token this proof accompanies at a resource: adds {@code ath} =
     * base64url(SHA-256(ASCII token)) per RFC 9449 section 4.2. Null or blank omits {@code ath}.
     */
    public DpopProofBuilder accessToken(String accessToken) {
        this.ath = accessToken == null || accessToken.isBlank() ? null : accessTokenHash(accessToken);
        return this;
    }

    public DpopProofBuilder jwtId(String jwtId) {
        this.jwtId = jwtId;
        return this;
    }

    public DpopProofBuilder issuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }

    public String build() {
        if (this.htu == null || this.htu.isBlank()) {
            throw new IllegalArgumentException("uri (htu) is required");
        }
        String normalizedHtu = normalizeHtu(this.htu);
        JwtClaims claims = new JwtClaims();
        claims.setClaim("htm", this.htm);
        claims.setClaim("htu", normalizedHtu);
        claims.setJwtId(this.jwtId != null ? this.jwtId : UUID.randomUUID().toString());
        Instant iat = this.issuedAt != null ? this.issuedAt : Instant.now();
        claims.setIssuedAt(NumericDate.fromSeconds(iat.getEpochSecond()));
        if (this.nonce != null && !this.nonce.isBlank()) {
            claims.setClaim("nonce", this.nonce);
        }
        if (this.ath != null) {
            claims.setClaim("ath", this.ath);
        }
        return Jws.sign(claims.toJson(), this.instanceKey, TYP, true);
    }

    /** {@code base64url(SHA-256(ASCII accessToken))} — the RFC 9449 {@code ath} value. */
    static String accessTokenHash(String accessToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);   // every JRE ships SHA-256
        }
    }

    /**
     * Throws unless {@code url} is free of backslashes, ASCII whitespace and control characters before its
     * query or fragment (the part that becomes {@code htu}). URL parsers disagree on where such a URL goes
     * (WHATWG reads {@code https://evil.example\@as.example/t} as a request to evil.example,
     * {@code urllib.parse} as one to as.example), so a proof's {@code htu} could name a different server
     * from the one the request reaches.
     */
    static void checkHtu(String url) {
        for (int i = 0; i < url.length() && url.charAt(i) != '?' && url.charAt(i) != '#'; i++) {
            char c = url.charAt(i);
            if (c <= ' ' || c == 0x7f || c == '\\') {
                throw new IllegalArgumentException(
                        "uri (htu) must not contain a backslash, whitespace or control character");
            }
        }
    }

    /** The schemes an {@code htu} may have, with their default ports. */
    private static final Map<String, String> HTU_DEFAULT_PORTS = Map.of("http", "80", "https", "443");
    private static final String HTU_NOT_ABSOLUTE = "uri (htu) must be an absolute http or https URL with a host";
    private static final String HTU_HOST = "uri (htu) has an invalid host";
    private static final String HTU_PORT = "uri (htu) has an invalid port";
    private static final String HTU_PATH = "uri (htu) has an invalid path";
    private static final String UNRESERVED =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    private static final String HEX = "0123456789ABCDEFabcdef";

    /**
     * {@code [origin, path]} of a request URL's {@code htu}, by the rule in vectors/README.md that every port
     * applies alike: an absolute http(s) URL with a host; scheme and host lower-cased (ASCII only, an IPv6
     * literal as written); no user info; the port as a plain number and dropped when it is the scheme's
     * default; the path as written with non-ASCII characters percent-encoded (UTF-8);
     * no query or fragment. It is read from the string itself, not through {@link URI}, which finds no host
     * in a name with {@code _}. Anything else throws {@link IllegalArgumentException}.
     */
    static String[] htuParts(String url) {
        checkHtu(url);
        String bare = url;
        for (int i = 0; i < bare.length(); i++) {
            if (bare.charAt(i) == '?' || bare.charAt(i) == '#') {
                bare = bare.substring(0, i);
                break;
            }
        }
        int sep = bare.indexOf("://");
        String scheme = sep < 0 ? "" : bare.substring(0, sep).toLowerCase(Locale.ROOT);
        if (!HTU_DEFAULT_PORTS.containsKey(scheme)) {
            throw new IllegalArgumentException(HTU_NOT_ABSOLUTE);
        }
        String rest = bare.substring(sep + 3);
        int slash = rest.indexOf('/');
        String authority = slash < 0 ? rest : rest.substring(0, slash);
        String path = slash < 0 ? "" : rest.substring(slash);
        String hostport = authority.substring(authority.lastIndexOf('@') + 1);
        String host;
        String port = "";
        if (hostport.startsWith("[")) {
            int close = hostport.indexOf(']');
            String literal = close < 0 ? "" : hostport.substring(1, close);
            String after = close < 0 ? "" : hostport.substring(close + 1);
            if (!literal.contains(":") || !only(literal, HEX + ":.") || (!after.isEmpty() && after.charAt(0) != ':')) {
                throw new IllegalArgumentException(HTU_HOST);
            }
            host = "[" + literal.toLowerCase(Locale.ROOT) + "]";
            port = after.isEmpty() ? "" : after.substring(1);
        } else {
            int colon = hostport.indexOf(':');
            host = colon < 0 ? hostport : hostport.substring(0, colon);
            port = colon < 0 ? "" : hostport.substring(colon + 1);
            if (host.isEmpty()) {
                throw new IllegalArgumentException(HTU_NOT_ABSOLUTE);
            }
            if (!only(host, UNRESERVED)) {
                throw new IllegalArgumentException(HTU_HOST);
            }
            host = host.toLowerCase(Locale.ROOT);
        }
        if (!port.isEmpty()) {
            String digits = port.replaceFirst("^0+", "");
            if (!only(port, "0123456789") || digits.length() > 5
                    || (!digits.isEmpty() && Integer.parseInt(digits) > 65535)) {
                throw new IllegalArgumentException(HTU_PORT);
            }
            String n = digits.isEmpty() ? "0" : digits;
            if (!n.equals(HTU_DEFAULT_PORTS.get(scheme))) {
                host += ":" + n;
            }
        }
        return new String[] {scheme + "://" + host, encodeHtuPath(path)};
    }

    /**
     * {@code path} with every non-ASCII character percent-encoded as UTF-8 (upper-case hex) and every ASCII
     * character kept as written, {@code %XX} escapes, a lone {@code %} and characters outside RFC 3986
     * {@code pchar} included: those are what the HTTP client sends, and a server compares {@code htu} after
     * RFC 3986 section 6.2.2 normalisation, which decodes only unreserved characters. ({@code checkHtu} has
     * already refused controls, whitespace and backslash.) A lone surrogate is refused.
     */
    private static String encodeHtuPath(String path) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < path.length(); ) {
            int cp = path.codePointAt(i);
            if (cp < 0x80) {
                out.append((char) cp);
            } else if (cp <= 0xFFFF && Character.isSurrogate((char) cp)) {   // a lone surrogate
                throw new IllegalArgumentException(HTU_PATH);
            } else {
                for (byte b : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) {
                    out.append('%').append(HEX.charAt((b >> 4) & 0xF)).append(HEX.charAt(b & 0xF));
                }
            }
            i += Character.charCount(cp);
        }
        return out.toString();
    }

    private static boolean only(String s, String allowed) {
        for (int i = 0; i < s.length(); i++) {
            if (allowed.indexOf(s.charAt(i)) < 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * The RFC 9449 {@code htu} form of {@code url}: the origin and path {@link #htuParts(String)} gives. A
     * URL with no path keeps none (no slash is invented).
     */
    static String normalizeHtu(String url) {
        String[] parts = htuParts(url);
        return parts[0] + parts[1];
    }

    /**
     * {@code scheme://host[:port]} of {@code url} as its {@code htu} names it ({@link #htuParts(String)}), the
     * key a DPoP nonce is remembered under. A URL that rule refuses is its own key.
     */
    static String origin(String url) {
        try {
            return htuParts(url)[0];
        } catch (IllegalArgumentException e) {
            return url;
        }
    }
}
