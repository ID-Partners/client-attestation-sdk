package global.idpartners.clientattestation;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
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
 * scheme + host + port + path (no query, no fragment), as RFC 9449 requires.
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

    /** The target URL ({@code htu}) — required. Query and fragment are dropped when the proof is built. */
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
        JwtClaims claims = new JwtClaims();
        claims.setClaim("htm", this.htm);
        claims.setClaim("htu", normalizeHtu(this.htu));
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
     * The RFC 9449 {@code htu} form of {@code url}: lower-cased scheme and host, the port only when it is
     * not the scheme default, and the path — no user info, query or fragment. A value that is not an
     * absolute http(s)-style URL just has its query and fragment cut off.
     */
    static String normalizeHtu(String url) {
        URI uri;
        try {
            uri = URI.create(url.strip());
        } catch (IllegalArgumentException e) {
            return cutQueryAndFragment(url.strip());
        }
        if (uri.getScheme() == null || uri.getHost() == null) {
            return cutQueryAndFragment(url.strip());
        }
        return origin(uri) + uri.getRawPath();   // a hierarchical URI's raw path is never null
    }

    /**
     * {@code scheme://host[:port]} of an absolute URI, lower-cased, with a scheme-default port dropped — the
     * origin part of {@link #normalizeHtu(String)}.
     */
    static String origin(URI uri) {
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        StringBuilder out = new StringBuilder(scheme).append("://").append(uri.getHost().toLowerCase(Locale.ROOT));
        int port = uri.getPort();
        boolean defaultPort = port == -1 || ("https".equals(scheme) && port == 443)
                || ("http".equals(scheme) && port == 80);
        if (!defaultPort) {
            out.append(':').append(port);
        }
        return out.toString();
    }

    private static String cutQueryAndFragment(String url) {
        int cut = url.length();
        int q = url.indexOf('?');
        int f = url.indexOf('#');
        if (q >= 0) {
            cut = q;
        }
        if (f >= 0 && f < cut) {
            cut = f;
        }
        return url.substring(0, cut);
    }
}
