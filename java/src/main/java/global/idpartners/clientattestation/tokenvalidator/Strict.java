package global.idpartners.clientattestation.tokenvalidator;

import global.idpartners.clientattestation.internal.StrictJson;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The strict parsing every port applies to a token before trusting any of it (validation/SEMANTICS.md):
 * compact serialisation, strict RFC 8259 JSON objects, NumericDates and claim types. A failure throws
 * {@link Malformed}; its message is generic and never quotes token bytes.
 *
 * <p>Segment decoding and the JSON reader are {@link StrictJson}, shared with the client's JWT-SVID check:
 * jose4j's reader is lenient (it takes trailing commas, leading zeros and raw control characters) and the
 * ports must agree on what is JSON.
 */
final class Strict {

    static final long MAX_SAFE_INTEGER = (1L << 53) - 1;

    private Strict() {
    }

    /** The input is not well-formed; the token is invalid. */
    static final class Malformed extends Exception {
        private static final long serialVersionUID = 1L;

        Malformed(String message) {
            super(message);
        }
    }

    /** The parts of a compact JWS: the header object and the undecoded payload. */
    static final class Compact {
        final Map<String, Object> header;
        final byte[] payload;

        Compact(Map<String, Object> header, byte[] payload) {
            this.header = header;
            this.payload = payload;
        }
    }

    private static byte[] decodeSegment(String segment) throws Malformed {
        try {
            return StrictJson.decodeSegment(segment);
        } catch (StrictJson.Malformed e) {
            throw new Malformed(e.getMessage());
        }
    }

    /**
     * The header object and payload bytes of a compact JWS. The payload is returned undecoded: it is only
     * parsed once the signature over it verifies.
     */
    static Compact splitCompact(String token) throws Malformed {
        if (token == null) {
            throw new Malformed("malformed token");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new Malformed("malformed token");
        }
        byte[] header = decodeSegment(parts[0]);
        byte[] payload = decodeSegment(parts[1]);
        decodeSegment(parts[2]);
        Map<String, Object> headerObject = parseObject(header, "header");
        if (headerObject.containsKey("crit")) {
            // we implement no JWS extension, so RFC 7515 section 4.1.11 says reject any crit
            throw new Malformed("header has crit");
        }
        return new Compact(headerObject, payload);
    }

    /**
     * {@code data} as a strict RFC 8259 JSON object: UTF-8 without a BOM, no duplicate member names at any
     * depth, at most {@link StrictJson#MAX_DEPTH} levels deep, nothing after it (the reader is
     * {@link StrictJson#parseObject(byte[], String)}, shared with the client).
     */
    static Map<String, Object> parseObject(byte[] data, String what) throws Malformed {
        try {
            return StrictJson.parseObject(data, what);
        } catch (StrictJson.Malformed e) {
            throw new Malformed(e.getMessage());
        }
    }

    /** {@code text} as a strict JSON object (see {@link #parseObject(byte[], String)}). */
    static Map<String, Object> parseObject(String text, String what) throws Malformed {
        try {
            return StrictJson.parseObject(text, what);
        } catch (StrictJson.Malformed e) {
            throw new Malformed(e.getMessage());
        }
    }

    // ── claims ──────────────────────────────────────────────────────────────────────────────────────

    /**
     * A NumericDate claim (fractions truncate toward zero), null when absent or null. Anything but a finite
     * JSON number within ±(2^53 − 1) is malformed.
     */
    static Long numericDate(Map<String, Object> claims, String name) throws Malformed {
        Object value = claims.get(name);
        if (value == null) {
            return null;
        }
        double d;
        if (value instanceof Long || value instanceof Integer) {
            long l = ((Number) value).longValue();
            if (l > MAX_SAFE_INTEGER || l < -MAX_SAFE_INTEGER) {
                throw new Malformed(name + " is out of range");
            }
            return l;
        } else if (value instanceof BigInteger) {
            throw new Malformed(name + " is out of range");
        } else if (value instanceof Double) {
            d = (Double) value;
        } else {
            throw new Malformed(name + " is not a NumericDate");
        }
        if (!Double.isFinite(d)) {
            throw new Malformed(name + " is not a NumericDate");
        }
        if (Math.abs(d) > MAX_SAFE_INTEGER) {
            throw new Malformed(name + " is out of range");
        }
        return (long) d;
    }

    private static List<String> stringArray(Object value) {
        if (!(value instanceof List)) {
            return null;
        }
        List<String> out = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (!(item instanceof String)) {
                return null;
            }
            out.add((String) item);
        }
        return out;
    }

    /** {@code aud} as a list: absent or null is empty, a string is one entry, an array must hold only strings. */
    static List<String> audience(Map<String, Object> claims) throws Malformed {
        Object value = claims.get("aud");
        if (value == null) {
            return new ArrayList<>();
        }
        if (value instanceof String) {
            List<String> out = new ArrayList<>();
            out.add((String) value);
            return out;
        }
        List<String> out = stringArray(value);
        if (out == null) {
            throw new Malformed("aud is not a string or an array of strings");
        }
        return out;
    }

    /**
     * Granted scopes: from {@code scope} (a space-delimited string) when present, else {@code scp} (a
     * space-delimited string, as Microsoft Entra ID issues it, or an array of strings). Either one present with
     * any other shape is malformed.
     */
    static List<String> scopes(Map<String, Object> claims) throws Malformed {
        Object scope = claims.get("scope");
        Object scp = claims.get("scp");
        if (scope != null && !(scope instanceof String)) {
            throw new Malformed("scope is not a string");
        }
        List<String> scpList = scp == null ? new ArrayList<>()
                : scp instanceof String ? split((String) scp) : stringArray(scp);
        if (scpList == null) {
            throw new Malformed("scp is not a string or an array of strings");
        }
        return scope == null ? scpList : split((String) scope);
    }

    /** Split on U+0020 only, as RFC 6749 section 3.3 says; runs of spaces make no empty scopes. */
    private static List<String> split(String text) {
        List<String> out = new ArrayList<>();
        for (String s : text.split(" ")) {
            if (!s.isEmpty()) {
                out.add(s);
            }
        }
        return out;
    }

    /** {@code sub}, null when absent or null; any other non-string is malformed. */
    static String subject(Map<String, Object> claims) throws Malformed {
        Object value = claims.get("sub");
        if (value != null && !(value instanceof String)) {
            throw new Malformed("sub is not a string");
        }
        return (String) value;
    }

    /**
     * Whether {@code alg} is refused whatever the accepted algorithms say: {@code none} (in any case), because an
     * unsigned token proves nothing, and the HMAC algorithms, because an HMAC "signature" checked against an
     * issuer's public key is forgeable by anyone who has that key.
     */
    static boolean isForbiddenAlgorithm(String alg) {
        String lowered = alg.toLowerCase(Locale.ROOT);
        return lowered.equals("none") || lowered.startsWith("hs");
    }
}
