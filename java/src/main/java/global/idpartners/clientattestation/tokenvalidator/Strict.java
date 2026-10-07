package global.idpartners.clientattestation.tokenvalidator;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The strict parsing every port applies to a token before trusting any of it (validation/SEMANTICS.md):
 * compact serialisation, strict RFC 8259 JSON objects, NumericDates and claim types. A failure throws
 * {@link Malformed}; its message is generic and never quotes token bytes.
 *
 * <p>The JSON reader is our own because jose4j's is lenient (it takes trailing commas, leading zeros and raw
 * control characters) and the ports must agree on what is JSON. It yields the types jose4j does: {@code Map},
 * {@code List}, {@code String}, {@code Boolean}, {@code null}, {@code Long} for an integer that fits,
 * {@code BigInteger} for a larger one and {@code Double} for a number with a fraction or exponent.
 */
final class Strict {

    /** Deepest object/array nesting a header, payload or introspection response may have. */
    static final int MAX_DEPTH = 64;
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
        if (segment.length() % 4 == 1) {
            throw new Malformed("malformed token");
        }
        for (int i = 0; i < segment.length(); i++) {
            char c = segment.charAt(i);
            boolean ok = c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_';
            if (!ok) {
                throw new Malformed("malformed token");
            }
        }
        byte[] data = Base64.getUrlDecoder().decode(segment);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(data).equals(segment)) {
            throw new Malformed("malformed token");   // non-zero padding bits: not the canonical encoding
        }
        return data;
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
     * depth, at most {@link #MAX_DEPTH} levels deep, nothing after it.
     */
    static Map<String, Object> parseObject(byte[] data, String what) throws Malformed {
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(data)).toString();
        } catch (CharacterCodingException e) {
            throw new Malformed(what + " is not UTF-8");
        }
        return parseObject(text, what);
    }

    /** {@code text} as a strict JSON object (see {@link #parseObject(byte[], String)}). */
    static Map<String, Object> parseObject(String text, String what) throws Malformed {
        Reader reader = new Reader(text, what);
        reader.skipWhitespace();
        if (reader.peek() != '{') {
            reader.value(0);   // still has to be JSON, then it is the wrong kind
            throw new Malformed(what + " is not a JSON object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> object = (Map<String, Object>) reader.value(0);
        reader.skipWhitespace();
        if (reader.pos != text.length()) {
            throw new Malformed(what + " is not JSON");
        }
        return object;
    }

    /** A recursive-descent RFC 8259 reader, depth-limited so nesting can't exhaust the stack. */
    private static final class Reader {
        private final String s;
        private final String what;
        int pos;

        Reader(String s, String what) {
            this.s = s;
            this.what = what;
        }

        private Malformed notJson() {
            return new Malformed(this.what + " is not JSON");
        }

        int peek() {
            return this.pos < this.s.length() ? this.s.charAt(this.pos) : -1;
        }

        void skipWhitespace() {
            while (this.pos < this.s.length()) {
                char c = this.s.charAt(this.pos);
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    return;
                }
                this.pos++;
            }
        }

        private void expect(char c) throws Malformed {
            if (peek() != c) {
                throw notJson();
            }
            this.pos++;
        }

        Object value(int depth) throws Malformed {
            skipWhitespace();
            int c = peek();
            switch (c) {
                case '{':
                    return object(depth + 1);
                case '[':
                    return array(depth + 1);
                case '"':
                    return string();
                case 't':
                    literal("true");
                    return Boolean.TRUE;
                case 'f':
                    literal("false");
                    return Boolean.FALSE;
                case 'n':
                    literal("null");
                    return null;
                default:
                    return number();
            }
        }

        private void literal(String word) throws Malformed {
            if (!this.s.startsWith(word, this.pos)) {
                throw notJson();
            }
            this.pos += word.length();
        }

        private Map<String, Object> object(int depth) throws Malformed {
            if (depth > MAX_DEPTH) {
                throw new Malformed(this.what + " is nested too deeply");
            }
            this.pos++;   // '{'
            Map<String, Object> out = new LinkedHashMap<>();
            skipWhitespace();
            if (peek() == '}') {
                this.pos++;
                return out;
            }
            while (true) {
                skipWhitespace();
                String name = string();
                if (out.containsKey(name)) {
                    throw new Malformed(this.what + " is not a strict JSON object (duplicate member name)");
                }
                skipWhitespace();
                expect(':');
                out.put(name, value(depth));
                skipWhitespace();
                if (peek() == ',') {
                    this.pos++;
                    continue;
                }
                expect('}');
                return out;
            }
        }

        private List<Object> array(int depth) throws Malformed {
            if (depth > MAX_DEPTH) {
                throw new Malformed(this.what + " is nested too deeply");
            }
            this.pos++;   // '['
            List<Object> out = new ArrayList<>();
            skipWhitespace();
            if (peek() == ']') {
                this.pos++;
                return out;
            }
            while (true) {
                out.add(value(depth));
                skipWhitespace();
                if (peek() == ',') {
                    this.pos++;
                    continue;
                }
                expect(']');
                return out;
            }
        }

        private String string() throws Malformed {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (true) {
                if (this.pos >= this.s.length()) {
                    throw notJson();
                }
                char c = this.s.charAt(this.pos++);
                if (c == '"') {
                    return out.toString();
                }
                if (c < 0x20) {
                    throw notJson();   // a raw control character
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                int e = peek();
                this.pos++;
                switch (e) {
                    case '"': out.append('"'); break;
                    case '\\': out.append('\\'); break;
                    case '/': out.append('/'); break;
                    case 'b': out.append('\b'); break;
                    case 'f': out.append('\f'); break;
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    case 'u':
                        if (this.pos + 4 > this.s.length()) {
                            throw notJson();
                        }
                        int code = 0;
                        for (int i = 0; i < 4; i++) {
                            int d = Character.digit(this.s.charAt(this.pos++), 16);
                            if (d < 0) {
                                throw notJson();
                            }
                            code = code * 16 + d;
                        }
                        out.append((char) code);
                        break;
                    default:
                        throw notJson();
                }
            }
        }

        private Object number() throws Malformed {
            int start = this.pos;
            if (peek() == '-') {
                this.pos++;
            }
            if (peek() == '0') {
                this.pos++;
            } else if (digits() == 0) {
                throw notJson();
            }
            boolean integer = true;
            if (peek() == '.') {
                this.pos++;
                integer = false;
                if (digits() == 0) {
                    throw notJson();
                }
            }
            if (peek() == 'e' || peek() == 'E') {
                this.pos++;
                integer = false;
                if (peek() == '+' || peek() == '-') {
                    this.pos++;
                }
                if (digits() == 0) {
                    throw notJson();
                }
            }
            String text = this.s.substring(start, this.pos);
            if (!integer) {
                return Double.parseDouble(text);   // overflows to ±Infinity, as every port's double does
            }
            BigInteger big = new BigInteger(text);
            return big.bitLength() < 64 ? (Object) big.longValue() : big;
        }

        private int digits() {
            int n = 0;
            while (peek() >= '0' && peek() <= '9') {
                this.pos++;
                n++;
            }
            return n;
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
