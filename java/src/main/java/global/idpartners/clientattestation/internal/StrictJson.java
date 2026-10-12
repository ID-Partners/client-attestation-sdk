package global.idpartners.clientattestation.internal;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The strict reading every port applies to a token before trusting any of it (validation/SEMANTICS.md):
 * canonical base64url segments and strict RFC 8259 JSON objects. The token validator and the client's
 * JWT-SVID check share it, so they agree on what is JSON. A failure throws {@link Malformed}; its message is
 * generic and never quotes the input.
 *
 * <p>The JSON reader is our own because jose4j's is lenient (it takes trailing commas, leading zeros and raw
 * control characters) and the ports must agree on what is JSON. It yields the types jose4j does: {@code Map},
 * {@code List}, {@code String}, {@code Boolean}, {@code null}, {@code Long} for an integer that fits,
 * {@code BigInteger} for a larger one of up to {@value #MAX_EXACT_DIGITS} digits and {@code Double} for a longer
 * one or a number with a fraction or exponent.
 *
 * <p><b>Not API.</b> This package is internal: it is public only so the SDK's own packages can share it,
 * it is not exported by the module, and it may change in any release.
 */
public final class StrictJson {

    /** Deepest object/array nesting a header, payload or introspection response may have. */
    public static final int MAX_DEPTH = 64;
    /** The most digits an integer literal may have to be read exactly; a longer one is read as a double. */
    public static final int MAX_EXACT_DIGITS = 19;

    private StrictJson() {
    }

    /** The input is not well-formed. */
    public static final class Malformed extends Exception {
        private static final long serialVersionUID = 1L;

        public Malformed(String message) {
            super(message);
        }
    }

    /**
     * One segment of a compact JWS: unpadded base64url in its canonical form (no non-zero padding bits).
     */
    public static byte[] decodeSegment(String segment) throws Malformed {
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
     * {@code data} as a strict RFC 8259 JSON object: UTF-8 without a BOM, no duplicate member names at any
     * depth, at most {@link #MAX_DEPTH} levels deep, nothing after it.
     */
    public static Map<String, Object> parseObject(byte[] data, String what) throws Malformed {
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
    public static Map<String, Object> parseObject(String text, String what) throws Malformed {
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
                            int d = hexDigit(this.s.charAt(this.pos++));
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
            int digits = text.length() - (text.charAt(0) == '-' ? 1 : 0);   // JSON has no leading zeros
            if (!integer || digits > MAX_EXACT_DIGITS) {
                // overflows to ±Infinity, as every port's double does. A long integer is read as a double too:
                // new BigInteger is quadratic in the digits, and this runs on the header before any signature
                return Double.parseDouble(text);
            }
            BigInteger big = new BigInteger(text);
            return big.bitLength() < 64 ? (Object) big.longValue() : big;
        }

        /** The value of an ASCII hex digit, or -1. Not {@code Character.digit}: it takes any Unicode digit. */
        private static int hexDigit(char c) {
            if (c >= '0' && c <= '9') {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
            }
            return -1;
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
}
