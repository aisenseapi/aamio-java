package at.aamio;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The little JSON this client needs, so that it needs nothing else. Objects
 * become LinkedHashMap, arrays ArrayList, integers Long, other numbers
 * Double, and null stays null. write() is compact in insertion order, which
 * is what goes on the wire and gets signed; canonical() is the form a
 * gate_hash is taken over: keys sorted by their UTF-8 bytes at every level,
 * no whitespace, integers as integers, strings escaped only where JSON
 * requires it.
 */
public final class Json {
    private Json() {
    }

    public static Object parse(String text) {
        Parser p = new Parser(text);
        p.skip();
        Object value = p.value();
        p.skip();
        if (p.pos != text.length()) {
            throw p.err("trailing characters");
        }
        return value;
    }

    /** parse() when the text must be an object; null when it is not JSON or not an object. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(String text) {
        if (text == null) {
            return null;
        }
        try {
            Object v = parse(text);
            return v instanceof Map ? (Map<String, Object>) v : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value, false);
        return out.toString();
    }

    public static String canonical(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value, true);
        return out.toString();
    }

    private static void write(StringBuilder out, Object v, boolean canonical) {
        if (v == null) {
            out.append("null");
        } else if (v instanceof Boolean b) {
            out.append(b ? "true" : "false");
        } else if (v instanceof Integer || v instanceof Long || v instanceof Short || v instanceof Byte || v instanceof BigInteger) {
            out.append(v);
        } else if (v instanceof Number n) {
            double d = n.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("not a JSON number: " + d);
            }
            if (d == Math.rint(d) && Math.abs(d) < 9.0e18) {
                out.append((long) d);
            } else {
                out.append(new BigDecimal(Double.toString(d)).stripTrailingZeros().toPlainString());
            }
        } else if (v instanceof CharSequence s) {
            string(out, s.toString());
        } else if (v instanceof Map<?, ?> m) {
            List<Map.Entry<?, ?>> entries = new ArrayList<>(m.entrySet());
            if (canonical) {
                entries.sort((a, b) -> compareUtf8(String.valueOf(a.getKey()), String.valueOf(b.getKey())));
            }
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : entries) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                string(out, String.valueOf(e.getKey()));
                out.append(':');
                write(out, e.getValue(), canonical);
            }
            out.append('}');
        } else if (v instanceof Iterable<?> items) {
            out.append('[');
            boolean first = true;
            for (Object item : items) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                write(out, item, canonical);
            }
            out.append(']');
        } else if (v instanceof Object[] array) {
            write(out, Arrays.asList(array), canonical);
        } else {
            throw new IllegalArgumentException("cannot encode a " + v.getClass().getName());
        }
    }

    /** Escapes only what JSON requires: the quote, the backslash and control characters below 0x20. "/" and U+2028 stay raw. */
    private static void string(StringBuilder out, String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private static int compareUtf8(String a, String b) {
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        return Arrays.compareUnsigned(x, y);
    }

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        void skip() {
            while (pos < s.length() && " \t\n\r".indexOf(s.charAt(pos)) >= 0) {
                pos++;
            }
        }

        Object value() {
            char c = peek();
            switch (c) {
                case '{':
                    return object();
                case '[':
                    return array();
                case '"':
                    return string();
                case 't':
                    expect("true");
                    return Boolean.TRUE;
                case 'f':
                    expect("false");
                    return Boolean.FALSE;
                case 'n':
                    expect("null");
                    return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return number();
                    }
                    throw err("unexpected character '" + c + "'");
            }
        }

        Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            pos++;
            skip();
            if (peek() == '}') {
                pos++;
                return m;
            }
            while (true) {
                skip();
                if (peek() != '"') {
                    throw err("expected a key");
                }
                String key = string();
                skip();
                if (peek() != ':') {
                    throw err("expected ':'");
                }
                pos++;
                skip();
                m.put(key, value());
                skip();
                char c = peek();
                pos++;
                if (c == '}') {
                    return m;
                }
                if (c != ',') {
                    throw err("expected ',' or '}'");
                }
            }
        }

        List<Object> array() {
            List<Object> list = new ArrayList<>();
            pos++;
            skip();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                skip();
                list.add(value());
                skip();
                char c = peek();
                pos++;
                if (c == ']') {
                    return list;
                }
                if (c != ',') {
                    throw err("expected ',' or ']'");
                }
            }
        }

        String string() {
            pos++;
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= s.length()) {
                    throw err("unterminated string");
                }
                char c = s.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (pos >= s.length()) {
                        throw err("unterminated escape");
                    }
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (pos + 4 > s.length()) {
                                throw err("short unicode escape");
                            }
                            try {
                                sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                            } catch (NumberFormatException x) {
                                throw err("bad unicode escape");
                            }
                            pos += 4;
                        }
                        default -> throw err("bad escape");
                    }
                } else if (c < 0x20) {
                    throw err("control character in string");
                } else {
                    sb.append(c);
                }
            }
        }

        Object number() {
            int start = pos;
            boolean integral = true;
            if (s.charAt(pos) == '-') {
                pos++;
            }
            digits();
            if (pos < s.length() && s.charAt(pos) == '.') {
                integral = false;
                pos++;
                digits();
            }
            if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                integral = false;
                pos++;
                if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) {
                    pos++;
                }
                digits();
            }
            String t = s.substring(start, pos);
            try {
                if (integral) {
                    try {
                        return Long.parseLong(t);
                    } catch (NumberFormatException e) {
                        return new BigInteger(t);
                    }
                }
                return Double.parseDouble(t);
            } catch (NumberFormatException e) {
                throw err("bad number " + t);
            }
        }

        private void digits() {
            while (pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '9') {
                pos++;
            }
        }

        char peek() {
            if (pos >= s.length()) {
                throw err("unexpected end");
            }
            return s.charAt(pos);
        }

        void expect(String word) {
            if (!s.startsWith(word, pos)) {
                throw err("expected " + word);
            }
            pos += word.length();
        }

        IllegalArgumentException err(String what) {
            return new IllegalArgumentException("JSON: " + what + " at " + pos);
        }
    }
}
