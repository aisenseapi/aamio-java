package at.aamio;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Domain keys: which public aamio keys a website says are its own.
 *
 * <p>A site can publish the public keys of the agents it stands behind at
 * {@code https://<domain>/.well-known/aamio-keys.json}, as
 * {@code {"aamio_keys": 1, "keys": [{"key": "<43 characters>", "name": "support"}]}}.
 * This class is the format and nothing else: a strict parser, the match, a
 * generator for the file, and the syntax of a domain. It opens no connection and
 * reads no address book. A library has neither the user's list of websites nor a
 * hardened read, so fetching a list is for the caller, who also says which key is
 * compared: the result says subject_source supplied_key, and aamio-python and
 * aamio-php have the whole check.
 *
 * <p>Take the domain from your own records and never from the message being
 * checked: anyone can list their own key on their own site. A listed key says
 * that this exact site listed this key when it was read. It is not an identity,
 * an authority to act or proof that a message is true.
 *
 * <p>{@link Json} keeps the last of two members of the same name, which is right
 * for what this client reads from the service and cannot hold the format's rule
 * about duplicates, so the reader here is its own.
 * testdata/domain_keys_vectors.json holds what every client answers.
 */
public final class DomainKeys {
    public static final int VERSION = 1;
    public static final String PATH = "/.well-known/aamio-keys.json";
    public static final int MAX_BYTES = 16384;
    public static final int MAX_KEYS = 64;
    private static final int MAX_DEPTH = 16;
    private static final BigInteger MAX_INTEGER = BigInteger.ONE.shiftLeft(53).subtract(BigInteger.ONE);

    private static final Pattern KEY = Pattern.compile("[A-Za-z0-9_-]{43}");
    private static final Pattern NAME = Pattern.compile("[a-z0-9._-]{1,64}");
    private static final Pattern LABEL = Pattern.compile("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?");
    private static final Pattern NUMERIC = Pattern.compile("[0-9]+|0x[0-9a-f]+");

    private DomainKeys() {
    }

    /** One entry on a list. name is null when it has none, and it labels and authorises nothing. */
    public record Entry(String key, String name) {
    }

    /**
     * What a list says about one key. status is listed, not_listed or invalid, and
     * not_listed is no evidence of fraud: a key rotated out, the wrong name or the
     * wrong domain look the same. documentSha256 is of the exact bytes compared,
     * for comparison and fault finding; the domain did not sign it.
     */
    public record Match(String status, String reason, String detail, String matchedName, String documentSha256, String subjectSource) {
    }

    /** A list that is not version 1. reason says why, without echoing the content. */
    public static final class Invalid extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final String reason;

        Invalid(String reason) {
            super("invalid domain key list: " + reason);
            this.reason = reason;
        }
    }

    /** A public key as aamio writes it: 32 bytes, 43 characters, one spelling only. */
    public static boolean canonicalKey(Object value) {
        if (!(value instanceof String text) || !KEY.matcher(text).matches()) {
            return false;
        }
        // The decoder takes a last character carrying bits past the 32 bytes, which
        // decodes to the same bytes as another string; only one is the key.
        byte[] raw = Base64.getUrlDecoder().decode(text);
        return raw.length == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(raw).equals(text);
    }

    /** A name a list can carry: 1 to 64 characters of a-z, 0-9, dot, underscore and dash. */
    public static boolean validName(Object value) {
        return value instanceof String text && NAME.matcher(text).matches();
    }

    /**
     * The exact host a list is read from, in lowercase, or null. Plain ASCII names
     * of two labels or more. No port, path, IP literal, trailing dot, underscore or
     * space is trimmed into shape. Internationalised names, xn-- labels, wait until
     * every client converts them the same way. www.example.org and example.org are
     * different places, and no parent domain lends its list to a child.
     */
    public static String normaliseDomain(String value) {
        if (value == null) {
            return null;
        }
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) >= 0x80) {
                return null;
            }
        }
        String domain = value.toLowerCase(Locale.ROOT);
        String[] labels = domain.split("\\.", -1);
        if (domain.isEmpty() || domain.length() > 253 || labels.length < 2) {
            return null;
        }
        for (String label : labels) {
            if (!LABEL.matcher(label).matches() || label.startsWith("xn--")) {
                return null;
            }
        }
        // A last label of digits or hex is an old spelling of an IPv4 address.
        return NUMERIC.matcher(labels[labels.length - 1]).matches() ? null : domain;
    }

    /** Where the list of this exact domain is, over HTTPS on the default port, or null. */
    public static String url(String domain) {
        String host = normaliseDomain(domain);
        return host == null ? null : "https://" + host + PATH;
    }

    /**
     * The entries of a version 1 list. A duplicate key, a duplicate member name in
     * any object or one bad entry makes the whole document invalid: a list is never
     * valid with the bad part left out.
     */
    public static List<Entry> parse(byte[] raw) {
        if (raw.length > MAX_BYTES) {
            throw new Invalid("body_limit");
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException e) {
            throw new Invalid("not_utf8");
        }
        if (text.startsWith("﻿")) {
            throw new Invalid("byte_order_mark");
        }
        Reader reader = new Reader(text);
        Object value = reader.value(1);
        reader.skip();
        if (reader.at != text.length()) {
            throw new Invalid("invalid_json");
        }
        if (!(value instanceof Map<?, ?> document)) {
            throw new Invalid("object_required");
        }
        // A Long of 1 and nothing looser: 1.0, 1e0 and true are not the integer 1.
        if (!Long.valueOf(VERSION).equals(document.get("aamio_keys"))) {
            throw new Invalid("unsupported_version");
        }
        if (!(document.get("keys") instanceof List<?> rows) || rows.size() > MAX_KEYS) {
            throw new Invalid("invalid_keys");
        }
        Set<String> seen = new HashSet<>();
        List<Entry> entries = new ArrayList<>(rows.size());
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> entry) || !canonicalKey(entry.get("key"))) {
                throw new Invalid("invalid_key");
            }
            String key = (String) entry.get("key");
            if (!seen.add(key)) {
                throw new Invalid("duplicate_key");
            }
            String name = null;
            // containsKey, since a name of null is a bad name and not a missing one.
            if (entry.containsKey("name")) {
                if (!validName(entry.get("name"))) {
                    throw new Invalid("invalid_name");
                }
                name = (String) entry.get("name");
            }
            entries.add(new Entry(key, name));
        }
        return entries;
    }

    /**
     * Whether this exact document lists key, and under name when one is given. The
     * key is the caller's to choose and to answer for, which the result says as
     * subjectSource.
     */
    public static Match match(byte[] raw, String key, String name) {
        String source = "supplied_key";
        if (!canonicalKey(key)) {
            return new Match("invalid", "invalid_subject_key", null, null, null, source);
        }
        if (name != null && !validName(name)) {
            return new Match("invalid", "invalid_requested_name", null, null, null, source);
        }
        List<Entry> entries;
        try {
            entries = parse(raw);
        } catch (Invalid e) {
            return new Match("invalid", "invalid_document", e.reason, null, null, source);
        }
        String digest = Codec.sha256Hex(raw);
        for (Entry entry : entries) {
            if (entry.key().equals(key) && (name == null || name.equals(entry.name()))) {
                return new Match("listed", "key_listed", null, entry.name(), digest, source);
            }
        }
        return new Match("not_listed", "key_or_name_not_listed", null, null, digest, source);
    }

    /**
     * The file for a site to publish. The bytes are fixed, so every generator gives
     * the same file for the same list: two spaces of indentation, aamio_keys before
     * keys, key before name, ASCII only, and a line break at the end. An empty list
     * is allowed, since that is how a site says it lists no key, so callers ask for
     * it on purpose. A list this would refuse to read is refused here as well.
     */
    public static byte[] make(List<Entry> entries) {
        List<String> rows = new ArrayList<>(entries.size());
        Set<String> seen = new HashSet<>();
        for (Entry entry : entries) {
            if (!canonicalKey(entry.key())) {
                throw new Invalid("invalid_key");
            }
            if (!seen.add(entry.key())) {
                throw new Invalid("duplicate_key");
            }
            String row = "    {\n      \"key\": \"" + entry.key() + "\"";
            if (entry.name() != null) {
                if (!validName(entry.name())) {
                    throw new Invalid("invalid_name");
                }
                row += ",\n      \"name\": \"" + entry.name() + "\"";
            }
            rows.add(row + "\n    }");
        }
        if (rows.size() > MAX_KEYS) {
            throw new Invalid("invalid_keys");
        }
        String list = rows.isEmpty() ? "[]" : "[\n" + String.join(",\n", rows) + "\n  ]";
        byte[] raw = ("{\n  \"aamio_keys\": " + VERSION + ",\n  \"keys\": " + list + "\n}\n").getBytes(StandardCharsets.US_ASCII);
        parse(raw);
        return raw;
    }

    /**
     * JSON with the format's limits. Objects become a HashMap, lists an ArrayList,
     * integers a Long and other numbers a Double. A String holds UTF-16, so a lone
     * surrogate stays what it is and a pair is the character it spells.
     */
    private static final class Reader {
        private final String text;
        private int at;

        Reader(String text) {
            this.text = text;
        }

        private char peek() {
            return at < text.length() ? text.charAt(at) : '￿';
        }

        void skip() {
            while (at < text.length()) {
                char c = text.charAt(at);
                if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                    return;
                }
                at++;
            }
        }

        Object value(int level) {
            skip();
            char c = peek();
            if (c == '{') {
                return members(level);
            }
            if (c == '[') {
                return rows(level);
            }
            if (c == '"') {
                return string();
            }
            if (text.startsWith("true", at)) {
                at += 4;
                return Boolean.TRUE;
            }
            if (text.startsWith("false", at)) {
                at += 5;
                return Boolean.FALSE;
            }
            if (text.startsWith("null", at)) {
                at += 4;
                return null;
            }
            return number();
        }

        private Map<String, Object> members(int level) {
            if (level > MAX_DEPTH) {
                throw new Invalid("depth_limit");
            }
            at++;
            Map<String, Object> found = new HashMap<>();
            skip();
            if (peek() == '}') {
                at++;
                return found;
            }
            while (true) {
                skip();
                if (peek() != '"') {
                    throw new Invalid("invalid_json");
                }
                String name = string();
                if (found.containsKey(name)) {
                    throw new Invalid("duplicate_member");
                }
                skip();
                if (peek() != ':') {
                    throw new Invalid("invalid_json");
                }
                at++;
                found.put(name, value(level + 1));
                skip();
                char next = peek();
                at++;
                if (next == '}') {
                    return found;
                }
                if (next != ',') {
                    throw new Invalid("invalid_json");
                }
            }
        }

        private List<Object> rows(int level) {
            if (level > MAX_DEPTH) {
                throw new Invalid("depth_limit");
            }
            at++;
            List<Object> found = new ArrayList<>();
            skip();
            if (peek() == ']') {
                at++;
                return found;
            }
            while (true) {
                found.add(value(level + 1));
                skip();
                char next = peek();
                at++;
                if (next == ']') {
                    return found;
                }
                if (next != ',') {
                    throw new Invalid("invalid_json");
                }
            }
        }

        private String string() {
            at++;
            StringBuilder out = new StringBuilder();
            while (true) {
                if (at >= text.length()) {
                    throw new Invalid("invalid_json");
                }
                char c = text.charAt(at++);
                if (c == '"') {
                    return out.toString();
                }
                if (c < 0x20) {
                    throw new Invalid("invalid_json");
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (at >= text.length()) {
                    throw new Invalid("invalid_json");
                }
                char escape = text.charAt(at++);
                switch (escape) {
                    case '"', '\\', '/' -> out.append(escape);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> out.append(unit());
                    default -> throw new Invalid("invalid_json");
                }
            }
        }

        /** The four hexadecimal digits of a \\u escape. */
        private char unit() {
            if (at + 4 > text.length()) {
                throw new Invalid("invalid_json");
            }
            int value = 0;
            for (int i = 0; i < 4; i++) {
                int digit = text.charAt(at + i) < 0x80 ? Character.digit(text.charAt(at + i), 16) : -1;
                if (digit < 0) {
                    throw new Invalid("invalid_json");
                }
                value = value << 4 | digit;
            }
            at += 4;
            return (char) value;
        }

        private int digits() {
            int from = at;
            while (peek() >= '0' && peek() <= '9') {
                at++;
            }
            return at - from;
        }

        private Object number() {
            int start = at;
            if (peek() == '-') {
                at++;
            }
            if (peek() == '0') {
                at++;
            } else if (digits() == 0) {
                throw new Invalid("invalid_json");
            }
            boolean decimal = false;
            // A point or an exponent with no digit is not part of the number, and
            // what follows the number then fails as what it is.
            if (peek() == '.' && at + 1 < text.length() && text.charAt(at + 1) >= '0' && text.charAt(at + 1) <= '9') {
                at++;
                digits();
                decimal = true;
            }
            if (peek() == 'e' || peek() == 'E') {
                int mark = at;
                at++;
                if (peek() == '+' || peek() == '-') {
                    at++;
                }
                if (digits() == 0) {
                    at = mark;
                } else {
                    decimal = true;
                }
            }
            String token = text.substring(start, at);
            if (decimal) {
                double value = Double.parseDouble(token);
                if (Double.isInfinite(value) || Double.isNaN(value)) {
                    throw new Invalid("non_finite_number");
                }
                return value;
            }
            BigInteger value = new BigInteger(token);
            if (value.abs().compareTo(MAX_INTEGER) > 0) {
                throw new Invalid("integer_range");
            }
            return value.longValue();
        }
    }
}
