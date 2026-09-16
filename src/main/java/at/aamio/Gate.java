package at.aamio;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * What an inbox asks of whoever writes to it, and what this client does about
 * it. The ceilings are the service's own, so an inbox run by a stranger can
 * never make this client spend more CPU than aamio lets any inbox ask for.
 */
public final class Gate {
    public static final int REQUIRE_MAX_BITS = 20;
    public static final int ADVISE_MAX_BITS = 18;

    private static final Pattern NONCE = Pattern.compile("^[A-Za-z0-9_-]{1,64}$");

    private Gate() {
    }

    // ----------------------------------------------------------- canonical --

    /**
     * The text a gate_hash is taken over: keys sorted by their UTF-8 bytes at
     * every level, no whitespace, integers as integers, an empty object as {},
     * empty buckets removed, strings escaped only where JSON requires it.
     */
    public static String canonical(Map<String, Object> gate) {
        Map<String, Object> pruned = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : gate.entrySet()) {
            boolean bucket = e.getKey().equals("require") || e.getKey().equals("advise");
            if (bucket && e.getValue() instanceof Map<?, ?> m && m.isEmpty()) {
                continue;
            }
            pruned.put(e.getKey(), e.getValue());
        }
        return Json.canonical(pruned);
    }

    /** sha256 hex over the canonical text. */
    public static String hash(Map<String, Object> gate) {
        return Codec.sha256Hex(canonical(gate));
    }

    /** Gate JSON as a map; integers stay integers. */
    public static Map<String, Object> parse(String text) {
        Map<String, Object> gate = Json.object(text);
        if (gate == null) {
            throw new IllegalArgumentException("a gate is a JSON object");
        }
        return gate;
    }

    // ---------------------------------------------------------------- work --

    /** What thread work is computed over. key is the X-Key exactly as sent, or empty for an unsigned message, so two line breaks meet. */
    public static String powInput(String w, String key, String bodySha256, String nonce) {
        return "aamio-pow-v1\n" + w + "\n" + key + "\n" + bodySha256 + "\n" + nonce;
    }

    public static byte[] powDigest(String w, String key, String bodySha256, String nonce) {
        return Codec.sha256(Codec.utf8(powInput(w, key, bodySha256, nonce)));
    }

    /** What board work is computed over: no address, a post is not to a thread. */
    public static String boardPowInput(String key, String bodySha256, String nonce) {
        return "aamio-board-pow-v1\n" + key + "\n" + bodySha256 + "\n" + nonce;
    }

    public static byte[] boardPowDigest(String key, String bodySha256, String nonce) {
        return Codec.sha256(Codec.utf8(boardPowInput(key, bodySha256, nonce)));
    }

    /** Leading zero bits from the top bit of the first byte. */
    public static int zeroBits(byte[] digest) {
        int bits = 0;
        for (byte b : digest) {
            int v = b & 0xff;
            if (v == 0) {
                bits += 8;
                continue;
            }
            bits += Integer.numberOfLeadingZeros(v) - 24;
            break;
        }
        return bits;
    }

    /** The first nonce, counting from 0, whose thread digest reaches bits. */
    public static String solve(String w, String key, byte[] body, int bits) {
        return search("aamio-pow-v1\n" + w + "\n" + key + "\n" + Codec.sha256Hex(body) + "\n", bits);
    }

    /** The first nonce whose board digest reaches bits. */
    public static String solveBoard(String key, byte[] body, int bits) {
        return search("aamio-board-pow-v1\n" + key + "\n" + Codec.sha256Hex(body) + "\n", bits);
    }

    private static String search(String prefix, int bits) {
        if (bits < 0 || bits > REQUIRE_MAX_BITS) {
            throw new IllegalArgumentException("work is 0 to " + REQUIRE_MAX_BITS + " bits");
        }
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        byte[] head = Codec.utf8(prefix);
        for (long n = 0; ; n++) {
            String nonce = Long.toString(n);
            md.reset();
            md.update(head);
            md.update(Codec.utf8(nonce));
            if (zeroBits(md.digest()) >= bits) {
                return nonce;
            }
        }
    }

    /** Whether s is a valid X-Work value: 1 to 64 characters of [A-Za-z0-9_-]. */
    public static boolean isNonce(String s) {
        return s != null && NONCE.matcher(s).matches();
    }

    // ---------------------------------------------------------------- plan --

    /**
     * What to do about a gate before writing: bits to work for (-1 for none),
     * stop with the reason when the send must not happen (null otherwise),
     * notes for what was passed over.
     */
    public record Plan(int bits, String stop, List<String> notes) {
    }

    /** Reads a gate and decides. A null or empty gate is nothing to do. */
    public static Plan plan(Map<String, Object> gate) {
        int bits = -1;
        List<String> notes = new ArrayList<>();
        if (gate == null || gate.isEmpty()) {
            return new Plan(bits, null, notes);
        }
        if (gate.get("require") instanceof Map<?, ?> require) {
            for (Map.Entry<?, ?> e : new TreeMap<>(stringKeys(require)).entrySet()) {
                String condition = e.getKey().toString();
                if (!condition.equals("pow") && !condition.equals("per_key") && !condition.equals("write_until")) {
                    return new Plan(bits, "the inbox requires \"" + condition + "\", which this client does not know; nothing was sent", notes);
                }
                if (condition.equals("pow")) {
                    int asked = bitsOf(e.getValue());
                    if (asked > REQUIRE_MAX_BITS) {
                        return new Plan(bits, "the inbox requires " + asked + " bits of work, above the " + REQUIRE_MAX_BITS + " aamio lets an inbox ask for; nothing was sent", notes);
                    }
                    bits = Math.max(bits, asked);
                }
            }
        }
        if (gate.get("advise") instanceof Map<?, ?> advise) {
            for (Map.Entry<?, ?> e : new TreeMap<>(stringKeys(advise)).entrySet()) {
                String condition = e.getKey().toString();
                if (!condition.equals("pow")) {
                    notes.add("the inbox advises \"" + condition + "\", which this client does not know, and it was passed over");
                    continue;
                }
                int asked = bitsOf(e.getValue());
                if (asked > ADVISE_MAX_BITS) {
                    notes.add("the inbox advises " + asked + " bits of work, above the " + ADVISE_MAX_BITS + " a client does without asking, and it was passed over");
                    continue;
                }
                bits = Math.max(bits, asked);
            }
        }
        return new Plan(bits, null, notes);
    }

    private static Map<String, Object> stringKeys(Map<?, ?> m) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : m.entrySet()) {
            out.put(String.valueOf(e.getKey()), e.getValue());
        }
        return out;
    }

    private static int bitsOf(Object v) {
        if (v instanceof Map<?, ?> m && m.get("bits") instanceof Number n) {
            return n.intValue();
        }
        return 0;
    }
}
