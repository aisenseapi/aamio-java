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
 * 32 bits is for an inbox that means to meet only writers with real compute,
 * so the plan weighs the work against the time the inbox has left and says no
 * before it starts, rather than learning it from a 410 an hour later.
 */
public final class Gate {
    public static final int REQUIRE_MAX_BITS = 32;
    public static final int ADVISE_MAX_BITS = 18;
    /** Below this the work is a second or so, and not worth timing first. */
    private static final int ESTIMATE_FROM_BITS = 17;
    private static volatile double rate;

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
        return search("aamio-pow-v1\n" + w + "\n" + key + "\n" + Codec.sha256Hex(body) + "\n", bits, null);
    }

    /**
     * solve with a deadline: null when it passes first, and a null deadline is
     * none. Past the life of the inbox the work buys nothing, and 32 bits can
     * run for hours.
     */
    public static String solveUntil(String w, String key, byte[] body, int bits, java.time.Instant deadline) {
        return search("aamio-pow-v1\n" + w + "\n" + key + "\n" + Codec.sha256Hex(body) + "\n", bits, deadline);
    }

    /** The first nonce whose board digest reaches bits. */
    public static String solveBoard(String key, byte[] body, int bits) {
        return search("aamio-board-pow-v1\n" + key + "\n" + Codec.sha256Hex(body) + "\n", bits, null);
    }

    /**
     * Attempts a second the search makes on this machine, timed once and kept.
     * The estimate before long work is only as good as this number, so it is the
     * search's own loop that is timed, for a quarter of a second.
     */
    public static double hashRate() {
        if (rate == 0) {
            MessageDigest md;
            try {
                md = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
            byte[] head = Codec.utf8("aamio-pow-v1\ncalibration\n\n" + "0".repeat(64) + "\n");
            long count = 0;
            long start = System.nanoTime();
            long elapsed;
            do {
                for (int i = 0; i < 4096; i++, count++) {
                    md.reset();
                    md.update(head);
                    md.update(Codec.utf8(Long.toString(count)));
                    zeroBits(md.digest());
                }
                elapsed = System.nanoTime() - start;
            } while (elapsed < 250_000_000L);
            rate = count / (elapsed / 1e9);
        }
        return rate;
    }

    /** How long bits of work takes here on average. A lottery: one in a hundred takes about 4.6 times as long. */
    public static double expectedSeconds(int bits) {
        return Math.pow(2, bits) / hashRate();
    }

    /** A time in seconds as a person would say it. */
    public static String describe(double seconds) {
        if (seconds < 90) {
            return Math.max(1, Math.round(seconds)) + " seconds";
        }
        if (seconds < 5400) {
            return Math.round(seconds / 60) + " minutes";
        }
        return String.format(java.util.Locale.ROOT, "%.1f hours", seconds / 3600);
    }

    private static String search(String prefix, int bits, java.time.Instant deadline) {
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
            // Every 65536 attempts, a tenth of a second or so here.
            if (deadline != null && (n & 0xFFFF) == 0xFFFF && java.time.Instant.now().isAfter(deadline)) {
                return null;
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
     * notes for what was passed over, and how long the required work takes
     * here, when a time left was given.
     */
    public record Plan(int bits, String stop, List<String> notes, double expectedSeconds) {
        public Plan(int bits, String stop, List<String> notes) {
            this(bits, stop, notes, 0);
        }
    }

    /** Reads a gate and decides. A null or empty gate is nothing to do. */
    public static Plan plan(Map<String, Object> gate) {
        return plan(gate, -1);
    }

    /**
     * plan, weighed against secondsLeft, how long the inbox still takes writes,
     * from X-Seconds-Left on its gate; negative is unknown. Work that would not
     * be done by then is not started.
     */
    public static Plan plan(Map<String, Object> gate, double secondsLeft) {
        int bits = -1;
        double expected = 0;
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
                    if (secondsLeft >= 0) {
                        expected = asked >= ESTIMATE_FROM_BITS ? expectedSeconds(asked) : 0;
                        if (expected > secondsLeft) {
                            return new Plan(bits, "the inbox requires " + asked + " bits of work, which takes about " + describe(expected) + " on this machine, and it takes writes for " + describe(secondsLeft) + " more. The work would not be done before it closes, so it was not started and nothing was sent. Ask the owner for a longer inbox or less work, or send from a machine with more compute", notes);
                        }
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
        return new Plan(bits, null, notes, expected);
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
