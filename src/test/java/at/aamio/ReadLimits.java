package at.aamio;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Asking the service for a small answer.
 *
 * The service has taken X-Limit and X-Max-Bytes since 0.7.2, and no file in this
 * package sent either. A thread may hold two hundred messages of 65536 bytes, so
 * one read can be about a megabyte. Measured on the live service on 20 September
 * 2026: the same thread, 20 529 bytes without the headers and 360 with them.
 *
 * Whole messages only. A signed message cut in half does not verify, so a budget
 * under the first message comes back as too_large naming it, never as a piece of
 * it. Nothing here does the cutting: the service does, and this asks and passes
 * on what came back.
 *
 * read(w, id, after, wait) keeps the signature every caller compiled against and
 * asks for nothing. The overload with limit and maxBytes is the one that asks.
 * Nothing here touches the network.
 *
 *   java -cp build/classes:build/test-classes at.aamio.ReadLimits
 */
public final class ReadLimits {
    private static final String W = "llllllllllllllllllll";

    private ReadLimits() {
    }

    private static Keys keys(int n) {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) n);
        return Keys.fromSeed(seed);
    }

    private static Map<String, Object> stored(String w, long seq, String body, Keys by) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("seq", seq);
        m.put("at", seq);
        m.put("type", "text");
        m.put("body", body);
        m.put("sha256", Codec.sha256Hex(body));
        m.put("from", by.publicKey());
        m.put("sig", by.sign(Keys.threadSigningInput(w, body)));
        m.put("verified", true);
        return m;
    }

    /** What the last call was sent, so a header that never left can be seen. */
    private static final List<Map<String, String>> SEEN = new ArrayList<>();
    private static final List<String> URLS = new ArrayList<>();

    private static void answering(Map<String, Object> body) {
        SEEN.clear();
        URLS.clear();
        Http.override = (method, url, reqBody, headers) -> {
            SEEN.add(headers == null ? Map.of() : new LinkedHashMap<>(headers));
            URLS.add(url);
            return new Http.Answer(200, body, Map.of());
        };
    }

    private static Map<String, Object> empty() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("w", W);
        body.put("exists", true);
        body.put("count", 0L);
        body.put("allow", List.of());
        body.put("messages", List.of());
        body.put("next", 0L);
        body.put("waited", 0L);
        return body;
    }

    private static String header(String name) {
        Map<String, String> sent = SEEN.get(SEEN.size() - 1);
        for (Map.Entry<String, String> entry : sent.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        Client client = new Client("http://example.invalid", null);

        Check.section("a read that asked for nothing");
        answering(empty());
        client.read(W, "read-key", 0, 0);
        Check.ok("read-key".equals(header("X-Read")), "the read key goes in the header");
        Check.ok(header("X-Limit") == null, "no X-Limit, so an older service sees the call it always saw");
        Check.ok(header("X-Max-Bytes") == null, "and no X-Max-Bytes");

        Check.section("a count and a budget");
        answering(empty());
        client.read(W, "read-key", 0, 0, 5, 4096);
        Check.ok("5".equals(header("X-Limit")), "the count reaches the wire");
        Check.ok("4096".equals(header("X-Max-Bytes")), "the budget reaches the wire");

        answering(empty());
        client.read(W, "read-key", 0, 0, 3, null);
        Check.ok("3".equals(header("X-Limit")) && header("X-Max-Bytes") == null, "a count on its own");
        answering(empty());
        client.read(W, "read-key", 0, 0, null, 2048);
        Check.ok(header("X-Limit") == null && "2048".equals(header("X-Max-Bytes")), "a budget on its own");

        Check.section("what the service left behind");
        Map<String, Object> shortened = empty();
        shortened.put("more", true);
        shortened.put("next", 12L);
        answering(shortened);
        Client.Read answer = client.read(W, "read-key", 0, 0, 2, null);
        Check.ok(Boolean.TRUE.equals(answer.answer().field("more")), "more comes back, so a short answer is not a quiet thread");
        Check.ok(answer.next() == 12L, "next is the last message handed over, or the next read steps over one");

        Map<String, Object> tooLarge = empty();
        tooLarge.put("too_large", Map.of("seq", 7L, "bytes", 70000L, "fix", "Raise X-Max-Bytes above 70000 or read this one on its own."));
        answering(tooLarge);
        Client.Read named = client.read(W, "read-key", 0, 0, null, 1024);
        Check.ok(named.answer().field("too_large") instanceof Map<?, ?>, "a message over budget is named, not cut");

        Check.section("the limits beside a cursor and a wait");
        answering(empty());
        client.read(W, "read-key", 9, 3, 4, null);
        Check.ok(URLS.get(0).endsWith("/" + W + "/after/9/wait/3"), "the path keeps both: " + URLS.get(0));
        Check.ok("4".equals(header("X-Limit")), "and the limit went with them");

        Check.section("a thread read with its allowlist");
        Keys alice = keys(1);
        Keys stranger = keys(9);
        Map<String, Object> two = empty();
        two.put("messages", List.of(stored(W, 1, "from a partner", alice), stored(W, 2, "from a stranger", stranger)));
        two.put("next", 2L);
        answering(two);
        Client.Opened opened = new Client.Opened("read-key", W, List.of(alice.publicKey()), new Http.Answer(201, Map.of(), Map.of()));
        Client.Read handed = client.readThread(opened, 0, 0, 2, 4096);
        Check.ok("2".equals(header("X-Limit")) && "4096".equals(header("X-Max-Bytes")), "the limits reach the wire through readThread");
        Check.ok(handed.messages().size() == 1 && handed.messages().get(0).seq() == 1L, "a smaller answer is not a looser one");
        Check.ok(handed.keptOut().size() == 1, "what the list kept out is still said out loud");

        Http.override = null;
        System.exit(Check.done());
    }
}
