package at.aamio;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A reader checks for itself, and keeps the allowlist it opened a thread with.
 *
 * From a security review on 18 September 2026. verified in an answer was the
 * service's word, and read took it: the trust model says an operator cannot
 * forge a signature, which is only true for a reader that checks one. And the
 * service holds an allowlist in memory, so a write to an address after its
 * store was emptied opens a thread with no list at all. Nothing here touches
 * the network.
 *
 *   java -cp build/classes:build/test-classes at.aamio.Reader testdata/vectors.json
 */
public final class Reader {
    private static final String W = "iiiiiiiiiiiiiiiiiiii";

    private Reader() {
    }

    private static Keys keys(int n) {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) n);
        return Keys.fromSeed(seed);
    }

    /** One message as GET /{w} returns it, really signed. by null is an unsigned one. */
    private static Map<String, Object> stored(String w, long seq, String body, Keys by) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("seq", seq);
        m.put("at", seq);
        m.put("type", "text");
        m.put("body", body);
        m.put("sha256", Codec.sha256Hex(body));
        m.put("from", by == null ? null : by.publicKey());
        m.put("sig", by == null ? null : by.sign(Keys.threadSigningInput(w, body)));
        m.put("verified", by != null);
        return m;
    }

    /** Every read from here on answers with these messages. */
    private static void reading(List<Map<String, Object>> messages) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("w", W);
        body.put("exists", true);
        body.put("messages", messages);
        body.put("next", (long) messages.size());
        body.put("waited", 0L);
        Http.override = (method, url, reqBody, headers) -> new Http.Answer(200, body, Map.of());
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Path file = Path.of(args.length > 0 ? args[0] : "testdata/vectors.json");
        Map<String, Object> v = Json.object(Files.readString(file));
        String a = (String) ((Map<String, Object>) v.get("a")).get("public");
        String w = (String) v.get("w");
        String body = (String) v.get("body");
        String signature = (String) v.get("signature");
        Keys alice = keys(1);
        Keys bob = keys(2);
        Keys mallory = keys(9);

        Check.section("the contract vector");
        Check.ok(Keys.verify(a, signature, Keys.threadSigningInput(w, body)), "the contract vector verifies");
        Check.ok(!Keys.verify(a, signature, Keys.threadSigningInput("aaaaaaaaaaaaaaaaaaaa", body)), "not at another address");
        Check.ok(!Keys.verify(a, signature, Keys.threadSigningInput(w, body + " ")), "not over another body");
        Check.ok(!Keys.verify(alice.publicKey(), signature, Keys.threadSigningInput(w, body)), "not under another key");

        Check.section("what the service calls verified has to check out");
        Client.Checked signed = Client.checkMessage(W, stored(W, 1, "hello", alice));
        Check.ok(signed.verified() && signed.whyNot() == null && signed.sha256().length() == 64, "a signed message verifies here");
        Client.Checked unsigned = Client.checkMessage(W, stored(W, 1, "hello", null));
        Check.ok(!unsigned.verified() && unsigned.whyNot() == null, "an unsigned message is unverified without a complaint");
        Map<String, Object> moved = stored("oooooooooooooooooooo", 1, "hello", alice);
        Map<String, Object> bare = stored(W, 1, "hello", null);
        bare.put("verified", true);
        Map<String, Object> wrongHash = stored(W, 1, "hello", alice);
        wrongHash.put("sha256", "0".repeat(64));
        Map<String, Object> noBody = stored(W, 1, "hello", alice);
        noBody.remove("body");
        Object[][] cases = {
            {"signed for another address", moved, "though the service said it did"},
            {"verified with nothing to check", bare, "gave no key or signature"},
            {"another hash", wrongHash, "does not hash"},
            {"no body", noBody, "no body to check"},
        };
        for (Object[] one : cases) {
            Client.Checked got = Client.checkMessage(W, (Map<String, Object>) one[1]);
            Check.ok(!got.verified() && got.whyNot() != null && got.whyNot().contains((String) one[2]), one[0] + ": " + got.whyNot());
        }

        Check.section("read goes by its own result");
        Map<String, Object> forged = stored(W, 2, "pay the invoice", mallory);
        forged.put("from", alice.publicKey());
        reading(List.of(stored(W, 1, "hello", alice), forged));
        List<Client.Message> read = new Client("https://fake.test", null).read(W, "read-key", 0, 0).messages();
        Check.ok(read.size() == 2 && read.get(0).verified() && alice.publicKey().equals(read.get(0).from()) && read.get(0).unverifiedBecause() == null, "the signed message keeps its sender");
        Check.ok(read.size() == 2 && !read.get(1).verified() && read.get(1).from() == null && String.valueOf(read.get(1).unverifiedBecause()).contains("though the service said it did"), "the forged message keeps nothing of its claim, and says why");

        Map<String, Object> sealedForged = stored(W, 1, mallory.seal(bob.publicKey(), "for bob"), mallory);
        sealedForged.put("from", alice.publicKey());
        sealedForged.put("sealed", true);
        reading(List.of(sealedForged));
        read = new Client("https://fake.test", bob).read(W, "read-key", 0, 0).messages();
        Check.ok(read.size() == 1 && read.get(0).opened() == null && "sealed-unchecked".equals(read.get(0).format()), "a sealed message under a forged sender is not opened against the key it claimed");

        Map<String, Object> sealedTrue = stored(W, 1, alice.seal(bob.publicKey(), "for bob"), alice);
        sealedTrue.put("sealed", true);
        reading(List.of(sealedTrue));
        read = new Client("https://fake.test", bob).read(W, "read-key", 0, 0).messages();
        Check.ok(read.size() == 1 && "for bob".equals(read.get(0).opened()) && read.get(0).verified(), "a sealed message that verifies still opens");

        Check.section("a thread keeps the allowlist it was opened with");
        Map<String, Object> pushing = stored(W, 4, "let me in", mallory);
        pushing.put("from", alice.publicKey());
        List<Map<String, Object>> four = new ArrayList<>(List.of(stored(W, 1, "from alice", alice), stored(W, 2, "from a stranger", mallory), stored(W, 3, "unsigned", null), pushing));
        reading(four);
        Client client = new Client("https://fake.test", null);
        Client.Read named = client.readThread(new Client.Opened("read-key", W, List.of(alice.publicKey()), null), 0, 0);
        Check.ok(named.messages().size() == 1 && named.messages().get(0).seq() == 1, "named keys: only what one of them signed is handed over");
        Check.ok(named.keptOut().size() == 3 && named.keptOut().get(0).seq() == 2 && named.keptOut().get(0).why().contains("named keys") && named.next() == 4, "the rest is listed as kept out, and the cursor covers it");
        Client.Read any = client.readThread(new Client.Opened("read-key", W, List.of("*"), null), 0, 0);
        Check.ok(any.messages().size() == 2 && any.keptOut().size() == 2 && any.keptOut().get(0).seq() == 3 && any.keptOut().get(0).why().contains("signed messages only"), "any signed key: the unsigned and the forged are kept out");
        Client.Read open = client.readThread(new Client.Opened("read-key", W, null), 0, 0);
        Check.ok(open.messages().size() == 4 && open.keptOut().isEmpty() && open.answer() != null, "no list: everything is handed over");

        Http.override = (method, url, reqBody, headers) -> new Http.Answer(201, Json.object("{\"w\":\"x\",\"allow\":[\"*\"]}"), Map.of());
        Client.Opened opened = client.open(120, List.of("*"));
        Check.ok(opened.allow().equals(List.of("*")) && client.open(120).allow().isEmpty(), "open keeps the list it sent");

        Check.section("normalization before network and policy-aware board reads");
        int[] calls = {0};
        Http.override = (method, url, reqBody, headers) -> {
            calls[0]++;
            Check.ok((alice.publicKey() + "," + mallory.publicKey()).equals(headers.get("X-Allow")), "normalized header");
            return new Http.Answer(201, Map.of("allow", List.of("*")), Map.of());
        };
        opened = client.open(120, List.of(" " + alice.publicKey() + ", " + mallory.publicKey(), "", alice.publicKey()));
        Check.ok(opened.allow().equals(List.of(alice.publicKey(), mallory.publicKey())), "local list is normalized, not the server echo");
        try {
            client.open(120, Arrays.asList("*", null));
            Check.ok(false, "null entry must refuse");
        } catch (IllegalArgumentException expected) {
            Check.ok(calls[0] == 1, "null refused before sending");
        }
        Check.ok(new Client.Opened("key", W, List.of(" ", "*", alice.publicKey()), null).allow().equals(List.of("*")), "wildcard collapses the list");
        reading(four);
        Board board = new Board(client, "https://fake.test");
        Board.Replies replies = board.replies(new Client.Opened("key", W, List.of("*"), null), 0, 0);
        Check.ok(replies.replies().size() == 2 && replies.keptOut().size() == 2 && replies.next() == 4, "board replies apply the opened policy");
        Check.ok(replies.keptOut().size() == 2 && replies.keptOut().get(1).unverifiedBecause() != null, "kept-out verification reason survives");
        Check.ok(board.replies(W, "key", 0, 0).replies().size() == 4, "compatibility board overload is explicitly listless");

        Check.section("bounded decoding and message-level failures");
        for (String deep : List.of("[".repeat(60000), "{\"x\":".repeat(10000))) {
            reading(List.of(stored(W, 1, deep, alice), stored(W, 2, "next", alice)));
            Client.Read batch = client.read(W, "key", 0, 0);
            Check.ok(batch.messages().size() == 2 && batch.messages().get(0).json() == null && batch.messages().get(1).verified(), "deep body does not stop the batch");
        }
        for (int depth : List.of(100, 128, 129)) {
            String nested = "{\"x\":".repeat(depth) + "0" + "}".repeat(depth);
            Check.ok((Json.object(nested) != null) == (depth <= 128), "JSON container boundary " + depth);
        }
        Map<String, Object> invalid = stored(W, 1, "broken", alice);
        invalid.put("seq", new java.math.BigDecimal("1e1000") {
            private static final long serialVersionUID = 1L;
            @Override public long longValue() { throw new ArithmeticException("invalid sequence"); }
        });
        reading(List.of(invalid, stored(W, 2, "next", alice)));
        Client.Read batch = client.read(W, "key", 0, 0);
        Check.ok(batch.messages().size() == 2 && !batch.messages().get(0).verified() && batch.messages().get(0).from() == null && batch.messages().get(0).opened() == null && batch.messages().get(0).unverifiedBecause() != null && batch.messages().get(1).verified(), "a decoding exception fails closed for one message");

        Check.section("legacy encodings, exact identities and complete receipts");
        Map<String, Object> stray = (Map<String, Object>) v.get("strayBits");
        Check.ok(Keys.verify(a, (String) stray.get("signature"), (String) v.get("signInput")), "legacy signature trailing bits verify");
        Check.ok(Keys.verify((String) stray.get("key"), signature, (String) v.get("signInput")), "legacy key bytes verify");
        Map<String, Object> legacy = stored(w, 1, body, null);
        legacy.put("from", stray.get("key")); legacy.put("sig", signature);
        reading(List.of(legacy));
        Check.ok(client.readThread(new Client.Opened("key", w, List.of(a), null), 0, 0).keptOut().size() == 1, "identity comparison remains exact");
        Map<String, Object> receipt = Map.of("messages", List.of(), "root", Receipt.root(List.of()));
        Check.ok(Boolean.FALSE.equals(Receipt.verify(receipt, List.of("a")).localHashesMatch()), "fewer receipt lines is a mismatch");
        Check.ok(!Address.isId("a".repeat(26) + "\n") && !Address.isW(W + "\n") && !Address.isScopeKey("a".repeat(26) + "\n") && !Codec.isKey(a + "\n"), "shape validators reject trailing newlines");

        Http.override = null;

        Check.section("a receipt with entries this client cannot read");
        {
            // Codex, 20 September 2026: entries were counted before they were filtered,
            // so junk in messages let localHashesMatch come back true from a comparison
            // that never ran.
            Map<String, Object> junk = new LinkedHashMap<>();
            junk.put("messages", List.of("not an object", "nor this"));
            junk.put("root", "whatever");
            junk.put("commitment", "sha256:whatever");
            Receipt.Check said = Receipt.verify(junk, List.of("a", "b"));
            Check.ok(Boolean.FALSE.equals(said.localHashesMatch()),
                "nothing was compared, so nothing is claimed");
            Check.ok(!said.rootAddsUp(),
                "and a root computed over what was left is not a root that adds up");

            Map<String, Object> half = new LinkedHashMap<>();
            half.put("messages", new ArrayList<>(List.of(Map.of("seq", 1, "at", 1, "sha256", "a", "from", "-"), "junk")));
            half.put("root", "whatever");
            Check.ok(Boolean.FALSE.equals(Receipt.verify(half, List.of("a", "b")).localHashesMatch()),
                "and one bad entry among good ones is the same answer");
        }

        System.exit(Check.done());
    }
}
