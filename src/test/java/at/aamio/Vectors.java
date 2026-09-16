package at.aamio;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * The vectors every client shares, reproduced here with nothing in between,
 * then the client against a fake service. testdata/vectors.json is the file
 * aamio-js keeps; the gate vectors are the ones the service, aamio-python,
 * aamio-php, aamio-go and aamio-rust check. Nothing here touches the network.
 *
 *   java -cp build/classes:build/test-classes at.aamio.Vectors testdata/vectors.json
 */
public final class Vectors {
    private Vectors() {
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Path file = Path.of(args.length > 0 ? args[0] : "testdata/vectors.json");
        Map<String, Object> v = Json.object(Files.readString(file));
        Map<String, Object> a = (Map<String, Object>) v.get("a");
        Map<String, Object> b = (Map<String, Object>) v.get("b");
        String id = (String) v.get("id");
        String w = (String) v.get("w");
        String body = (String) v.get("body");
        boolean threw;

        Check.section("encodings");
        Check.ok(Codec.sha256Hex("abc").equals(v.get("sha256_abc")), "sha256 of abc");
        Check.ok(Codec.b64url(new byte[] {(byte) 0xfb, (byte) 0xff}).equals("-_8"), "base64url without padding");
        Check.ok(Arrays.equals(Codec.unb64url("+/8="), new byte[] {(byte) 0xfb, (byte) 0xff}), "standard base64 with padding is accepted too");
        Check.ok(Codec.isKey((String) a.get("public")) && !Codec.isKey("short"), "key shape");
        Check.ok(Codec.base32(new byte[] {'f', 'o', 'o', 'b', 'a', 'r'}).equals("mzxw6ytboi"), "base32, lowercase, without padding");
        Check.ok(Codec.hex(Codec.unhex("00ff10")).equals("00ff10"), "hex round trip");

        Check.section("json");
        Map<String, Object> parsed = (Map<String, Object>) Json.parse("{\"a\":[1,2.5,\"x\",true,null,{\"b\":\"\\u00e6\\ud83d\\ude00\"}],\"n\":-7}");
        List<Object> items = (List<Object>) parsed.get("a");
        Check.ok(items.get(0).equals(1L) && items.get(1).equals(2.5) && items.get(2).equals("x") && items.get(3).equals(Boolean.TRUE) && items.get(4) == null && parsed.get("n").equals(-7L), "integers are Long, other numbers Double, null is null");
        Check.ok(((Map<String, Object>) items.get(5)).get("b").equals("æ😀"), "unicode escapes and surrogate pairs decode");
        Check.ok(Json.write(parsed).equals("{\"a\":[1,2.5,\"x\",true,null,{\"b\":\"æ😀\"}],\"n\":-7}"), "write is compact, in order, with UTF-8 raw");
        Check.ok(Json.write(Map.of("s", "a\"b\\c/d\n")).equals("{\"s\":\"a\\\"b\\\\c/d\\u0001\\n\"}"), "only the quote, the backslash and controls are escaped");
        threw = false;
        try {
            Json.parse("{\"a\":1,}");
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        Check.ok(threw, "a trailing comma is refused");
        Check.ok(Json.object("[1]") == null && Json.object("nope") == null && Json.object(null) == null, "object() is null for a list, for text and for nothing");

        Check.section("addresses");
        Check.ok(Address.w(id).equals(w), "w(id) is the shared vector");
        Check.ok(Address.w("aamio0000000000000000000ok").equals("5d6gubrpdewztqru2nmi"), "w(aamio…ok)");
        String fresh = Address.newId();
        Check.ok(fresh.length() == 26 && Address.isId(fresh) && Address.isW(Address.w(fresh)), "a fresh id is 26 characters of the alphabet, and its w has the shape");
        threw = false;
        try {
            Address.w("short");
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        Check.ok(threw, "a short id is refused before it is hashed");

        Check.section("keys");
        Keys ka = Keys.fromSeedHex((String) a.get("seed"));
        Keys kb = Keys.fromSeedHex((String) b.get("seed"));
        Check.ok(ka.publicKey().equals(a.get("public")) && kb.publicKey().equals(b.get("public")), "public keys from seeds, derived on the curve here");
        Check.ok(ka.hash().equals(a.get("hash")) && ka.hashPrefix().equals(((String) a.get("hash")).substring(0, 8)), "hash of A");
        Check.ok(Codec.hex(Keys.curvePublic(ka.publicKey())).equals(a.get("curvePublic")) && Codec.hex(Keys.curvePublic(kb.publicKey())).equals(b.get("curvePublic")), "X25519 public keys, as libsodium derives them");
        Check.ok(Keys.threadSigningInput(w, body).equals(v.get("signInput")), "thread signing input");
        String input = (String) v.get("signInput");
        String sig = (String) v.get("signature");
        Check.ok(ka.sign(input).equals(sig), "signature of A over it, byte for byte");
        Check.ok(Keys.verify(ka.publicKey(), sig, input) && !Keys.verify(kb.publicKey(), sig, input) && !Keys.verify(ka.publicKey(), sig, input + "x"), "verify");
        Check.ok(Keys.fromSeed(ka.seed()).publicKey().equals(ka.publicKey()), "a key rebuilt from its seed is the same key");
        Check.ok(!Keys.verify("not a key", sig, input) && !Keys.verify(ka.publicKey(), "AAAA", input), "garbage never verifies");

        Check.section("sealing");
        Check.ok(Codec.utf8(kb.open(ka.publicKey(), (String) v.get("envelopeFromAToB"))).equals(v.get("plaintext")), "B opens the envelope A sealed, made by PyNaCl");
        String env = ka.seal(kb.publicKey(), "fra java til hvem som helst");
        Check.ok(env.startsWith("{\"e2ee\":\"nacl.box.v1\",\"to\":\"" + kb.hashPrefix() + "\",\"nonce\":\"") && Keys.isEnvelope(env), "envelope shape");
        Check.ok(Codec.utf8(kb.open(ka.publicKey(), env)).equals("fra java til hvem som helst"), "B opens what A sealed here");
        String why = "";
        try {
            ka.open(kb.publicKey(), env);
        } catch (IllegalArgumentException e) {
            why = e.getMessage();
        }
        Check.ok(why.contains("sealed to"), "A cannot open an envelope sealed to B, and is told whom it was sealed to");
        threw = false;
        try {
            kb.open(Keys.generate().publicKey(), env);
        } catch (IllegalArgumentException e) {
            threw = true;
        }
        Check.ok(threw, "does not open with the wrong sender key");
        Check.ok(!ka.seal(kb.publicKey(), "x").equals(env), "a fresh nonce every time");
        Check.ok(!Keys.isEnvelope("{\"e2ee\":\"nacl.box.v1\"}") && !Keys.isEnvelope("plain text"), "a body without nonce and ct is not an envelope");
        byte[] big = new byte[70000];
        new Random(7).nextBytes(big);
        Check.ok(Arrays.equals(kb.open(ka.publicKey(), ka.seal(kb.publicKey(), big)), big), "a box of many blocks opens byte for byte");

        Check.section("receipt");
        Map<String, Object> receipt = (Map<String, Object>) v.get("receipt");
        List<Object> messages = (List<Object>) receipt.get("messages");
        Check.ok(Receipt.root(messages).equals(receipt.get("root")), "the root recomputed from the lines is the published root");
        Receipt.Check c = Receipt.verify(receipt, null);
        Check.ok(c.rootAddsUp() && c.commitmentMatches() && c.localRootMatches() == null, "root_adds_up and commitment_matches on a real receipt, local unknown");
        Check.ok(Receipt.root(List.of(messages.get(1), messages.get(0))).equals(receipt.get("root")), "the order the lines arrive in does not matter, seq does");
        Map<String, Object> broken = new LinkedHashMap<>(receipt);
        Map<String, Object> first = new LinkedHashMap<>((Map<String, Object>) messages.get(0));
        first.put("sha256", "0".repeat(64));
        broken.put("messages", List.of(first, messages.get(1)));
        Check.ok(!Receipt.verify(broken, null).rootAddsUp(), "one changed hash breaks the root");
        List<String> hashes = List.of((String) ((Map<?, ?>) messages.get(0)).get("sha256"), (String) ((Map<?, ?>) messages.get(1)).get("sha256"));
        Check.ok(Boolean.TRUE.equals(Receipt.verify(receipt, hashes).localRootMatches()), "local hashes that match say so");
        Check.ok(Receipt.verify(receipt, hashes.subList(0, 1)).localRootMatches() == null, "fewer local hashes than the receipt counts is null, not a failure");
        Check.ok(Boolean.FALSE.equals(Receipt.verify(receipt, List.of(hashes.get(1), hashes.get(0))).localRootMatches()), "local hashes in another order do not match");

        Check.section("gate vectors");
        String gw = "b4netymg7r5nnt2yiscp";
        String gkey = "A".repeat(43);
        String gbody = "{\"post\":\"abc\",\"reply_to\":\"xyz\",\"text\":\"hei\"}";
        String gsha = "36751f20147f74e3dfbaf829fb8f04ea9ed596268bd685a69fdfa5992fddd6b8";
        Check.ok(Codec.sha256Hex(gbody).equals(gsha), "the vector body hashes to the published sha256");
        byte[] signed = Gate.powDigest(gw, gkey, gsha, "7036");
        Check.ok(Codec.hex(signed).equals("00003a2ac769f2265d621969d9ff1feaaa2b9dcc6f006b6adae1d22c2db8a842") && Gate.zeroBits(signed) == 18, "signed: nonce 7036 gives 18 bits");
        byte[] unsigned = Gate.powDigest(gw, "", gsha, "91617");
        Check.ok(Codec.hex(unsigned).equals("000018b5cc286cf27d2c97296aff9e2e60db0c165e7cf3af7a44857423c08612") && Gate.zeroBits(unsigned) == 19, "unsigned: nonce 91617 gives 19 bits");
        Check.ok(Gate.powInput(gw, "", gsha, "1").contains("\n\n"), "an unsigned message puts an empty key in the input");
        Check.ok(Gate.zeroBits(Gate.powDigest(gw, "B".repeat(43), gsha, "7036")) < 16 && Gate.zeroBits(Gate.powDigest(gw, "", gsha, "7036")) < 16
            && Gate.zeroBits(Gate.powDigest("aaaaaaaaaaaaaaaaaaaa", gkey, gsha, "7036")) < 16 && Gate.zeroBits(Gate.powDigest(gw, gkey, "0".repeat(64), "7036")) < 16, "work is bound to what it was done for");
        byte[] twelve = new byte[32];
        twelve[1] = 0x0f;
        Check.ok(Gate.zeroBits(new byte[32]) == 256 && Gate.zeroBits(twelve) == 12 && Gate.zeroBits(new byte[] {(byte) 0x80}) == 0 && Gate.zeroBits(new byte[] {0x01}) == 7, "zero bits from the top bit of the first byte");
        String nonce = Gate.solve(gw, gkey, Codec.utf8(gbody), 8);
        Check.ok(Gate.isNonce(nonce) && Gate.zeroBits(Gate.powDigest(gw, gkey, gsha, nonce)) >= 8, "solve reaches the bits");
        String boardNonce = Gate.solveBoard(gkey, Codec.utf8(gbody), 6);
        Check.ok(Gate.zeroBits(Gate.boardPowDigest(gkey, gsha, boardNonce)) >= 6, "board work solves the same way");
        Check.ok(!Gate.isNonce("") && !Gate.isNonce("a".repeat(65)) && !Gate.isNonce("a b") && Gate.isNonce("x_-9"), "nonce shape");

        Check.section("canonical");
        Map<String, Object> g = Gate.parse("{\"advise\":{\"pow\":{\"covers\":1,\"bits\":16}},\"require\":{}}");
        Check.ok(Gate.canonical(g).equals("{\"advise\":{\"pow\":{\"bits\":16,\"covers\":1}}}"), "keys sorted, empty bucket removed");
        Check.ok(Gate.hash(g).equals("de2a8fd4c8d7cbf9f6839c810632caf2c4b40fd8ba99ad19678f6c5b063d4d64"), "published gate_hash");
        Map<String, Object> e = Gate.parse("{\"require\":{},\"advise\":{}}");
        Check.ok(Gate.canonical(e).equals("{}") && Gate.hash(e).equals("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"), "an empty gate is {} and hashes to the published value");
        int[] points = {0x61, 0x22, 0x62, 0x5C, 0x63, 0x2F, 0x64, 0x01, 0x65, 0x1F, 0x66, 0x0A, 0x67, 0xE6, 0x68, 0x2028, 0x69, 0x1F600, 0x6A, 0x7F};
        String canon = Gate.canonical(Map.of("s", new String(points, 0, points.length)));
        Check.ok(Codec.hex(Codec.utf8(canon)).equals("7b2273223a22615c22625c5c632f645c7530303031655c7530303166665c6e67c3a668e280a869f09f98806a7f227d"), "string escaping, byte for byte");
        Check.ok(Codec.sha256Hex(canon).equals("b089754be373b84fb2b5fd2d6db856363986712915c98a5f7a412ff38b313b63"), "and it hashes to the published value");
        Check.ok(Json.canonical(Map.of("b", 1, "a", 2)).equals("{\"a\":2,\"b\":1}") && Json.canonical(Map.of("x", 2.0)).equals("{\"x\":2}"), "sorted keys, an integral double is an integer");
        Map<String, Object> order = new LinkedHashMap<>();
        order.put("😀", 1);
        order.put("～", 2);
        Check.ok(Json.canonical(order).equals("{\"～\":2,\"😀\":1}"), "keys sort by their UTF-8 bytes, as the other clients do, not by UTF-16 code unit");

        Check.section("plan");
        Check.ok(Gate.plan(null).bits() == -1 && Gate.plan(null).stop() == null && Gate.plan(Map.of()).bits() == -1, "no gate: nothing to do");
        Check.ok(Gate.plan(Gate.parse("{\"advise\":{\"pow\":{\"bits\":16,\"covers\":1}}}")).bits() == 16, "advised 16 bits are done without asking");
        Gate.Plan p = Gate.plan(Gate.parse("{\"advise\":{\"pow\":{\"bits\":19}}}"));
        Check.ok(p.bits() == -1 && p.notes().size() == 1 && p.stop() == null, "advised 19 bits are passed over with a note");
        p = Gate.plan(Gate.parse("{\"require\":{\"pow\":{\"bits\":20,\"covers\":1},\"per_key\":3,\"write_until\":1800000000}}"));
        Check.ok(p.bits() == 20 && p.stop() == null, "required 20 bits are done; per_key and write_until are known");
        Check.ok(Gate.plan(Gate.parse("{\"require\":{\"pow\":{\"bits\":21}}}")).stop().contains("21"), "required 21 bits stop the send");
        Check.ok(Gate.plan(Gate.parse("{\"require\":{\"captcha\":true}}")).stop().contains("captcha"), "an unknown requirement stops the send and names it");
        p = Gate.plan(Gate.parse("{\"advise\":{\"captcha\":true,\"pow\":{\"bits\":8}}}"));
        Check.ok(p.stop() == null && p.bits() == 8 && p.notes().size() == 1, "an unknown advice is passed over, the known one is done");

        Check.section("client, against a fake service");
        List<String> log = new ArrayList<>();
        Map<String, Map<String, Object>> gates = new HashMap<>();
        Http.override = (method, url, reqBody, headers) -> {
            String path = url.substring(url.indexOf('/', 8));
            log.add(method + " " + path + " " + headers.keySet());
            if (method.equals("PUT")) {
                return new Http.Answer(201, Json.object("{\"w\":\"" + path.substring(1) + "\",\"expire_at\":1,\"count\":0}"), Map.of());
            }
            if (path.endsWith("/gate")) {
                Map<String, Object> gt = gates.get(path.substring(1, 21));
                return new Http.Answer(200, gt == null ? new LinkedHashMap<>() : gt, Map.of());
            }
            if (method.equals("POST")) {
                String at = path.substring(1);
                Map<String, Object> gt = gates.get(at);
                int need = gt != null && gt.get("require") instanceof Map<?, ?> r && r.get("pow") instanceof Map<?, ?> pw && pw.get("bits") instanceof Number n ? n.intValue() : 0;
                String key = headers.getOrDefault("X-Key", "");
                String work = headers.get("X-Work");
                if (need > 0 && (work == null || Gate.zeroBits(Gate.powDigest(at, key, Codec.sha256Hex(reqBody), work)) < need)) {
                    Map<String, Object> refusal = new LinkedHashMap<>();
                    refusal.put("error", "This address asks for work");
                    refusal.put("fix", "Send X-Work");
                    refusal.put("gate", gt);
                    return new Http.Answer(428, refusal, Map.of());
                }
                if (headers.containsKey("X-Key") && !Keys.verify(key, headers.get("X-Sig"), Keys.threadSigningInput(at, reqBody))) {
                    return new Http.Answer(403, Json.object("{\"error\":\"bad signature\",\"fix\":\"sign it\"}"), Map.of());
                }
                Map<String, Object> ok = new LinkedHashMap<>();
                ok.put("seq", 1L);
                ok.put("verified", headers.containsKey("X-Key"));
                ok.put("sealed", Keys.isEnvelope(Codec.utf8(reqBody)));
                return new Http.Answer(201, ok, Map.of());
            }
            return new Http.Answer(404, Json.object("{\"error\":\"no\",\"fix\":\"no\"}"), Map.of());
        };
        Client client = new Client("https://fake.test", ka);
        Client.Opened opened = client.open(120, List.of("*"), Map.of("require", Map.of("pow", Map.of("bits", 4))));
        Check.ok(opened.status() == 201 && Address.w(opened.id()).equals(opened.w()) && log.get(0).contains("X-Read") && log.get(0).contains("X-TTL") && log.get(0).contains("X-Allow"), "open sends the read key, the ttl and the allowlist as headers");
        gates.put(opened.w(), Map.of("require", Map.of("pow", Map.of("bits", 4L))));
        Client.Sent s1 = client.send(opened.w(), "with work");
        Check.ok(s1.status() == 201 && s1.work() != null && Boolean.TRUE.equals(s1.answer().field("verified")) && !s1.stopped(), "a required gate is read first and the work goes with the first attempt, signed");
        String w2 = Address.w(Address.newId());
        client.gate(w2, true);
        gates.put(w2, Map.of("require", Map.of("pow", Map.of("bits", 5L))));
        Client.Sent s2 = client.send(w2, "late gate");
        Check.ok(s2.status() == 201 && s2.work() != null, "a 428 carrying the gate is answered once with the work");
        String w3 = Address.w(Address.newId());
        gates.put(w3, Map.of("require", Map.of("captcha", true)));
        Client.Sent s3 = client.send(w3, "never");
        Check.ok(s3.stopped() && s3.status() == 0 && s3.answer().error().contains("captcha") && log.stream().noneMatch(l -> l.startsWith("POST /" + w3)), "an unknown requirement stops the send before anything is sent");
        Client.Sent s4 = client.send(opened.w(), Codec.utf8("{\"tender\":\"ARC-4471\"}"), Client.SendOptions.sealedTo(kb.publicKey()));
        Check.ok(s4.status() == 201 && Keys.isEnvelope(Codec.utf8(s4.bytes())) && Boolean.TRUE.equals(s4.answer().field("sealed")), "a sealed send puts the envelope on the wire");
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("seq", 1L);
        raw.put("at", 2L);
        raw.put("from", ka.publicKey());
        raw.put("verified", true);
        raw.put("sealed", true);
        raw.put("body", Codec.utf8(s4.bytes()));
        Client.Message m = new Client(null, kb).decode(raw);
        Check.ok(m.format().equals("sealed") && m.json() != null && "ARC-4471".equals(m.json().get("tender")) && ka.publicKey().equals(m.from()), "the recipient decodes it: format sealed, JSON parsed");
        Client.Message notMine = new Client(null, Keys.generate()).decode(raw);
        Check.ok(notMine.format().equals("unreadable") && notMine.error().contains("sealed to"), "somebody else finds it unreadable, and learns whom it was sealed to");
        Check.ok(new Client(null, null).decode(raw).format().equals("sealed-to-someone-else"), "a client without keys leaves it sealed");
        Http.override = null;

        System.exit(Check.done());
    }
}
