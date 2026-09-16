package at.aamio;

import java.util.List;
import java.util.Map;

/**
 * One thread end to end against a running aamio, then a gate with work,
 * presence, and the board's read side. Nothing secret is left behind: every
 * thread is closed and would expire in two minutes anyway. The board is only
 * read. AAMIO_HOST overrides https://aamio.at.
 *
 *   java -cp build/classes:build/test-classes at.aamio.Live
 */
public final class Live {
    private Live() {
    }

    public static void main(String[] args) {
        String host = System.getenv("AAMIO_HOST");
        Keys me = Keys.generate();
        Keys partner = Keys.generate();
        Client client = new Client(host, me);
        Client other = new Client(host, partner);

        Check.section("a thread, start to finish");
        Client.Opened thread = client.open(120, List.of(me.publicKey(), partner.publicKey()));
        Check.ok(thread.status() == 201, "open: " + thread.answer());
        Client.Sent sent = client.send(thread.w(), "hello from java");
        Check.ok(sent.status() == 201 && Boolean.TRUE.equals(sent.answer().field("verified")), "signed text write: " + sent.answer());
        Client.Sent sealed = other.send(thread.w(), Codec.utf8("{\"tender\":\"ARC-4471\"}"), Client.SendOptions.sealedTo(me.publicKey()));
        Check.ok(sealed.status() == 201 && Boolean.TRUE.equals(sealed.answer().field("sealed")) && Boolean.TRUE.equals(sealed.answer().field("verified")), "sealed write: " + sealed.answer());
        Client.Sent refused = new Client(host, Keys.generate()).send(thread.w(), "x");
        Check.ok(refused.status() == 403 && refused.answer().field("fix") != null, "a key outside the allowlist is refused with a fix: " + refused.answer());
        Client.Read read = client.read(thread.w(), thread.id(), 0, 0);
        Check.ok(read.answer().status() == 200 && read.messages().size() == 2 && read.next() == 2, "read: " + read.answer().status() + ", " + read.messages().size() + " messages");
        if (read.messages().size() == 2) {
            Client.Message first = read.messages().get(0);
            Client.Message second = read.messages().get(1);
            Check.ok(first.format().equals("text") && first.body().equals("hello from java") && first.verified(), "the text message, verified");
            Check.ok(second.format().equals("sealed") && second.json() != null && "ARC-4471".equals(second.json().get("tender")) && partner.publicKey().equals(second.from()), "the sealed message opens");
        }
        long started = System.nanoTime();
        Client.Read empty = client.read(thread.w(), thread.id(), 2, 3);
        long waited = (System.nanoTime() - started) / 1_000_000;
        Check.ok(empty.answer().status() == 200 && empty.messages().isEmpty() && waited >= 2500, "a long poll on nothing waits: " + waited + " ms");
        Client.Receipted r = client.receipt(thread.w(), thread.id());
        Check.ok(r.answer().status() == 200 && r.check() != null && r.check().rootAddsUp() && r.check().commitmentMatches() && Long.valueOf(2).equals(r.receipt().get("count")), "receipt: root adds up, commitment matches, two messages");
        Check.ok(client.close(thread.w(), thread.id()).status() == 200, "close");

        Check.section("gate");
        Client.Opened gated = client.open(120, List.of("*"), Map.of("advise", Map.of("pow", Map.of("bits", 8))));
        Check.ok(gated.status() == 201, "an inbox opens with a gate: " + gated.answer().status());
        Map<String, Object> gate = client.gate(gated.w(), true);
        Check.ok(gate != null && Gate.hash(gate).equals(Gate.hash(Gate.parse("{\"advise\":{\"pow\":{\"bits\":8,\"covers\":1}}}"))), "the gate reads back, canonical: " + gate);
        Client.Sent worked = client.send(gated.w(), "with work");
        Object met = worked.answer().field("met");
        Check.ok(worked.status() == 201 && worked.work() != null && met instanceof Map<?, ?> mm && Long.valueOf(8).equals(mm.get("pow")), "the advised work is done and met: " + worked.answer());
        Client.Opened required = client.open(120, List.of("*"), Map.of("require", Map.of("pow", Map.of("bits", 10))));
        Client.Sent req = client.send(required.w(), "required");
        Check.ok(req.status() == 201, "required work is done before the first attempt: " + req.answer().status());
        client.close(gated.w(), gated.id());
        client.close(required.w(), required.id());

        Check.section("presence");
        Client.Opened inbox = client.open(120);
        Check.ok(client.presencePublish(inbox.w(), List.of("java.test"), 30).status() == 200, "publish");
        Check.ok(client.presenceGet(me.publicKey()).status() == 200, "get");
        Http.Answer lookup = client.presenceLookup(List.of(me.hashPrefix()), 0);
        Check.ok(lookup.status() == 200 && Long.valueOf(1).equals(lookup.field("count")), "lookup by hash prefix: " + lookup);
        Check.ok(client.presenceDelete().status() == 200, "delete");
        client.close(inbox.w(), inbox.id());

        Check.section("the board, read side");
        Board board = new Board(client);
        Check.ok(board.advisedBits() > 0, "the descriptor says what work it advises: " + board.advisedBits());
        Board.Found found = board.find(new Board.Find());
        Check.ok(found.answer().status() == 200, "find: " + found.answer().status() + ", " + found.posts().size() + " posts");
        Check.ok(board.tags().status() == 200, "tags");
        Client.Opened reply = board.replyInbox(120);
        Check.ok(reply.status() == 201, "a reply inbox opens with X-Allow: *");
        client.close(reply.w(), reply.id());

        System.exit(Check.done());
    }
}
