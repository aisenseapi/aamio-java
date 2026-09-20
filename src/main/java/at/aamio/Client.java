package at.aamio;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import at.aamio.Http.Answer;

/**
 * One aamio host, optionally with keys. Every call returns what the service
 * answered with the status beside it; every refusal carries error and fix.
 * Status 0 means no answer at all: the message may have landed, so it is
 * unknown, never refused.
 */
public final class Client {
    public static final String DEFAULT_HOST = Hosts.DEFAULT_HOST;
    public static final int DEFAULT_TTL = 600;
    public static final int MAX_BODY = 65536;

    private final String host;
    private final Keys keys;
    private final Map<String, Map<String, Object>> gates = Collections.synchronizedMap(new HashMap<>());
    /** X-Seconds-Left per address, and the System.nanoTime it was read at. */
    private final Map<String, double[]> gateLeft = Collections.synchronizedMap(new HashMap<>());
    private final int timeout;

    public Client(String host, Keys keys) {
        this(host, keys, 40);
    }

    public Client(String host, Keys keys, int timeoutSeconds) {
        String h = host == null || host.isEmpty() ? DEFAULT_HOST : host;
        while (h.endsWith("/")) {
            h = h.substring(0, h.length() - 1);
        }
        this.host = h;
        this.keys = keys;
        this.timeout = timeoutSeconds;
    }

    public String host() {
        return host;
    }

    public Keys keys() {
        return keys;
    }

    /** One HTTP request to this host's URL space, or anywhere: what Http.call does. */
    public Answer call(String method, String url, byte[] body, Map<String, String> headers) {
        return Http.call(method, url, body, headers, timeout);
    }

    // ------------------------------------------------------------- threads --

    /**
     * An opened thread: keep id, share w. allow is the allowlist it was opened
     * with, kept here because the service holds it in memory only: see
     * readThread. It is empty for a thread opened without one.
     */
    public record Opened(String id, String w, List<String> allow, Answer answer) {
        public Opened {
            allow = normalizeAllow(allow);
        }

        /** A thread with no allowlist of its own. */
        public Opened(String id, String w, Answer answer) {
            this(id, w, List.of(), answer);
        }

        public int status() {
            return answer.status();
        }
    }

    public Opened open(int ttl) {
        return open(ttl, null, null);
    }

    public Opened open(int ttl, List<String> allow) {
        return open(ttl, allow, null);
    }

    /** Opens a thread with a lifetime. allow lists signer keys, or ["*"] for any key as long as the message is signed; gate sets conditions, or null. */
    public Opened open(int ttl, List<String> allow, Map<String, Object> gate) {
        allow = normalizeAllow(allow);
        String id = Address.newId();
        String w = Address.w(id);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Read", id);
        headers.put("X-TTL", Integer.toString(ttl));
        headers.put("Content-Type", "application/json");
        if (!allow.isEmpty()) {
            headers.put("X-Allow", String.join(",", allow));
        }
        byte[] body = gate == null ? null : Codec.utf8(Json.write(Map.of("gate", gate)));
        return new Opened(id, w, allow, call("PUT", host + "/" + w, body, headers));
    }

    private static List<String> normalizeAllow(List<String> allow) {
        List<String> out = new ArrayList<>();
        for (String entry : allow == null ? List.<String>of() : allow) {
            if (entry == null) throw new IllegalArgumentException("an allowlist entry must be a string");
            for (String part : entry.split(",")) {
                String key = part.trim();
                if (!key.isEmpty() && !out.contains(key)) out.add(key);
            }
        }
        return out.contains("*") ? List.of("*") : List.copyOf(out);
    }

    /** The conditions an inbox was opened with, read once per address unless fresh: an empty map for none, null when the thread is gone. */
    public Map<String, Object> gate(String w, boolean fresh) {
        synchronized (gates) {
            if (!fresh && gates.containsKey(w)) {
                return gates.get(w);
            }
        }
        Answer a = call("GET", host + "/" + w + "/gate", null, null);
        Map<String, Object> gate = null;
        if (a.status() == 200) {
            gate = a.map() != null ? a.map() : new LinkedHashMap<>();
            // The time left rides in a header, since the body is the exact bytes
            // the gate hash is taken over.
            String left = a.headers() == null ? null : a.headers().get("x-seconds-left");
            if (left != null && left.matches("\\d+")) {
                gateLeft.put(w, new double[] {Double.parseDouble(left), System.nanoTime()});
            }
        }
        gates.put(w, gate);
        return gate;
    }

    /** Drops the gate kept for w and the time it said: they belong to an inbox that may not be there now. */
    public void forgetGate(String w) {
        gates.remove(w);
        gateLeft.remove(w);
    }

    /**
     * The plan for w's gate, read again once before a no that rests on a gate
     * read earlier. A gate never changes while its thread lives, which is why
     * it is kept, but an address can have more than one life: the time a kept
     * gate said counted down to nothing and stayed there, and a new inbox at
     * the same address was refused on the old one's terms without the service
     * being asked.
     */
    public Gate.Plan planTo(String w) {
        boolean cached = gates.containsKey(w);
        Gate.Plan plan = Gate.plan(gate(w, false), secondsLeft(w));
        if (plan.stop() != null && cached) {
            forgetGate(w);
            plan = Gate.plan(gate(w, false), secondsLeft(w));
        }
        return plan;
    }

    /** How long w still takes writes, counted down from what its gate said; -1 when it did not say. */
    public double secondsLeft(String w) {
        double[] said = gateLeft.get(w);
        if (said == null) {
            return -1;
        }
        return Math.max(0, said[0] - (System.nanoTime() - said[1]) / 1e9);
    }

    /** How a write is shaped: unsigned, sealed to a key, or marked as JSON. */
    public record SendOptions(boolean unsigned, String sealTo, boolean json) {
        public static final SendOptions TEXT = new SendOptions(false, null, false);
        public static final SendOptions JSON = new SendOptions(false, null, true);

        public static SendOptions sealedTo(String key) {
            return new SendOptions(false, key, true);
        }

        /** The same options, but the write goes without X-Key and X-Sig. */
        public SendOptions withoutSignature() {
            return new SendOptions(true, sealTo, json);
        }
    }

    /** The outcome of a write: the answer, the exact bytes sent, the nonce when work was done, notes, and stopped when the gate stopped it before anything was sent. */
    public record Sent(Answer answer, byte[] bytes, String work, List<String> notes, boolean stopped) {
        public int status() {
            return answer.status();
        }
    }

    public Sent send(String w, String text) {
        return send(w, Codec.utf8(text), SendOptions.TEXT);
    }

    public Sent send(String w, Map<String, Object> json) {
        return send(w, Codec.utf8(Json.write(json)), SendOptions.JSON);
    }

    /**
     * Writes bytes to an address. Reads the gate once, does the work it asks
     * for within the ceilings, answers a 428 once, and stops with a reason
     * rather than send what the gate would refuse.
     */
    public Sent send(String w, byte[] body, SendOptions options) {
        if (!Address.isW(w)) {
            throw new IllegalArgumentException("not a write address");
        }
        SendOptions o = options == null ? SendOptions.TEXT : options;
        byte[] bytes = body;
        String contentType = o.json() ? "application/json" : "text/plain; charset=utf-8";
        if (o.sealTo() != null) {
            if (keys == null) {
                throw new IllegalStateException("sealing needs keys");
            }
            bytes = Codec.utf8(keys.seal(o.sealTo(), body));
            contentType = "application/json";
        }
        if (bytes.length > MAX_BODY) {
            throw new IllegalArgumentException("a message is at most 65536 bytes; send a URL and a hash instead");
        }
        boolean signing = !o.unsigned() && keys != null;
        String key = signing ? keys.publicKey() : "";
        Gate.Plan plan = planTo(w);
        List<String> notes = new ArrayList<>(plan.notes());
        if (plan.stop() != null) {
            Map<String, Object> refusal = new LinkedHashMap<>();
            refusal.put("error", plan.stop());
            refusal.put("fix", "Open an address whose conditions this client can meet, or update the client.");
            return new Sent(new Answer(0, refusal, Map.of()), null, null, notes, true);
        }
        final byte[] payload = bytes;
        final String type = contentType;
        record Attempt(Answer answer, String work) {
        }
        java.util.function.IntFunction<Attempt> attempt = bits -> {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", type);
            if (signing) {
                headers.put("X-Key", key);
                headers.put("X-Sig", keys.sign(Keys.threadSigningInput(w, payload)));
            }
            String work = null;
            if (bits > 0) {
                // The work stops when the inbox would close, less a few seconds
                // for the post itself: past that a nonce buys nothing but a 410.
                double left = secondsLeft(w);
                work = Gate.solveUntil(w, key, payload, bits, left < 0 ? null : java.time.Instant.now().plusMillis((long) (Math.max(0, left - 5) * 1000)));
                if (work == null) {
                    return new Attempt(null, null);
                }
                headers.put("X-Work", work);
            }
            return new Attempt(call("POST", host + "/" + w, payload, headers), work);
        };
        java.util.function.IntFunction<Sent> ranOut = bits -> {
            Map<String, Object> refusal = new LinkedHashMap<>();
            refusal.put("error", "the proof of work of " + bits + " bits was not done before the inbox stops taking writes, so the work was stopped and nothing was sent");
            refusal.put("fix", "The estimate before it started said it would fit, and this time it took longer, which happens: the work is a lottery. Ask the owner for a longer inbox, or send from a machine with more compute.");
            return new Sent(new Answer(0, refusal, Map.of()), null, null, notes, true);
        };
        Attempt done = attempt.apply(plan.bits());
        if (done.answer() == null) {
            return ranOut.apply(plan.bits());
        }
        if (done.answer().status() == 428 && done.answer().field("gate") instanceof Map<?, ?> again) {
            // The refusal carries the whole gate; meet it once, never more.
            Map<String, Object> gate = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : again.entrySet()) {
                gate.put(String.valueOf(e.getKey()), e.getValue());
            }
            gates.put(w, gate);
            if (done.answer().field("seconds_left") instanceof Number left) {
                gateLeft.put(w, new double[] {left.doubleValue(), System.nanoTime()});
            }
            Gate.Plan second = Gate.plan(gate, secondsLeft(w));
            if (second.stop() != null) {
                Map<String, Object> refusal = new LinkedHashMap<>();
                refusal.put("error", second.stop());
                refusal.put("fix", "Open an address whose conditions this client can meet, or update the client.");
                notes.addAll(second.notes());
                return new Sent(new Answer(0, refusal, Map.of()), null, null, notes, true);
            }
            if (second.bits() > 0) {
                done = attempt.apply(second.bits());
                if (done.answer() == null) {
                    return ranOut.apply(second.bits());
                }
                notes.addAll(second.notes());
            }
        }
        // An inbox that is not there, or has expired, takes its gate with it:
        // the next send here reads the gate of whatever is there then.
        if (done.answer().status() == 404 || done.answer().status() == 410) {
            forgetGate(w);
        }
        return new Sent(done.answer(), payload, done.work(), notes, false);
    }

    /**
     * One message as read, with the service's own fields around the body and,
     * when this client could open it, the plaintext. format is text, sealed,
     * unreadable or sealed-to-someone-else; json is the body (or the opened
     * plaintext) as an object when it parses as one.
     */
    public record Message(long seq, long at, String from, boolean verified, boolean sealed, String body, String opened, String format, String error, Map<String, Object> json, String unverifiedBecause) {
        /** A message with nothing said against it. */
        public Message(long seq, long at, String from, boolean verified, boolean sealed, String body, String opened, String format, String error, Map<String, Object> json) {
            this(seq, at, from, verified, sealed, body, opened, format, error, json, null);
        }

        /** The opened plaintext when sealed, else the body. */
        public String text() {
            return opened != null ? opened : body;
        }
    }

    /** A message the thread's own allowlist kept out of what readThread handed over. */
    public record KeptOut(long seq, String why, String unverifiedBecause) {
        public KeptOut(long seq, String why) {
            this(seq, why, null);
        }
    }

    /** What a read answered, decoded. keptOut is what readThread left out, and empty for a plain read. */
    public record Read(Answer answer, List<Message> messages, long next, List<KeptOut> keptOut) {
        public Read(Answer answer, List<Message> messages, long next) {
            this(answer, messages, next, List.of());
        }
    }

    /** What this client found when it checked a message: see checkMessage. */
    public record Checked(boolean verified, String whyNot, String sha256) {
    }

    /**
     * Checks one message as the service returned it: the body is hashed and
     * compared with the sha256 beside it, and the signature verified over the
     * address being read. verified in an answer is the service's word, and the
     * trust model says an operator cannot forge a signature, which only holds
     * for a reader that checks. whyNot is null for a message that verified and
     * for an ordinary unsigned one, and a sentence when something that should
     * have held did not.
     */
    public static Checked checkMessage(String w, Map<?, ?> raw) {
        if (!(raw.get("body") instanceof String body)) {
            return new Checked(false, "the message has no body to check", null);
        }
        String digest = Codec.sha256Hex(body);
        if (!digest.equals(raw.get("sha256"))) {
            return new Checked(false, "the body does not hash to the sha256 the service gave with it, so these are not the bytes that were stored", digest);
        }
        String from = raw.get("from") instanceof String s ? s : "";
        String signature = raw.get("sig") instanceof String s ? s : "";
        boolean claimed = Boolean.TRUE.equals(raw.get("verified"));
        if (from.isEmpty() || signature.isEmpty()) {
            return new Checked(false, claimed ? "the service calls it verified and gave no key or signature to check" : null, digest);
        }
        if (Keys.verify(from, signature, Keys.threadSigningInput(w, body))) {
            return new Checked(true, null, digest);
        }
        return new Checked(false, "the signature does not check out for this key, this address and these bytes" + (claimed ? ", though the service said it did" : ""), digest);
    }

    /**
     * read for a thread this client opened, with the allowlist it was opened
     * with applied to what is read. The service enforces the list while it
     * holds the thread, and it holds it in memory: a write to the address after
     * its store was emptied opens a thread with no list. With named keys, only
     * messages verified here from one of them are handed over; with "*", only
     * messages verified here from any key. The rest is listed under keptOut,
     * never dropped in silence. The cursor covers both.
     */
    public Read readThread(Opened thread, int after, int wait) {
        return readThread(thread, after, wait, null, null);
    }

    /**
     * readThread with the limits of the six-argument read. A smaller answer is not a
     * looser one: the allowlist is checked here exactly as before, and what it keeps
     * out is still listed rather than dropped in silence.
     */
    public Read readThread(Opened thread, int after, int wait, Integer limit, Integer maxBytes) {
        Read read = read(thread.w(), thread.id(), after, wait, limit, maxBytes);
        if (thread.allow().isEmpty()) {
            return read;
        }
        boolean anySigned = thread.allow().contains("*");
        List<Message> handed = new ArrayList<>();
        List<KeptOut> kept = new ArrayList<>();
        for (Message m : read.messages()) {
            if (m.verified() && m.from() != null && (anySigned || thread.allow().contains(m.from()))) {
                handed.add(m);
                continue;
            }
            kept.add(new KeptOut(m.seq(), anySigned
                ? "this thread was opened for signed messages only, and this one did not verify here"
                : "this thread was opened for named keys, and this one was not signed by one of them, as checked here", m.unverifiedBecause()));
        }
        return new Read(read.answer(), handed, read.next(), kept);
    }

    /**
     * Reads with the read key from after, waiting up to wait seconds (25 at most).
     *
     * Every message is checked here before it is handed over: the body is
     * hashed and compared with the sha256 beside it, and the signature is
     * verified over this address. verified and from on what comes back are this
     * client's result, not the service's word, and a message the service called
     * verified that does not check out says why in unverifiedBecause.
     */
    public Read read(String w, String id, int after, int wait) {
        return read(w, id, after, wait, null, null);
    }

    /**
     * read, asking the service for a small answer.
     *
     * limit is at most this many messages, maxBytes at most this many bytes of them;
     * null for either means do not ask, and asking for neither is exactly the read
     * above. A thread may hold two hundred messages of 65536 bytes, so one read can
     * be about a megabyte, and without these the whole of it crosses the network
     * before anything here looks at it.
     *
     * Whole messages only: a signed message cut in half does not verify. When
     * something was left behind the answer carries more, and next is the last message
     * handed over, so passing it back as after skips nothing. When one message alone
     * is over budget the answer carries too_large naming it and its size.
     *
     * A service that does not offer read-limits ignores both headers and answers as
     * it always did, so these are safe to send without asking what it supports.
     */
    public Read read(String w, String id, int after, int wait, Integer limit, Integer maxBytes) {
        String path = "/" + w;
        if (after > 0 || wait > 0) {
            path += "/after/" + after;
        }
        if (wait > 0) {
            path += "/wait/" + Math.min(wait, 25);
        }
        Map<String, String> headers = new LinkedHashMap<>(Map.of("X-Read", id));
        if (limit != null) {
            headers.put("X-Limit", String.valueOf(limit));
        }
        if (maxBytes != null) {
            headers.put("X-Max-Bytes", String.valueOf(maxBytes));
        }
        Answer a = Http.call("GET", host + path, null, headers, timeout + 25);
        List<Message> messages = new ArrayList<>();
        // The cursor the caller already has, so a refusal or a dead connection
        // leaves it where it was. Zero sent the documented loop back to the
        // first message and delivered the whole thread a second time.
        long next = after;
        if (a.status() == 200 && a.map() != null) {
            if (a.field("next") instanceof Number n) {
                next = n.longValue();
            }
            if (a.field("messages") instanceof List<?> list) {
                for (Object item : list) {
                    messages.add(decodeAt(w, item instanceof Map<?, ?> raw ? raw : Map.of()));
                }
            }
        }
        return new Read(a, messages, next);
    }

    /**
     * decode for a message read at w: the hash and the signature are checked
     * first, and everything decode does goes by that result. A message that
     * does not verify here has no from, so a sealed body under a forged sender
     * is not opened against the key it claimed.
     */
    public Message decodeAt(String w, Map<?, ?> raw) {
        try {
            return checkedDecode(w, raw);
        } catch (RuntimeException e) {
            long seq = raw != null && raw.get("seq") instanceof Long n ? n : 0;
            long at = raw != null && raw.get("at") instanceof Long n ? n : 0;
            String body = raw != null && raw.get("body") instanceof String s ? s : "";
            String why = "the message could not be checked here: " + e.getClass().getSimpleName();
            return new Message(seq, at, null, false, false, body, null, "unreadable", why, null, why);
        }
    }

    private Message checkedDecode(String w, Map<?, ?> raw) {
        Checked result = checkMessage(w, raw);
        Map<String, Object> checked = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            checked.put(String.valueOf(entry.getKey()), entry.getValue());
        }
        checked.put("verified", result.verified());
        if (!result.verified()) {
            checked.put("from", null);
        }
        if (result.sha256() != null) {
            checked.put("sha256", result.sha256());
        }
        Message m = decode(checked);
        return new Message(m.seq(), m.at(), m.from(), m.verified(), m.sealed(), m.body(), m.opened(), m.format(), m.error(), m.json(), result.whyNot());
    }

    /**
     * One raw message to a Message, opening it when it is sealed to us.
     * verified, sealed and from are never taken from the payload. decode takes
     * the service's fields as they are: UNSAFE for remote input and not a
     * verification API. Use decodeAt or read for remotely supplied messages.
     */
    public Message decode(Map<?, ?> raw) {
        long seq = raw.get("seq") instanceof Number n ? n.longValue() : 0;
        long at = raw.get("at") instanceof Number n ? n.longValue() : 0;
        String from = raw.get("from") instanceof String s ? s : null;
        boolean verified = Boolean.TRUE.equals(raw.get("verified"));
        boolean sealed = Boolean.TRUE.equals(raw.get("sealed"));
        String body = raw.get("body") instanceof String s ? s : "";
        String format = "text";
        String opened = null;
        String error = null;
        String text = body;
        if (sealed) {
            // The envelope names who it is sealed to, so read that rather than
            // guess. This said "sealed to someone else" whenever the client had
            // no keys or the message carried no sender, with no error beside
            // the claim, and envelopes sealed to the reader were dropped on it.
            String to = Keys.envelopeTo(body);
            String mine = keys != null ? keys.hashPrefix() : null;
            if (to != null && mine != null && !to.equals(mine)) {
                format = "sealed-to-someone-else";
                error = "this envelope is sealed to " + to + ", not to " + mine;
            } else if (keys == null || from == null || from.isEmpty()) {
                format = "sealed-unchecked";
            } else {
                try {
                    opened = Codec.utf8(keys.open(from, body));
                    format = "sealed";
                    text = opened;
                } catch (RuntimeException e) {
                    format = "unreadable";
                    error = e.getMessage();
                }
            }
            if (!"sealed".equals(format)) {
                // Nothing was opened, so there is no payload here. json used to
                // hold the envelope itself, and a caller reading "json is not
                // null" as "this was decoded" got the envelope instead.
                return new Message(seq, at, from, verified, sealed, body, opened, format, error, null);
            }
        }
        return new Message(seq, at, from, verified, sealed, body, opened, format, error, Json.object(text));
    }

    /** A receipt and this client's own check of it. receipt is null unless the status was 200. */
    public record Receipted(Answer answer, Map<String, Object> receipt, Receipt.Check check) {
    }

    public Receipted receipt(String w, String id) {
        Answer a = call("GET", host + "/" + w + "/receipt", null, Map.of("X-Read", id));
        if (a.status() != 200 || a.map() == null) {
            return new Receipted(a, null, null);
        }
        return new Receipted(a, a.map(), Receipt.verify(a.map(), null));
    }

    /** Closes a thread early. */
    public Answer close(String w, String id) {
        return call("DELETE", host + "/" + w, null, Map.of("X-Read", id));
    }

    // ------------------------------------------------------------ presence --

    /** Says where this key can be reached, for up to 120 seconds. */
    public Answer presencePublish(String w, List<String> tags, int ttl) {
        needKeys();
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("w", w);
        record.put("tags", tags == null ? List.of() : tags);
        record.put("ttl", ttl);
        byte[] body = Codec.utf8(Json.write(record));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("X-Key", keys.publicKey());
        headers.put("X-Sig", keys.sign(Keys.presenceSigningInput(keys.publicKey(), body)));
        return call("PUT", host + "/p/" + keys.publicKey(), body, headers);
    }

    /** One key's record. */
    public Answer presenceGet(String key) {
        return call("GET", host + "/p/" + key, null, null);
    }

    /** Live records by hash prefix; with wait it watches. */
    public Answer presenceLookup(List<String> prefixes, int wait) {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("prefixes", prefixes);
        String route = "/p/lookup";
        if (wait > 0) {
            route = "/p/watch";
            request.put("wait", Math.min(wait, 25));
        }
        return Http.call("POST", host + route, Codec.utf8(Json.write(request)), Map.of("Content-Type", "application/json"), timeout + 25);
    }

    /** Withdraws this key's record. */
    public Answer presenceDelete() {
        needKeys();
        byte[] body = Codec.utf8(Json.write(Map.of("at", System.currentTimeMillis() / 1000)));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("X-Key", keys.publicKey());
        headers.put("X-Sig", keys.sign(Keys.presenceDeleteSigningInput(keys.publicKey(), body)));
        return call("DELETE", host + "/p/" + keys.publicKey(), body, headers);
    }

    private void needKeys() {
        if (keys == null) {
            throw new IllegalStateException("this call needs keys");
        }
    }
}
