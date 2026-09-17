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

    /** An opened thread: keep id, share w. */
    public record Opened(String id, String w, Answer answer) {
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
        String id = Address.newId();
        String w = Address.w(id);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Read", id);
        headers.put("X-TTL", Integer.toString(ttl));
        headers.put("Content-Type", "application/json");
        if (allow != null) {
            headers.put("X-Allow", String.join(",", allow));
        }
        byte[] body = gate == null ? null : Codec.utf8(Json.write(Map.of("gate", gate)));
        return new Opened(id, w, call("PUT", host + "/" + w, body, headers));
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
        }
        gates.put(w, gate);
        return gate;
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
        Gate.Plan plan = Gate.plan(gate(w, false));
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
                work = Gate.solve(w, key, payload, bits);
                headers.put("X-Work", work);
            }
            return new Attempt(call("POST", host + "/" + w, payload, headers), work);
        };
        Attempt done = attempt.apply(plan.bits());
        if (done.answer().status() == 428 && done.answer().field("gate") instanceof Map<?, ?> again) {
            // The refusal carries the whole gate; meet it once, never more.
            Map<String, Object> gate = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : again.entrySet()) {
                gate.put(String.valueOf(e.getKey()), e.getValue());
            }
            gates.put(w, gate);
            Gate.Plan second = Gate.plan(gate);
            if (second.stop() == null && second.bits() > 0) {
                done = attempt.apply(second.bits());
                notes.addAll(second.notes());
            }
        }
        return new Sent(done.answer(), payload, done.work(), notes, false);
    }

    /**
     * One message as read, with the service's own fields around the body and,
     * when this client could open it, the plaintext. format is text, sealed,
     * unreadable or sealed-to-someone-else; json is the body (or the opened
     * plaintext) as an object when it parses as one.
     */
    public record Message(long seq, long at, String from, boolean verified, boolean sealed, String body, String opened, String format, String error, Map<String, Object> json) {
        /** The opened plaintext when sealed, else the body. */
        public String text() {
            return opened != null ? opened : body;
        }
    }

    /** What a read answered, decoded. */
    public record Read(Answer answer, List<Message> messages, long next) {
    }

    /** Reads with the read key from after, waiting up to wait seconds (25 at most). */
    public Read read(String w, String id, int after, int wait) {
        String path = "/" + w;
        if (after > 0 || wait > 0) {
            path += "/after/" + after;
        }
        if (wait > 0) {
            path += "/wait/" + Math.min(wait, 25);
        }
        Answer a = Http.call("GET", host + path, null, Map.of("X-Read", id), timeout + 25);
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
                    if (item instanceof Map<?, ?> raw) {
                        messages.add(decode(raw));
                    }
                }
            }
        }
        return new Read(a, messages, next);
    }

    /** One raw message to a Message, opening it when it is sealed to us. verified, sealed and from are the service's fields, never the payload's. */
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
