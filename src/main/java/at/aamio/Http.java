package at.aamio;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One HTTP call, one answer. The body is decoded when the answer is JSON
 * and left as text otherwise. No answer at all is status 0 with the reason
 * in the body: the request may have landed, which is unknown, and a caller
 * must never confuse it with a refusal.
 */
public final class Http {
    public static final String USER_AGENT = "aamio-java/" + Codec.VERSION;

    /** What the service said: the status, the decoded body (a Map for objects, a String for text), and the headers, lowercased. */
    public record Answer(int status, Object body, Map<String, String> headers) {
        /** The body when it is a JSON object, else null. */
        @SuppressWarnings("unchecked")
        public Map<String, Object> map() {
            return body instanceof Map ? (Map<String, Object>) body : null;
        }

        /** One field of the body when it is an object, else null. */
        public Object field(String name) {
            Map<String, Object> m = map();
            return m == null ? null : m.get(name);
        }

        public String text() {
            if (body instanceof String s) {
                return s;
            }
            return body == null ? "" : Json.write(body);
        }

        /** The refusal contract: every 4xx and 5xx carries error and fix. */
        public String error() {
            Map<String, Object> m = map();
            if (m == null) {
                return text();
            }
            return (String.valueOf(m.getOrDefault("error", "")) + ". " + String.valueOf(m.getOrDefault("fix", ""))).trim();
        }

        /** Whether the outcome is unknown rather than a refusal. */
        public boolean unknown() {
            return status == 0;
        }

        @Override
        public String toString() {
            return status + " " + text();
        }
    }

    /** A stand-in for the network, for tests: everything Http.call would do. */
    @FunctionalInterface
    public interface Transport {
        Answer call(String method, String url, byte[] body, Map<String, String> headers);
    }

    /** When set, every call goes here instead of the network. Null in production. */
    public static volatile Transport override;

    private static final HttpClient CLIENT = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).followRedirects(HttpClient.Redirect.NEVER).build();

    private Http() {
    }

    public static Answer call(String method, String url, byte[] body, Map<String, String> headers) {
        return call(method, url, body, headers, 40);
    }

    public static Answer call(String method, String url, byte[] body, Map<String, String> headers, int timeoutSeconds) {
        Transport stub = override;
        if (stub != null) {
            return stub.call(method, url, body, headers == null ? Map.of() : headers);
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(timeoutSeconds)).header("Accept", "application/json").header("User-Agent", USER_AGENT);
        if (headers != null) {
            for (Map.Entry<String, String> h : headers.entrySet()) {
                if (h.getValue() != null && !h.getValue().isEmpty()) {
                    request.header(h.getKey(), h.getValue());
                }
            }
        }
        request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        try {
            HttpResponse<byte[]> response = CLIENT.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            String text = Codec.utf8(response.body());
            Object decoded;
            try {
                decoded = Json.parse(text);
            } catch (RuntimeException e) {
                decoded = text;
            }
            Map<String, String> got = new LinkedHashMap<>();
            response.headers().map().forEach((name, values) -> got.put(name.toLowerCase(), String.join(", ", values)));
            return new Answer(response.statusCode(), decoded, got);
        } catch (IOException e) {
            return noAnswer(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return noAnswer(e);
        }
    }

    private static Answer noAnswer(Exception e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "no answer: " + e);
        body.put("fix", "The request may have landed. Keep the bytes, mark the send unknown, and retry only when somebody has decided it is safe to.");
        return new Answer(0, body, Map.of());
    }
}
