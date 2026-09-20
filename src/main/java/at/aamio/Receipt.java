package at.aamio;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * What GET /{w}/receipt answers: hashes, times, keys and one root, no
 * content. A client checks it on its own: whether the lines hash to the root
 * it claims, whether the commitment is that root in the sha256: form, and,
 * given the hashes this process saw, whether they agree.
 */
public final class Receipt {
    private Receipt() {
    }

    /** What a client can say about a receipt. localHashesMatch is null when the receipt counts more messages than the client holds, which is a receipt taken later, not a failure. */
    public record Check(boolean rootAddsUp, boolean commitmentMatches, Boolean localHashesMatch) {
    }

    /** The root recomputed: sha256 of the lines "seq<TAB>at<TAB>sha256<TAB>from-or-dash<LF>" in seq order. */
    public static String root(List<?> messages) {
        StringBuilder lines = new StringBuilder();
        for (Map<?, ?> m : sorted(messages)) {
            Object from = m.get("from");
            String signer = from instanceof String s && !s.isEmpty() ? s : "-";
            lines.append(number(m.get("seq"))).append('\t').append(number(m.get("at"))).append('\t').append(m.get("sha256")).append('\t').append(signer).append('\n');
        }
        return Codec.sha256Hex(lines.toString());
    }

    /**
     * Recomputes and compares. localHashes may be null.
     *
     * Entries used to be counted before they were filtered, so three of which one was
     * not an object counted as three, matched a local list of three, and then the
     * comparison ran over the two that survived. With every entry invalid the loop
     * never ran and the answer was true, from no comparisons at all.
     *
     * A receipt this client cannot read whole is one it can say nothing true about, so
     * every answer below is false for it rather than a claim made over what was left.
     */
    public static Check verify(Map<String, Object> receipt, List<String> localHashes) {
        List<?> messages = receipt.get("messages") instanceof List<?> l ? l : List.of();
        List<Map<?, ?>> readable = sorted(messages);

        if (readable.size() != messages.size()) {
            return new Check(false, false, localHashes == null ? null : Boolean.FALSE);
        }

        String claimed = String.valueOf(receipt.get("root"));
        boolean rootAddsUp = MessageDigest.isEqual(Codec.utf8(root(messages)), Codec.utf8(claimed));
        boolean commitmentMatches = ("sha256:" + claimed).equals(receipt.get("commitment"));
        Boolean local = null;
        if (localHashes != null && readable.size() < localHashes.size()) {
            local = false;
        } else if (localHashes != null && readable.size() == localHashes.size()) {
            boolean match = true;
            int i = 0;
            for (Map<?, ?> m : readable) {
                if (!localHashes.get(i++).equals(m.get("sha256"))) {
                    match = false;
                    break;
                }
            }
            local = match;
        }
        return new Check(rootAddsUp, commitmentMatches, local);
    }

    private static List<Map<?, ?>> sorted(List<?> messages) {
        List<Map<?, ?>> out = new ArrayList<>();
        for (Object item : messages) {
            if (item instanceof Map<?, ?> m) {
                out.add(m);
            }
        }
        out.sort(Comparator.comparingLong(m -> number(m.get("seq"))));
        return out;
    }

    private static long number(Object v) {
        return v instanceof Number n ? n.longValue() : 0L;
    }
}
