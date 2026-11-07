package at.aamio;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * The vectors every client that takes the format up shares, the same file
 * aamio-python keeps. Nothing here touches the network.
 *
 *   java -cp build/classes:build/test-classes at.aamio.DomainKeysVectors testdata/domain_keys_vectors.json
 */
public final class DomainKeysVectors {
    private DomainKeysVectors() {
    }

    private static List<DomainKeys.Entry> entries(Map<String, Object> row) {
        List<DomainKeys.Entry> found = new ArrayList<>();
        for (Object each : (List<?>) row.get("entries")) {
            Map<?, ?> entry = (Map<?, ?>) each;
            found.add(new DomainKeys.Entry((String) entry.get("key"), (String) entry.get("name")));
        }
        return found;
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Path file = Path.of(args.length > 0 ? args[0] : "testdata/domain_keys_vectors.json");
        byte[] here = Files.readAllBytes(file);
        Map<String, Object> v = Json.object(new String(here, StandardCharsets.UTF_8));

        Check.section("domain keys");
        Path there = Path.of("..", "aamio-python", "tests", "domain_keys_vectors.json");
        if (Files.exists(there)) {
            Check.ok(Arrays.equals(Files.readAllBytes(there), here), "the vectors are the ones aamio-python keeps");
        }

        for (Object each : (List<Object>) v.get("documents")) {
            Map<String, Object> row = (Map<String, Object>) each;
            byte[] raw = row.containsKey("text") ? ((String) row.get("text")).getBytes(StandardCharsets.UTF_8) : Base64.getDecoder().decode((String) row.get("b64"));
            boolean valid = (Boolean) row.get("valid");
            boolean right;
            try {
                int count = DomainKeys.parse(raw).size();
                right = valid && count == ((Number) row.get("keys")).intValue();
            } catch (DomainKeys.Invalid e) {
                right = !valid;
            }
            Check.ok(right, "document: " + row.get("case"));
        }
        for (Object each : (List<Object>) v.get("matches")) {
            Map<String, Object> row = (Map<String, Object>) each;
            DomainKeys.Match found = DomainKeys.match(((String) row.get("text")).getBytes(StandardCharsets.UTF_8), (String) row.get("key"), (String) row.get("name"));
            boolean right = found.status().equals(row.get("status"))
                && (!row.containsKey("reason") || found.reason().equals(row.get("reason")))
                && (!row.containsKey("matched_name") || java.util.Objects.equals(found.matchedName(), row.get("matched_name")))
                && java.util.Objects.equals(found.documentSha256(), row.get("document_sha256"))
                && found.subjectSource().equals("supplied_key");
            Check.ok(right, "match: " + row.get("case"));
        }
        Map<String, Object> domains = (Map<String, Object>) v.get("domains");
        for (Object each : (List<Object>) domains.get("valid")) {
            List<String> pair = (List<String>) each;
            Check.ok(pair.get(1).equals(DomainKeys.normaliseDomain(pair.get(0))), "domain: " + pair.get(0));
        }
        for (Object each : (List<Object>) domains.get("invalid")) {
            Check.ok(DomainKeys.normaliseDomain((String) each) == null, "not a domain: " + Json.write(each));
        }
        Check.ok(DomainKeys.normaliseDomain(null) == null, "null is no domain");
        Check.ok("https://example.org/.well-known/aamio-keys.json".equals(DomainKeys.url("Example.ORG")) && DomainKeys.url("https://example.org") == null, "the address is built from a host alone");
        for (Object each : (List<Object>) v.get("generated")) {
            Map<String, Object> row = (Map<String, Object>) each;
            Check.ok(((String) row.get("text")).equals(new String(DomainKeys.make(entries(row)), StandardCharsets.UTF_8)), "generated: " + row.get("case"));
        }
        for (Object each : (List<Object>) v.get("refused")) {
            Map<String, Object> row = (Map<String, Object>) each;
            boolean refused = false;
            try {
                DomainKeys.make(entries(row));
            } catch (DomainKeys.Invalid e) {
                refused = true;
            }
            Check.ok(refused, "refused: " + row.get("case"));
        }
        DomainKeys.Match invalid = DomainKeys.match("{\"aamio_keys\":2,\"keys\":[],\"x\":\"secret text\"}".getBytes(StandardCharsets.UTF_8), "29VTeOqp8srcy1SyPZ3NtHy9XBnLf4h7D2LDrCzo7S4", null);
        Check.ok("invalid_document".equals(invalid.reason()) && "unsupported_version".equals(invalid.detail()), "an invalid document says why without its content");
        System.exit(Check.done());
    }
}
