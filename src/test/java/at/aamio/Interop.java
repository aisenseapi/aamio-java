package at.aamio;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The Java side of tests/interop.py: reads one JSON object on stdin, opens
 * what Python sealed, verifies what Python signed, seals and signs for
 * Python, and prints one JSON object. Nothing touches the network.
 */
public final class Interop {
    private Interop() {
    }

    public static void main(String[] args) throws IOException {
        Map<String, Object> in = Json.object(Codec.utf8(System.in.readAllBytes()));
        Keys keys = Keys.fromSeedHex((String) in.get("java_seed"));
        String py = (String) in.get("py_public");
        String input = (String) in.get("signing_input");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("java_public", keys.publicKey());
        out.put("opened", Codec.utf8(keys.open(py, (String) in.get("envelope_from_py"))));
        out.put("py_signature_verifies", Keys.verify(py, (String) in.get("py_signature"), input));
        out.put("envelope_from_java", keys.seal(py, (String) in.get("plaintext_for_py")));
        out.put("java_signature", keys.sign(input));
        System.out.write(Codec.utf8(Json.write(out) + "\n"));
        System.out.flush();
    }
}
