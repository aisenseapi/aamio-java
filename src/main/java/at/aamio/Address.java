package at.aamio;

import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * A thread's two names: the read key (id), made here and shown to nobody
 * but the service in the X-Read header, and the write address (w) derived
 * from it, given to whoever should write.
 */
public final class Address {
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
    private static final Pattern ID = Pattern.compile("^[a-z0-9]{20,64}$");
    private static final Pattern W = Pattern.compile("^[a-z2-7]{20}$");
    private static final SecureRandom RANDOM = new SecureRandom();

    private Address() {
    }

    /** A read key: 26 characters of [a-z0-9] from the CSPRNG. */
    public static String newId() {
        return newId(26);
    }

    /** A read key of the given length, 20 to 64. */
    public static String newId(int length) {
        if (length < 20 || length > 64) {
            throw new IllegalArgumentException("an id is 20 to 64 characters");
        }
        StringBuilder out = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            out.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return out.toString();
    }

    public static boolean isId(String s) {
        return s != null && ID.matcher(s).matches();
    }

    public static boolean isW(String s) {
        return s != null && W.matcher(s).matches();
    }

    /** The write address for a read key: the first 20 characters of the lowercase base32 of sha256(id). */
    public static String w(String id) {
        if (!isId(id)) {
            throw new IllegalArgumentException("an id is 20 to 64 characters of a-z and 0-9");
        }
        return Codec.base32(Codec.sha256(Codec.utf8(id))).substring(0, 20);
    }
}
