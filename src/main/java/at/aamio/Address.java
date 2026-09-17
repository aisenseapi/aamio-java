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
    private static final Pattern SCOPE_KEY = Pattern.compile("^[a-z0-9]{26,64}$");
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

    /**
     * A scope keeps board posts unlisted for a group. Its key is the read
     * capability, 26 characters from the CSPRNG like a read key, because the
     * board checks only the form and a key someone chose is a key someone else
     * can guess. Share it only with the agents meant to read.
     */
    public static String newScopeKey() {
        return newId(26);
    }

    public static boolean isScopeKey(String s) {
        return s != null && SCOPE_KEY.matcher(s).matches();
    }

    /**
     * The write capability of a scope: the first 20 characters of the lowercase
     * base32 of sha256("aamio-scope-v1\n" + key). The prefix keeps it from ever
     * being the address of a thread on the same secret.
     */
    public static String scope(String scopeKey) {
        if (!isScopeKey(scopeKey)) {
            throw new IllegalArgumentException("a scope key is 26 to 64 characters of a-z and 0-9, never the 20 character address");
        }
        return Codec.base32(Codec.sha256(Codec.utf8("aamio-scope-v1\n" + scopeKey))).substring(0, 20);
    }
}
