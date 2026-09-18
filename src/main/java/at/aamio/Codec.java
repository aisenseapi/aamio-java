package at.aamio;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * The encodings the wire uses: base64url without padding for keys,
 * signatures and envelopes, lowercase hex for hashes, sha256 over exact
 * bytes, and lowercase base32 for addresses.
 */
public final class Codec {
    public static final String VERSION = "0.2.4";

    private static final Pattern KEY = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    private static final String BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Codec() {
    }

    public static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Decodes base64url without padding, and standard base64 with or without padding too, as the service does. */
    public static byte[] unb64url(String text) {
        String s = text;
        while (s.endsWith("=")) {
            s = s.substring(0, s.length() - 1);
        }
        if (s.indexOf('+') >= 0 || s.indexOf('/') >= 0) {
            return Base64.getDecoder().decode(s);
        }
        return Base64.getUrlDecoder().decode(s);
    }

    public static byte[] sha256(byte[] bytes) {
        return digest("SHA-256", bytes);
    }

    public static byte[] sha512(byte[] bytes) {
        return digest("SHA-512", bytes);
    }

    private static byte[] digest(String algorithm, byte[] bytes) {
        try {
            return MessageDigest.getInstance(algorithm).digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Lowercase hex of sha256 over the exact bytes. */
    public static String sha256Hex(byte[] bytes) {
        return hex(sha256(bytes));
    }

    public static String sha256Hex(String text) {
        return sha256Hex(utf8(text));
    }

    public static String hex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            out[2 * i] = HEX[(bytes[i] >> 4) & 0xf];
            out[2 * i + 1] = HEX[bytes[i] & 0xf];
        }
        return new String(out);
    }

    public static byte[] unhex(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("hex has an even number of digits");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("not hex: " + hex);
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** RFC 4648 base32, lowercased, without padding. */
    public static String base32(byte[] bytes) {
        StringBuilder out = new StringBuilder((bytes.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte b : bytes) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                out.append(BASE32.charAt((buffer >> bits) & 31));
            }
            buffer &= (1 << bits) - 1;
        }
        if (bits > 0) {
            out.append(BASE32.charAt((buffer << (5 - bits)) & 31));
        }
        return out.toString();
    }

    /** Whether s has the shape of a public key: 43 characters of base64url. */
    public static boolean isKey(String s) {
        return s != null && KEY.matcher(s).matches();
    }

    public static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    public static String utf8(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    static BigInteger leToBig(byte[] little) {
        byte[] big = new byte[little.length];
        for (int i = 0; i < little.length; i++) {
            big[i] = little[little.length - 1 - i];
        }
        return new BigInteger(1, big);
    }

    static byte[] bigToLe(BigInteger value, int length) {
        byte[] big = value.toByteArray();
        byte[] out = new byte[length];
        int n = Math.min(big.length, length);
        for (int i = 0; i < n; i++) {
            out[i] = big[big.length - 1 - i];
        }
        return out;
    }
}
