package at.aamio;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * crypto_box the NaCl way, on the JDK alone: the X25519 agreement comes from
 * the JCA, and HSalsa20, XSalsa20 and Poly1305, which the JDK does not have,
 * are here. A box sealed by libsodium, PyNaCl, TweetNaCl or golang.org/x/crypto
 * opens here, and the other way round; the shared vectors prove it.
 */
final class Nacl {
    private static final int[] SIGMA = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    private static final BigInteger P1305 = BigInteger.TWO.pow(130).subtract(BigInteger.valueOf(5));
    private static final BigInteger CLAMP = new BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16);
    private static final BigInteger MASK128 = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);

    private Nacl() {
    }

    private static int load(byte[] b, int i) {
        return (b[i] & 0xff) | (b[i + 1] & 0xff) << 8 | (b[i + 2] & 0xff) << 16 | (b[i + 3] & 0xff) << 24;
    }

    private static void store(byte[] b, int i, int v) {
        b[i] = (byte) v;
        b[i + 1] = (byte) (v >>> 8);
        b[i + 2] = (byte) (v >>> 16);
        b[i + 3] = (byte) (v >>> 24);
    }

    private static int rotl(int v, int c) {
        return (v << c) | (v >>> (32 - c));
    }

    private static int[] state(byte[] key, int n0, int n1, int n2, int n3) {
        return new int[] {
            SIGMA[0], load(key, 0), load(key, 4), load(key, 8),
            load(key, 12), SIGMA[1], n0, n1,
            n2, n3, SIGMA[2], load(key, 16),
            load(key, 20), load(key, 24), load(key, 28), SIGMA[3],
        };
    }

    /** The 20 Salsa20 rounds over a state, without the feed-forward. */
    private static int[] rounds(int[] in) {
        int[] x = in.clone();
        for (int i = 0; i < 20; i += 2) {
            x[4] ^= rotl(x[0] + x[12], 7);
            x[8] ^= rotl(x[4] + x[0], 9);
            x[12] ^= rotl(x[8] + x[4], 13);
            x[0] ^= rotl(x[12] + x[8], 18);
            x[9] ^= rotl(x[5] + x[1], 7);
            x[13] ^= rotl(x[9] + x[5], 9);
            x[1] ^= rotl(x[13] + x[9], 13);
            x[5] ^= rotl(x[1] + x[13], 18);
            x[14] ^= rotl(x[10] + x[6], 7);
            x[2] ^= rotl(x[14] + x[10], 9);
            x[6] ^= rotl(x[2] + x[14], 13);
            x[10] ^= rotl(x[6] + x[2], 18);
            x[3] ^= rotl(x[15] + x[11], 7);
            x[7] ^= rotl(x[3] + x[15], 9);
            x[11] ^= rotl(x[7] + x[3], 13);
            x[15] ^= rotl(x[11] + x[7], 18);
            x[1] ^= rotl(x[0] + x[3], 7);
            x[2] ^= rotl(x[1] + x[0], 9);
            x[3] ^= rotl(x[2] + x[1], 13);
            x[0] ^= rotl(x[3] + x[2], 18);
            x[6] ^= rotl(x[5] + x[4], 7);
            x[7] ^= rotl(x[6] + x[5], 9);
            x[4] ^= rotl(x[7] + x[6], 13);
            x[5] ^= rotl(x[4] + x[7], 18);
            x[11] ^= rotl(x[10] + x[9], 7);
            x[8] ^= rotl(x[11] + x[10], 9);
            x[9] ^= rotl(x[8] + x[11], 13);
            x[10] ^= rotl(x[9] + x[8], 18);
            x[12] ^= rotl(x[15] + x[14], 7);
            x[13] ^= rotl(x[12] + x[15], 9);
            x[14] ^= rotl(x[13] + x[12], 13);
            x[15] ^= rotl(x[14] + x[13], 18);
        }
        return x;
    }

    /** HSalsa20: a 32-byte key and 16 bytes of input to a 32-byte key. */
    static byte[] hsalsa20(byte[] key, byte[] in16) {
        int[] x = rounds(state(key, load(in16, 0), load(in16, 4), load(in16, 8), load(in16, 12)));
        int[] pick = {0, 5, 10, 15, 6, 7, 8, 9};
        byte[] out = new byte[32];
        for (int i = 0; i < 8; i++) {
            store(out, 4 * i, x[pick[i]]);
        }
        return out;
    }

    /** The XSalsa20 keystream for a key and a 24-byte nonce, from block 0. */
    static byte[] xsalsa20(byte[] key, byte[] nonce24, int length) {
        byte[] sub = hsalsa20(key, Arrays.copyOf(nonce24, 16));
        int n0 = load(nonce24, 16);
        int n1 = load(nonce24, 20);
        byte[] out = new byte[length];
        byte[] block = new byte[64];
        long counter = 0;
        for (int off = 0; off < length; off += 64) {
            int[] in = state(sub, n0, n1, (int) counter, (int) (counter >>> 32));
            int[] x = rounds(in);
            for (int i = 0; i < 16; i++) {
                store(block, 4 * i, x[i] + in[i]);
            }
            System.arraycopy(block, 0, out, off, Math.min(64, length - off));
            counter++;
        }
        return out;
    }

    /** crypto_box_beforenm: the shared X25519 secret to the box key. */
    static byte[] beforeNm(byte[] shared) {
        return hsalsa20(shared, new byte[16]);
    }

    /** crypto_secretbox: tag then ciphertext. */
    static byte[] secretbox(byte[] key, byte[] nonce, byte[] plaintext) {
        byte[] stream = xsalsa20(key, nonce, 32 + plaintext.length);
        byte[] ct = new byte[plaintext.length];
        for (int i = 0; i < ct.length; i++) {
            ct[i] = (byte) (plaintext[i] ^ stream[32 + i]);
        }
        byte[] tag = poly1305(Arrays.copyOf(stream, 32), ct);
        byte[] out = new byte[16 + ct.length];
        System.arraycopy(tag, 0, out, 0, 16);
        System.arraycopy(ct, 0, out, 16, ct.length);
        return out;
    }

    /** crypto_secretbox_open: the plaintext, or null when the tag does not match. */
    static byte[] secretboxOpen(byte[] key, byte[] nonce, byte[] boxed) {
        if (boxed.length < 16) {
            return null;
        }
        byte[] ct = Arrays.copyOfRange(boxed, 16, boxed.length);
        byte[] stream = xsalsa20(key, nonce, 32 + ct.length);
        byte[] tag = poly1305(Arrays.copyOf(stream, 32), ct);
        if (!MessageDigest.isEqual(tag, Arrays.copyOf(boxed, 16))) {
            return null;
        }
        byte[] plain = new byte[ct.length];
        for (int i = 0; i < ct.length; i++) {
            plain[i] = (byte) (ct[i] ^ stream[32 + i]);
        }
        return plain;
    }

    /** Poly1305 over a message with a one-time 32-byte key. */
    static byte[] poly1305(byte[] key32, byte[] message) {
        BigInteger r = Codec.leToBig(Arrays.copyOf(key32, 16)).and(CLAMP);
        BigInteger s = Codec.leToBig(Arrays.copyOfRange(key32, 16, 32));
        BigInteger acc = BigInteger.ZERO;
        for (int off = 0; off < message.length; off += 16) {
            int len = Math.min(16, message.length - off);
            byte[] block = new byte[len + 1];
            System.arraycopy(message, off, block, 0, len);
            block[len] = 1;
            acc = acc.add(Codec.leToBig(block)).multiply(r).mod(P1305);
        }
        return Codec.bigToLe(acc.add(s).and(MASK128), 16);
    }
}
