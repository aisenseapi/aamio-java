package at.aamio;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.KeyAgreement;

/**
 * One Ed25519 identity: it signs what leaves, seals to partners and opens
 * what arrives. The X25519 pair used for sealing is derived from the Ed25519
 * pair the way libsodium does it, so a box sealed here opens in the other
 * clients, and theirs open here. Signing and the X25519 agreement are the
 * JDK's own; the public key is derived from the seed here, because the JCA
 * has no way to ask for it.
 */
public final class Keys {
    /** The name a sealed body carries in its e2ee field. */
    public static final String ENVELOPE = "nacl.box.v1";

    private static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger D = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
    private static final BigInteger BX = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
    private static final BigInteger BY = new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960");
    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] seed;
    private final PrivateKey signingKey;
    private final byte[] curveSecret;
    private final String publicKey;
    private final String hash;

    private Keys(byte[] seed, PrivateKey signingKey, byte[] curveSecret, byte[] publicRaw) {
        this.seed = seed;
        this.signingKey = signingKey;
        this.curveSecret = curveSecret;
        this.publicKey = Codec.b64url(publicRaw);
        this.hash = Codec.sha256Hex(publicRaw);
    }

    /** A fresh identity from the system's CSPRNG. */
    public static Keys generate() {
        byte[] seed = new byte[32];
        RANDOM.nextBytes(seed);
        return fromSeed(seed);
    }

    /** The identity for 32 seed bytes. */
    public static Keys fromSeed(byte[] seed) {
        if (seed == null || seed.length != 32) {
            throw new IllegalArgumentException("a seed is 32 bytes");
        }
        // libsodium: the signing scalar and the X25519 secret are both sha512(seed)[:32], clamped.
        byte[] h = Codec.sha512(seed);
        byte[] a = Arrays.copyOf(h, 32);
        a[0] &= (byte) 248;
        a[31] &= 127;
        a[31] |= 64;
        BigInteger[] point = scalarMultBase(Codec.leToBig(a));
        byte[] publicRaw = Codec.bigToLe(point[1], 32);
        if (point[0].testBit(0)) {
            publicRaw[31] |= (byte) 0x80;
        }
        try {
            PrivateKey signingKey = KeyFactory.getInstance("Ed25519").generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed.clone()));
            return new Keys(seed.clone(), signingKey, a, publicRaw);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("this JDK has no Ed25519", e);
        }
    }

    /** fromSeed over a hex string. */
    public static Keys fromSeedHex(String hex) {
        return fromSeed(Codec.unhex(hex));
    }

    /** The 32 bytes to keep under a file with mode 600, and nowhere else. */
    public byte[] seed() {
        return seed.clone();
    }

    /** The key as it travels: base64url, 43 characters. */
    public String publicKey() {
        return publicKey;
    }

    /** sha256 hex over the raw 32 bytes. */
    public String hash() {
        return hash;
    }

    /** The first 8 of hash(): what partners put in their address book. */
    public String hashPrefix() {
        return hash.substring(0, 8);
    }

    // ------------------------------------------------------------- signing --

    /** A detached signature over the exact string, base64url. */
    public String sign(String input) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(signingKey);
            sig.update(Codec.utf8(input));
            return Codec.b64url(sig.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Whether signature is by the holder of key over the exact string. */
    public static boolean verify(String key, String signature, String input) {
        if (!Codec.isKey(key) || signature == null || input == null) {
            return false;
        }
        try {
            byte[] raw = Codec.unb64url(key);
            byte[] sig = Codec.unb64url(signature);
            if (raw.length != 32 || sig.length != 64) {
                return false;
            }
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(edPublic(raw));
            verifier.update(Codec.utf8(input));
            return verifier.verify(sig);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** What a thread write is signed over. */
    public static String threadSigningInput(String w, byte[] body) {
        return "aamio-v1\n" + w + "\n" + Codec.sha256Hex(body);
    }

    public static String threadSigningInput(String w, String body) {
        return threadSigningInput(w, Codec.utf8(body));
    }

    /** What a presence publish is signed over. */
    public static String presenceSigningInput(String key, byte[] body) {
        return "aamio-presence-v1\n" + key + "\n" + Codec.sha256Hex(body);
    }

    /** What a presence delete is signed over. */
    public static String presenceDeleteSigningInput(String key, byte[] body) {
        return "aamio-presence-delete-v1\n" + key + "\n" + Codec.sha256Hex(body);
    }

    /** What a board post is signed over. */
    public static String boardSigningInput(String key, byte[] body) {
        return "aamio-board-v1\n" + key + "\n" + Codec.sha256Hex(body);
    }

    /** What a board withdrawal is signed over. */
    public static String boardDeleteSigningInput(String id, byte[] body) {
        return "aamio-board-delete-v1\n" + id + "\n" + Codec.sha256Hex(body);
    }

    // ------------------------------------------------------------- sealing --

    /** The X25519 public key for an Ed25519 public key, as libsodium's crypto_sign_ed25519_pk_to_curve25519: 32 bytes, little-endian u. */
    public static byte[] curvePublic(String key) {
        if (!Codec.isKey(key)) {
            throw new IllegalArgumentException("not a base64url Ed25519 public key of 32 bytes");
        }
        byte[] raw = Codec.unb64url(key);
        if (raw.length != 32) {
            throw new IllegalArgumentException("not a base64url Ed25519 public key of 32 bytes");
        }
        byte[] yBytes = raw.clone();
        yBytes[31] &= 0x7f;
        BigInteger y = Codec.leToBig(yBytes);
        if (y.compareTo(P) >= 0) {
            throw new IllegalArgumentException("not a point on the curve");
        }
        // -x^2 + y^2 = 1 + d x^2 y^2, so x^2 = (y^2 - 1) / (d y^2 + 1) must be a square.
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger x2 = y2.subtract(BigInteger.ONE).mod(P).multiply(D.multiply(y2).add(BigInteger.ONE).mod(P).modInverse(P)).mod(P);
        BigInteger legendre = x2.modPow(P.subtract(BigInteger.ONE).shiftRight(1), P);
        if (!x2.equals(BigInteger.ZERO) && !legendre.equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("not a point on the curve");
        }
        BigInteger u = BigInteger.ONE.add(y).multiply(BigInteger.ONE.subtract(y).mod(P).modInverse(P)).mod(P);
        return Codec.bigToLe(u, 32);
    }

    /** The first 8 hex characters of sha256 over a key's raw bytes. */
    public static String hashPrefixOf(String key) {
        return Codec.sha256Hex(Codec.unb64url(key)).substring(0, 8);
    }

    /** The envelope, as JSON text, sealed to the recipient's key. The recipient opens it with our public key. */
    public String seal(String recipientKey, byte[] plaintext) {
        byte[] peer = curvePublic(recipientKey);
        byte[] nonce = new byte[24];
        RANDOM.nextBytes(nonce);
        byte[] boxed = Nacl.secretbox(Nacl.beforeNm(shared(peer)), nonce, plaintext);
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("e2ee", ENVELOPE);
        envelope.put("to", hashPrefixOf(recipientKey));
        envelope.put("nonce", Codec.b64url(nonce));
        envelope.put("ct", Codec.b64url(boxed));
        return Json.write(envelope);
    }

    public String seal(String recipientKey, String plaintext) {
        return seal(recipientKey, Codec.utf8(plaintext));
    }

    /** Whether a body claims to be a sealed envelope. */
    public static boolean isEnvelope(String body) {
        Map<String, Object> e = Json.object(body);
        return e != null && ENVELOPE.equals(e.get("e2ee")) && nonEmpty(e.get("nonce")) && nonEmpty(e.get("ct"));
    }

    private static boolean nonEmpty(Object v) {
        return v instanceof String s && !s.isEmpty();
    }

    /** Opens an envelope sealed to us by the holder of senderKey. */
    public byte[] open(String senderKey, String envelopeText) {
        Map<String, Object> e = Json.object(envelopeText);
        if (e == null || !ENVELOPE.equals(e.get("e2ee"))) {
            throw new IllegalArgumentException("not an envelope");
        }
        String to = e.get("to") instanceof String s ? s : "";
        if (!to.equals(hashPrefix())) {
            throw new IllegalArgumentException("this envelope is sealed to " + to + ", not to " + hashPrefix());
        }
        byte[] peer = curvePublic(senderKey);
        byte[] nonce;
        byte[] boxed;
        try {
            nonce = Codec.unb64url(String.valueOf(e.get("nonce")));
            boxed = Codec.unb64url(String.valueOf(e.get("ct")));
        } catch (IllegalArgumentException x) {
            throw new IllegalArgumentException("the envelope is not base64: " + x.getMessage());
        }
        if (nonce.length != 24) {
            throw new IllegalArgumentException("the nonce is not 24 bytes");
        }
        byte[] plain = Nacl.secretboxOpen(Nacl.beforeNm(shared(peer)), nonce, boxed);
        if (plain == null) {
            throw new IllegalArgumentException("the envelope does not open with this key pair");
        }
        return plain;
    }

    private byte[] shared(byte[] peerU) {
        try {
            KeyFactory factory = KeyFactory.getInstance("X25519");
            PrivateKey mine = factory.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, curveSecret.clone()));
            PublicKey theirs = factory.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, Codec.leToBig(peerU)));
            KeyAgreement agreement = KeyAgreement.getInstance("X25519");
            agreement.init(mine);
            agreement.doPhase(theirs, true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("no shared secret with that key: " + e.getMessage(), e);
        }
    }

    private static PublicKey edPublic(byte[] raw) throws GeneralSecurityException {
        byte[] y = raw.clone();
        boolean xOdd = (y[31] & 0x80) != 0;
        y[31] &= 0x7f;
        return KeyFactory.getInstance("Ed25519").generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, Codec.leToBig(y))));
    }

    // ------------------------------------------------- the curve, for a·B --

    private static BigInteger[] add(BigInteger[] p, BigInteger[] q) {
        BigInteger x1 = p[0];
        BigInteger y1 = p[1];
        BigInteger x2 = q[0];
        BigInteger y2 = q[1];
        BigInteger dxy = D.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(P);
        BigInteger x3 = x1.multiply(y2).add(x2.multiply(y1)).mod(P).multiply(BigInteger.ONE.add(dxy).modInverse(P)).mod(P);
        BigInteger y3 = y1.multiply(y2).add(x1.multiply(x2)).mod(P).multiply(BigInteger.ONE.subtract(dxy).mod(P).modInverse(P)).mod(P);
        return new BigInteger[] {x3, y3};
    }

    private static BigInteger[] scalarMultBase(BigInteger k) {
        BigInteger[] result = {BigInteger.ZERO, BigInteger.ONE};
        BigInteger[] base = {BX, BY};
        for (int i = 0; i < k.bitLength(); i++) {
            if (k.testBit(i)) {
                result = add(result, base);
            }
            base = add(base, base);
        }
        return result;
    }
}
