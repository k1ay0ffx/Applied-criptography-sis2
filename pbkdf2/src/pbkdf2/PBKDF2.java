package pbkdf2;

import hmac.HMAC;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class PBKDF2 {

    public static final int SHA256 = 256;
    public static final int SHA512 = 512;

    // ── Core derive ───────────────────────────────────────────────────────────

    /** Full signature with explicit hash type. */
    public static byte[] derive(byte[] password, byte[] salt,
                                int iterations, int dkLen, int hashType) {
        HMAC hmac = new HMAC(getHashFunction(hashType));
        int  hLen = hmac.compute(password, new byte[0]).length;

        int    blocksNeeded = (dkLen + hLen - 1) / hLen;
        byte[] derivedKey   = new byte[dkLen];
        int    offset       = 0;

        for (int i = 1; i <= blocksNeeded; i++) {
            byte[] block  = computeBlock(hmac, password, salt, iterations, i);
            int    toCopy = Math.min(hLen, dkLen - offset);
            System.arraycopy(block, 0, derivedKey, offset, toCopy);
            offset += toCopy;
        }
        return derivedKey;
    }

    
    /**
     * Derives key using SHA-256 by default (no need to pass hashType).
     * Shortcut for: derive(password, salt, iterations, dkLen, SHA256)
     */
    public byte[] derive(byte[] password, byte[] salt, int iterations, int dkLen) {
        return derive(password, salt, iterations, dkLen, SHA256);
    }

    /**
     * Derives key from plain string password and salt, returns hex string.
     * Strings are encoded as UTF-8 internally before deriving.
     * Useful for AppConsole where user types password as text.
     */
    public String deriveHex(String password, String salt, int iterations, int dkLen) {
        return toHex(derive(
            password.getBytes(StandardCharsets.UTF_8),
            salt.getBytes(StandardCharsets.UTF_8),
            iterations, dkLen, SHA256));
    }

    public String deriveHex(byte[] password, byte[] salt, int iterations, int dkLen) {
        return toHex(derive(password, salt, iterations, dkLen, SHA256));
    }

    // ── Block computation F(P, S, c, i) ──────────────────────────────────────

    private static byte[] computeBlock(HMAC hmac, byte[] password, byte[] salt,
                                       int iterations, int blockIndex) {
        byte[] saltWithIndex = appendInt(salt, blockIndex);
        byte[] u     = hmac.compute(password, saltWithIndex);
        byte[] block = Arrays.copyOf(u, u.length);

        for (int iter = 2; iter <= iterations; iter++) {
            u = hmac.compute(password, u);
            xorInPlace(block, u);
        }
        return block;
    }

    private static byte[] appendInt(byte[] salt, int i) {
        byte[] result = new byte[salt.length + 4];
        System.arraycopy(salt, 0, result, 0, salt.length);
        result[salt.length    ] = (byte)(i >>> 24);
        result[salt.length + 1] = (byte)(i >>> 16);
        result[salt.length + 2] = (byte)(i >>>  8);
        result[salt.length + 3] = (byte) i;
        return result;
    }

    private static void xorInPlace(byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) a[i] ^= b[i];
    }

    private static HMAC.HashFunction getHashFunction(int hashType) {
        return (hashType == SHA512) ? new HMAC.SHA512HashFunction()
                                    : new HMAC.SHA256HashFunction();
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }
}