package hkdf;

import hmac.HMAC;
import java.nio.charset.StandardCharsets;

public class HKDF {

    public static final int SHA256 = 256;
    public static final int SHA512 = 512;

    // ── Core ──────────────────────────────────────────────────────────────────

    public static byte[] deriveKey(byte[] inputKeyMaterial, byte[] salt,
                                   byte[] info, int okmLen, int hashType) {
        byte[] prk = extract(inputKeyMaterial, salt, hashType);
        return expand(prk, info, okmLen, hashType);
    }

    public static byte[] extract(byte[] inputKeyMaterial, byte[] salt, int hashType) {
        HMAC hmac = new HMAC(getHashFunction(hashType));
        if (salt == null || salt.length == 0)
            salt = new byte[hmac.compute(new byte[0], new byte[0]).length];
        return hmac.compute(salt, inputKeyMaterial);
    }

    public static byte[] expand(byte[] prk, byte[] info, int okmLen, int hashType) {
        HMAC hmac = new HMAC(getHashFunction(hashType));
        int  hLen = hmac.compute(prk, new byte[0]).length;

        if (okmLen > 255 * hLen)
            throw new IllegalArgumentException("okmLen too large. Max: " + (255 * hLen));

        if (info == null) info = new byte[0];

        int    blocksNeeded = (okmLen + hLen - 1) / hLen;
        byte[] okm    = new byte[okmLen];
        byte[] t      = new byte[0];
        int    offset = 0;

        for (int i = 1; i <= blocksNeeded; i++) {
            byte[] input = concat(concat(t, info), new byte[]{ (byte) i });
            t = hmac.compute(prk, input);
            int toCopy = Math.min(hLen, okmLen - offset);
            System.arraycopy(t, 0, okm, offset, toCopy);
            offset += toCopy;
        }
        return okm;
    }

    
        /**
     * Derives key and returns result as hex string.
     * Uses SHA-256 by default.
     * @param ikm   input key material (raw bytes)
     * @param salt  optional salt (raw bytes)
     * @param info  context label (raw bytes)
     * @param okmLen  desired output length in bytes
     */
    public String deriveKeyHex(byte[] ikm, byte[] salt, byte[] info, int okmLen) {
        return toHex(deriveKey(ikm, salt, info, okmLen, SHA256));
    }

    /**
     * Same as above but accepts plain strings instead of byte arrays.
     * Strings are encoded as UTF-8 internally before deriving.
     */
    public String deriveKeyHex(String ikm, String salt, String info, int okmLen) {
        return toHex(deriveKey(
            ikm.getBytes(StandardCharsets.UTF_8),
            salt.getBytes(StandardCharsets.UTF_8),
            info.getBytes(StandardCharsets.UTF_8),
            okmLen, SHA256));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
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