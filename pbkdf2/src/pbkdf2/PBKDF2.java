package pbkdf2;

import hmac.HMAC;

import java.util.Arrays;

public class PDKDF2 {

    public static final int SHA256 = 256;
    public static final int SHA512 = 512;

    public static byte[] derive(byte[] password, byte[] salt,
                                int iterations, int dkLen, int hashType) {
        HMAC hmac = new HMAC(getHashFunction(hashType));
        int hLen = hmac.compute(password, new byte[0]).length;

        int blocksNeeded = (dkLen + hLen - 1) / hLen;
        byte[] derivedKey = new byte[dkLen];
        int offset = 0;

        for (int i = 1; i <= blocksNeeded; i++) {
            byte[] block = computeBlock(hmac, password, salt, iterations, i);
            int toCopy = Math.min(hLen, dkLen - offset);
            System.arraycopy(block, 0, derivedKey, offset, toCopy);
            offset += toCopy;
        }

        return derivedKey;
    }

    private static byte[] computeBlock(HMAC hmac, byte[] password, byte[] salt,
                                       int iterations, int blockIndex) {
        byte[] saltWithIndex = appendInt(salt, blockIndex);
        byte[] u = hmac.compute(password, saltWithIndex);
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
        result[salt.length    ] = (byte) (i >>> 24);
        result[salt.length + 1] = (byte) (i >>> 16);
        result[salt.length + 2] = (byte) (i >>> 8);
        result[salt.length + 3] = (byte)  i;
        return result;
    }

    private static void xorInPlace(byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) {
            a[i] ^= b[i];
        }
    }

    private static HMAC.HashFunction getHashFunction(int hashType) {
        if (hashType == SHA512) {
            return new HMAC.SHA512HashFunction();
        }
        return new HMAC.SHA256HashFunction();
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static void main(String[] args) {
        byte[] password   = "password".getBytes();
        byte[] salt       = "salt".getBytes();
        int    iterations = 1;
        int    dkLen      = 32;

        byte[] key = derive(password, salt, iterations, dkLen, SHA256);
        System.out.println("PBKDF2-SHA256: " + toHex(key));

        byte[] key512 = derive(password, salt, iterations, dkLen, SHA512);
        System.out.println("PBKDF2-SHA512: " + toHex(key512));
    }
}
