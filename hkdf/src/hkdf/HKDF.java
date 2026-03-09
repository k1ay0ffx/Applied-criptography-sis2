package hkdf;

import hmac.HMAC;

public class HKDF {

    public static final int SHA256 = 256;
    public static final int SHA512 = 512;

    public static byte[] deriveKey(byte[] inputKeyMaterial, byte[] salt,
                                   byte[] info, int okmLen, int hashType) {
        byte[] prk = extract(inputKeyMaterial, salt, hashType);
        return expand(prk, info, okmLen, hashType);
    }

    public static byte[] extract(byte[] inputKeyMaterial, byte[] salt, int hashType) {
        HMAC hmac = new HMAC(getHashFunction(hashType));
        if (salt == null || salt.length == 0) {
            salt = new byte[hmac.compute(new byte[0], new byte[0]).length];
        }
        return hmac.compute(salt, inputKeyMaterial);
    }

    public static byte[] expand(byte[] prk, byte[] info, int okmLen, int hashType) {
        HMAC hmac = new HMAC(getHashFunction(hashType));
        int hLen = hmac.compute(prk, new byte[0]).length;

        if (okmLen > 255 * hLen) {
            throw new IllegalArgumentException(
                    "okmLen слишком большой. Максимум: " + (255 * hLen) + " байт"
            );
        }

        if (info == null) info = new byte[0];

        int blocksNeeded = (okmLen + hLen - 1) / hLen;
        byte[] okm = new byte[okmLen];
        byte[] t   = new byte[0];
        int offset = 0;

        for (int i = 1; i <= blocksNeeded; i++) {
            byte[] input = concat(concat(t, info), new byte[]{ (byte) i });
            t = hmac.compute(prk, input);

            int toCopy = Math.min(hLen, okmLen - offset);
            System.arraycopy(t, 0, okm, offset, toCopy);
            offset += toCopy;
        }

        return okm;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0,        a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
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
        byte[] ikm  = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hexToBytes("000102030405060708090a0b0c");
        byte[] info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
        int    okmLen = 42;

        byte[] prk = extract(ikm, salt, SHA256);
        System.out.println("PRK: " + toHex(prk));

        byte[] okm = expand(prk, info, okmLen, SHA256);
        System.out.println("OKM: " + toHex(okm));
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
