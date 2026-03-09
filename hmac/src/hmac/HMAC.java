package hmac;

import sha256.SHA256;
import java.nio.charset.StandardCharsets;

public class HMAC {

    public interface HashFunction {
        byte[] hash(byte[] data);
        int getBlockSize();
        int getOutputSize();
    }

    public static class SHA256HashFunction implements HashFunction {
        @Override public byte[] hash(byte[] data) { return SHA256.hash(data); }
        @Override public int getBlockSize()        { return 64; }
        @Override public int getOutputSize()       { return 32; }
    }

    public static class SHA512HashFunction implements HashFunction {
        @Override public byte[] hash(byte[] data) { return sha512.SHA512.hash(data); }
        @Override public int getBlockSize()        { return 128; }
        @Override public int getOutputSize()       { return 64;  }
    }

    private static final byte IPAD = 0x36;
    private static final byte OPAD = 0x5C;

    private final HashFunction hashFunction;

    public HMAC(HashFunction hashFunction) { this.hashFunction = hashFunction; }
    public HMAC()                          { this(new SHA256HashFunction()); }

    // ── Core ──────────────────────────────────────────────────────────────────

    public byte[] compute(byte[] key, byte[] message) {
        int    blockSize = hashFunction.getBlockSize();
        byte[] keyPrime  = prepareKey(key, blockSize);
        byte[] innerKey  = xorWithPad(keyPrime, IPAD);
        byte[] outerKey  = xorWithPad(keyPrime, OPAD);
        byte[] innerHash = hashFunction.hash(concatenate(innerKey, message));
        return hashFunction.hash(concatenate(outerKey, innerHash));
    }

    public String computeHex(byte[] key, byte[] message) {
        return toHex(compute(key, message));
    }

    public boolean verifyHex(byte[] key, byte[] message, String expectedHex) {
        byte[] expected = fromHex(expectedHex);
        return verify(key, message, expected);
    }

    public boolean verify(byte[] key, byte[] message, byte[] expectedHmac) {
        return secureCompare(compute(key, message), expectedHmac);
    }

    // ── Key preparation ───────────────────────────────────────────────────────

    private byte[] prepareKey(byte[] key, int blockSize) {
        byte[] keyPrime = new byte[blockSize];
        byte[] src      = (key.length > blockSize) ? hashFunction.hash(key) : key;
        System.arraycopy(src, 0, keyPrime, 0, src.length);
        return keyPrime;
    }

    private byte[] xorWithPad(byte[] data, byte pad) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) result[i] = (byte)(data[i] ^ pad);
        return result;
    }

    private byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    public static boolean secureCompare(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) result |= a[i] ^ b[i];
        return result == 0;
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        hex = hex.replaceAll("\\s", "");
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < data.length; i++)
            data[i] = (byte)((Character.digit(hex.charAt(i*2),16)<<4)
                            + Character.digit(hex.charAt(i*2+1),16));
        return data;
    }

    //getBytes(StandardCharsets.UTF_8) in convenience methods
    public String computeString(String key, String message) {
        return toHex(compute(key.getBytes(StandardCharsets.UTF_8),
                             message.getBytes(StandardCharsets.UTF_8)));
    }

    public String computeHexKey(String hexKey, String message) {
        return toHex(compute(fromHex(hexKey),
                             message.getBytes(StandardCharsets.UTF_8)));
    }
}