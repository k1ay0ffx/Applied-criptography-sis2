package hmac;

import sha256.SHA256;

/**
 * HMAC (Hash-based Message Authentication Code) Implementation
 * 
 * HMAC provides message authentication using a cryptographic hash function
 * and a secret key. It can be used with any hash function (SHA-256, SHA-1, etc.)
 * 
 * RFC 2104: https://tools.ietf.org/html/rfc2104
 */
public class HMAC {
    
    /**
     * Hash function interface to support different hash algorithms
     */
    public interface HashFunction {
        byte[] hash(byte[] data);
        int getBlockSize();  // Block size in bytes (64 for SHA-256, 128 for SHA-512)
        int getOutputSize(); // Output size in bytes (32 for SHA-256, 64 for SHA-512)
    }
    
    /**
     * SHA-256 hash function implementation
     */
    public static class SHA256HashFunction implements HashFunction {
        @Override
        public byte[] hash(byte[] data) {
            return SHA256.hash(data);
        }
        
        @Override
        public int getBlockSize() {
            return 64;  // SHA-256 block size is 512 bits = 64 bytes
        }
        
        @Override
        public int getOutputSize() {
            return 32;  // SHA-256 output is 256 bits = 32 bytes
        }
    }
    
    // HMAC padding constants
    private static final byte IPAD = 0x36;  // Inner padding (00110110)
    private static final byte OPAD = 0x5C;  // Outer padding (01011100)
    
    private final HashFunction hashFunction;
    
    /**
     * Constructor with custom hash function
     */
    public HMAC(HashFunction hashFunction) {
        this.hashFunction = hashFunction;
    }
    
    /**
     * Default constructor using SHA-256
     */
    public HMAC() {
        this(new SHA256HashFunction());
    }
    
    /**
     * Compute HMAC for given message and key
     * 
     * HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
     * 
     * where:
     * - K' is the key padded/hashed to block size
     * - ipad is 0x36 repeated
     * - opad is 0x5C repeated
     * - || is concatenation
     * - ⊕ is XOR
     * - H is the hash function
     */
    public byte[] compute(byte[] key, byte[] message) {
        int blockSize = hashFunction.getBlockSize();
        
        // Step 1: Prepare the key
        byte[] keyPrime = prepareKey(key, blockSize);
        
        // Step 2: Create inner and outer padded keys
        byte[] innerKey = xorWithPad(keyPrime, IPAD);
        byte[] outerKey = xorWithPad(keyPrime, OPAD);
        
        // Step 3: Compute inner hash: H((K' ⊕ ipad) || message)
        byte[] innerInput = concatenate(innerKey, message);
        byte[] innerHash = hashFunction.hash(innerInput);
        
        // Step 4: Compute outer hash: H((K' ⊕ opad) || innerHash)
        byte[] outerInput = concatenate(outerKey, innerHash);
        byte[] hmac = hashFunction.hash(outerInput);
        
        return hmac;
    }
    
    /**
     * Prepare key to be exactly blockSize bytes
     * - If key is longer than blockSize, hash it
     * - If key is shorter than blockSize, pad with zeros
     */
    private byte[] prepareKey(byte[] key, int blockSize) {
        byte[] keyPrime = new byte[blockSize];
        
        if (key.length > blockSize) {
            // If key is too long, hash it first
            byte[] hashedKey = hashFunction.hash(key);
            System.arraycopy(hashedKey, 0, keyPrime, 0, hashedKey.length);
            // Rest is already zeros (padded)
        } else {
            // If key is shorter or equal, just copy and pad with zeros
            System.arraycopy(key, 0, keyPrime, 0, key.length);
            // Rest is already zeros (padded)
        }
        
        return keyPrime;
    }
    
    /**
     * XOR each byte of data with pad value
     */
    private byte[] xorWithPad(byte[] data, byte pad) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ pad);
        }
        return result;
    }
    
    /**
     * Concatenate two byte arrays
     */
    private byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
    
    /**
     * Convert byte array to hex string
     */
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
    
    /**
     * Convert hex string to byte array
     */
    public static byte[] fromHex(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
    
    /**
     * Constant-time comparison to prevent timing attacks
     */
    public static boolean secureCompare(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        
        return result == 0;
    }
    
    /**
     * Verify if a message matches an HMAC with given key
     */
    public boolean verify(byte[] key, byte[] message, byte[] expectedHmac) {
        byte[] computedHmac = compute(key, message);
        return secureCompare(computedHmac, expectedHmac);
    }
    
    // ==================== CONVENIENCE METHODS ====================
    
    /**
     * Compute HMAC for string message with string key
     */
    public String computeString(String key, String message) {
        byte[] hmac = compute(key.getBytes(), message.getBytes());
        return toHex(hmac);
    }
    
    /**
     * Compute HMAC with hex-encoded key
     */
    public String computeHexKey(String hexKey, String message) {
        byte[] key = fromHex(hexKey);
        byte[] hmac = compute(key, message.getBytes());
        return toHex(hmac);
    }
}
