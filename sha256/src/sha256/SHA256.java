package sha256;

public class SHA256 {
    
    // SHA-256 Constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    // Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    private static final int[] H0 = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    /**
     * Compute SHA-256 hash of input data
     * @param message Input message as byte array
     * @return 32-byte hash
     */
    public static byte[] hash(byte[] message) {
        // Pad the message
        byte[] paddedMessage = padMessage(message);
        
        // Initialize hash values
        int[] H = H0.clone();
        
        // Process message in 512-bit (64-byte) chunks
        for (int chunk = 0; chunk < paddedMessage.length; chunk += 64) {
            processChunk(paddedMessage, chunk, H);
        }
        
        // Convert hash values to byte array
        return hashToBytes(H);
    }
    
    /**
     * Pad message according to SHA-256 specification
     * Message length must be ≡ 448 (mod 512)
     */
    private static byte[] padMessage(byte[] message) {
        long messageLengthBits = (long) message.length * 8;
        
        // Calculate padding needed
        // We need: original message + 1 bit + zeros + 64 bits for length
        int paddingLength = 64 - ((message.length + 9) % 64);
        if (paddingLength == 64) paddingLength = 0;
        
        int totalLength = message.length + 1 + paddingLength + 8;
        byte[] padded = new byte[totalLength];
        
        // Copy original message
        System.arraycopy(message, 0, padded, 0, message.length);
        
        // Append single '1' bit (0x80 = 10000000 in binary)
        padded[message.length] = (byte) 0x80;
        
        // Zeros are already there (array initialized to 0)
        
        // Append message length as 64-bit big-endian integer
        for (int i = 0; i < 8; i++) {
            padded[totalLength - 8 + i] = (byte) (messageLengthBits >>> (56 - i * 8));
        }
        
        return padded;
    }
    
    /**
     * Process a single 512-bit chunk
     */
    private static void processChunk(byte[] message, int offset, int[] H) {
        // Create message schedule array (64 words)
        int[] W = new int[64];
        
        // Copy chunk into first 16 words (big-endian)
        for (int t = 0; t < 16; t++) {
            W[t] = ((message[offset + t * 4] & 0xFF) << 24) |
                   ((message[offset + t * 4 + 1] & 0xFF) << 16) |
                   ((message[offset + t * 4 + 2] & 0xFF) << 8) |
                   (message[offset + t * 4 + 3] & 0xFF);
        }
        
        // Extend the first 16 words into remaining 48 words
        for (int t = 16; t < 64; t++) {
            int s0 = rightRotate(W[t - 15], 7) ^ rightRotate(W[t - 15], 18) ^ (W[t - 15] >>> 3);
            int s1 = rightRotate(W[t - 2], 17) ^ rightRotate(W[t - 2], 19) ^ (W[t - 2] >>> 10);
            W[t] = W[t - 16] + s0 + W[t - 7] + s1;
        }
        
        // Initialize working variables
        int a = H[0];
        int b = H[1];
        int c = H[2];
        int d = H[3];
        int e = H[4];
        int f = H[5];
        int g = H[6];
        int h = H[7];
        
        // Main loop (64 rounds)
        for (int t = 0; t < 64; t++) {
            int S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            int ch = (e & f) ^ (~e & g);
            int temp1 = h + S1 + ch + K[t] + W[t];
            int S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            int maj = (a & b) ^ (a & c) ^ (b & c);
            int temp2 = S0 + maj;
            
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        
        // Add compressed chunk to current hash values
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }
    
    /**
     * Right rotate (circular shift) operation
     */
    private static int rightRotate(int value, int bits) {
        return (value >>> bits) | (value << (32 - bits));
    }
    
    /**
     * Convert hash values to byte array
     */
    private static byte[] hashToBytes(int[] H) {
        byte[] hash = new byte[32];
        for (int i = 0; i < 8; i++) {
            hash[i * 4] = (byte) (H[i] >>> 24);
            hash[i * 4 + 1] = (byte) (H[i] >>> 16);
            hash[i * 4 + 2] = (byte) (H[i] >>> 8);
            hash[i * 4 + 3] = (byte) H[i];
        }
        return hash;
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
     * Convenience method: hash a string (UTF-8 encoding)
     */
    public static String hashString(String input) {
        byte[] hash = hash(input.getBytes());
        return toHex(hash);
    }
}
