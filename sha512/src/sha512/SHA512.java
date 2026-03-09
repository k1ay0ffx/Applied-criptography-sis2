package sha512;

import java.nio.charset.StandardCharsets;

/**
 * SHA-512 — from scratch, no cryptographic libraries.
 * Reference: FIPS PUB 180-4
 */
public final class SHA512 {

    // ── Round constants K[0..79] ─────────────────────────────────────────────
    private static final long[] K = {
            0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
            0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
            0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
            0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
            0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
            0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
            0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
            0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
            0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
            0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
            0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
            0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
            0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
            0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
            0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
            0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
            0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
            0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
            0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
            0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };

    // ── Initial hash values H₀ ───────────────────────────────────────────────
    private static final long[] H_INIT = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
            0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    // ────────────────────────────────────────────────────────────────────────
    //  Public API
    // ────────────────────────────────────────────────────────────────────────

    /**
     * Returns the 64-byte SHA-512 digest of {@code message}.
     *
     * @param message raw input bytes
     * @return 64-byte digest
     */
    public static byte[] hash(byte[] message) {
        byte[] padded = pad(message);
        long[] h = H_INIT.clone();
        long[] w = new long[80];

        for (int b = 0; b < padded.length / 128; b++) {
            int base = b * 128;

            // 1 — prepare 80-word message schedule
            for (int i = 0;  i < 16; i++) w[i] = readBE64(padded, base + i * 8);
            for (int i = 16; i < 80; i++) {
                long s0 = rotr(w[i-15], 1) ^ rotr(w[i-15], 8) ^ (w[i-15] >>> 7);
                long s1 = rotr(w[i- 2],19) ^ rotr(w[i- 2],61) ^ (w[i- 2] >>> 6);
                w[i] = w[i-16] + s0 + w[i-7] + s1;
            }

            // 2 — initialise working variables
            long a = h[0], b2 = h[1], c = h[2], d = h[3];
            long e = h[4], f  = h[5], g = h[6], hh = h[7];

            // 3 — 80 compression rounds
            for (int i = 0; i < 80; i++) {
                long S1  = rotr(e,14) ^ rotr(e,18) ^ rotr(e,41);
                long ch  = (e & f) ^ (~e & g);
                long t1  = hh + S1 + ch + K[i] + w[i];
                long S0  = rotr(a,28) ^ rotr(a,34) ^ rotr(a,39);
                long maj = (a & b2) ^ (a & c) ^ (b2 & c);
                long t2  = S0 + maj;

                hh = g; g = f; f = e; e = d + t1;
                d  = c; c = b2; b2 = a; a = t1 + t2;
            }

            // 4 — add to hash state
            h[0]+=a; h[1]+=b2; h[2]+=c; h[3]+=d;
            h[4]+=e; h[5]+=f;  h[6]+=g; h[7]+=hh;
        }

        return toBytes(h);
    }

    /**
     * Returns the 64-byte SHA-512 digest of a UTF-8 string.
     *
     * @param text input string
     * @return 64-byte digest
     */
    public byte[] hash(String text) {
        return hash(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Returns the SHA-512 digest as a lowercase hex string.
     *
     * @param message raw input bytes
     * @return 128-character hex string
     */
    public String hashHex(byte[] message) {
        return toHex(hash(message));
    }

    /**
     * Returns the SHA-512 digest of a UTF-8 string as a lowercase hex string.
     *
     * @param text input string
     * @return 128-character hex string
     */
    public String hashHex(String text) {
        return toHex(hash(text));
    }

    // ────────────────────────────────────────────────────────────────────────
    //  Padding  (FIPS 180-4 §5.1.2)
    // ────────────────────────────────────────────────────────────────────────

    private static byte[] pad(byte[] msg) {
        int len       = msg.length;
        int paddedLen = ((len + 17 + 127) / 128) * 128;   // next multiple of 128

        byte[] padded = new byte[paddedLen];
        System.arraycopy(msg, 0, padded, 0, len);
        padded[len] = (byte) 0x80;                        // append '1' bit

        // 128-bit big-endian bit-length in the last 16 bytes
        // (only lower 64 bits used — sufficient for any practical message)
        writeBE64(padded, paddedLen - 8, (long) len * 8L);
        return padded;
    }

    // ────────────────────────────────────────────────────────────────────────
    //  Bit / byte helpers
    // ────────────────────────────────────────────────────────────────────────

    /** 64-bit right-rotation. */
    private static long rotr(long x, int n) {
        return (x >>> n) | (x << (64 - n));
    }

    /** Read a big-endian 64-bit word from {@code buf[off..off+7]}. */
    private static long readBE64(byte[] buf, int off) {
        return ((buf[off  ] & 0xFFL) << 56) | ((buf[off+1] & 0xFFL) << 48)
                | ((buf[off+2] & 0xFFL) << 40) | ((buf[off+3] & 0xFFL) << 32)
                | ((buf[off+4] & 0xFFL) << 24) | ((buf[off+5] & 0xFFL) << 16)
                | ((buf[off+6] & 0xFFL) <<  8) |  (buf[off+7] & 0xFFL);
    }

    /** Write a big-endian 64-bit word to {@code buf[off..off+7]}. */
    private static void writeBE64(byte[] buf, int off, long v) {
        for (int i = 7; i >= 0; i--) { buf[off + i] = (byte)(v & 0xFF); v >>>= 8; }
    }

    /** Convert 8 × 64-bit words to a 64-byte big-endian array. */
    private static byte[] toBytes(long[] h) {
        byte[] out = new byte[64];
        for (int i = 0; i < 8; i++) writeBE64(out, i * 8, h[i]);
        return out;
    }

    /** Hex-encode a byte array (lowercase). */
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }
}