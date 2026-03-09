package argon2;

/**
 * BLAKE2b — from scratch, no cryptographic libraries.
 * Used internally as the primitive for Argon2.
 * Reference: RFC 7693
 */
final class Blake2b {

    // ── IV: first 64 bits of √primes (same as SHA-512 H₀) ──────────────────
    static final long[] IV = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
            0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
            0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    // ── Message-word permutations for 12 rounds ──────────────────────────────
    private static final byte[][] SIGMA = {
            {  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
            { 14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
            { 11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
            {  7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
            {  9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
            {  2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
            { 12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
            { 13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
            {  6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
            { 10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
    };

    private static final int BLOCK = 128;

    // ── Instance state ───────────────────────────────────────────────────────
    private final int    digestLen;
    private final long[] h      = new long[8];
    private final byte[] buf    = new byte[BLOCK];
    private int          bufPos;
    private long         ctrLo, ctrHi;

    // ── Constructors ─────────────────────────────────────────────────────────

    Blake2b(int digestLen) { this(digestLen, null); }

    Blake2b(int digestLen, byte[] key) {
        if (digestLen < 1 || digestLen > 64) throw new IllegalArgumentException("digestLen 1–64");
        int kk = (key != null) ? key.length : 0;
        if (kk > 64) throw new IllegalArgumentException("key max 64 bytes");
        this.digestLen = digestLen;

        System.arraycopy(IV, 0, h, 0, 8);
        h[0] ^= 0x01010000L | ((long) kk << 8) | digestLen;

        if (kk > 0) {
            byte[] block = new byte[BLOCK];
            System.arraycopy(key, 0, block, 0, kk);
            update(block, 0, BLOCK);
        }
    }

    // ── Incremental API ──────────────────────────────────────────────────────

    void update(byte[] in) { update(in, 0, in.length); }

    void update(byte[] in, int off, int len) {
        if (len == 0) return;
        int fill = BLOCK - bufPos;
        if (bufPos > 0 && len > fill) {
            System.arraycopy(in, off, buf, bufPos, fill);
            incrCounter(BLOCK);
            compress(false);
            bufPos = 0; off += fill; len -= fill;
        }
        while (len > BLOCK) {
            System.arraycopy(in, off, buf, 0, BLOCK);
            incrCounter(BLOCK);
            compress(false);
            off += BLOCK; len -= BLOCK;
        }
        System.arraycopy(in, off, buf, bufPos, len);
        bufPos += len;
    }

    byte[] digest() {
        for (int i = bufPos; i < BLOCK; i++) buf[i] = 0;
        incrCounter(bufPos);
        compress(true);

        byte[] out = new byte[digestLen];
        for (int i = 0; i < digestLen; i++)
            out[i] = (byte)(h[i >>> 3] >>> ((i & 7) << 3));
        return out;
    }

    // ── Compression ──────────────────────────────────────────────────────────

    private void incrCounter(int add) {
        ctrLo += add;
        if (Long.compareUnsigned(ctrLo, Integer.toUnsignedLong(add)) < 0) ctrHi++;
    }

    private void compress(boolean last) {
        long[] m = new long[16];
        for (int i = 0; i < 16; i++) m[i] = rle64(buf, i * 8);

        long v0=h[0],v1=h[1],v2=h[2],v3=h[3],v4=h[4],v5=h[5],v6=h[6],v7=h[7];
        long v8=IV[0],v9=IV[1],v10=IV[2],v11=IV[3];
        long v12=IV[4]^ctrLo, v13=IV[5]^ctrHi;
        long v14 = last ? ~IV[6] : IV[6];
        long v15 = IV[7];

        for (int r = 0; r < 12; r++) {
            byte[] s = SIGMA[r % 10];
            // column
            v0+=v4+m[s[0]];  v12=rotr(v12^v0,32); v8+=v12;  v4=rotr(v4^v8,24);
            v0+=v4+m[s[1]];  v12=rotr(v12^v0,16); v8+=v12;  v4=rotr(v4^v8,63);

            v1+=v5+m[s[2]];  v13=rotr(v13^v1,32); v9+=v13;  v5=rotr(v5^v9,24);
            v1+=v5+m[s[3]];  v13=rotr(v13^v1,16); v9+=v13;  v5=rotr(v5^v9,63);

            v2+=v6+m[s[4]];  v14=rotr(v14^v2,32); v10+=v14; v6=rotr(v6^v10,24);
            v2+=v6+m[s[5]];  v14=rotr(v14^v2,16); v10+=v14; v6=rotr(v6^v10,63);

            v3+=v7+m[s[6]];  v15=rotr(v15^v3,32); v11+=v15; v7=rotr(v7^v11,24);
            v3+=v7+m[s[7]];  v15=rotr(v15^v3,16); v11+=v15; v7=rotr(v7^v11,63);
            // diagonal
            v0+=v5+m[s[8]];  v15=rotr(v15^v0,32); v10+=v15; v5=rotr(v5^v10,24);
            v0+=v5+m[s[9]];  v15=rotr(v15^v0,16); v10+=v15; v5=rotr(v5^v10,63);

            v1+=v6+m[s[10]]; v12=rotr(v12^v1,32); v11+=v12; v6=rotr(v6^v11,24);
            v1+=v6+m[s[11]]; v12=rotr(v12^v1,16); v11+=v12; v6=rotr(v6^v11,63);

            v2+=v7+m[s[12]]; v13=rotr(v13^v2,32); v8+=v13;  v7=rotr(v7^v8,24);
            v2+=v7+m[s[13]]; v13=rotr(v13^v2,16); v8+=v13;  v7=rotr(v7^v8,63);

            v3+=v4+m[s[14]]; v14=rotr(v14^v3,32); v9+=v14;  v4=rotr(v4^v9,24);
            v3+=v4+m[s[15]]; v14=rotr(v14^v3,16); v9+=v14;  v4=rotr(v4^v9,63);
        }

        h[0]^=v0^v8; h[1]^=v1^v9;  h[2]^=v2^v10; h[3]^=v3^v11;
        h[4]^=v4^v12;h[5]^=v5^v13; h[6]^=v6^v14; h[7]^=v7^v15;
    }

    // ── Static helpers ───────────────────────────────────────────────────────

    static byte[] digest(int len, byte[] input) {
        Blake2b b = new Blake2b(len); b.update(input); return b.digest();
    }

    static byte[] digest(int len, byte[]... inputs) {
        Blake2b b = new Blake2b(len);
        for (byte[] in : inputs) b.update(in);
        return b.digest();
    }

    private static long rotr(long x, int n) { return (x >>> n) | (x << (64 - n)); }

    /** Read little-endian 64-bit word. */
    static long rle64(byte[] buf, int off) {
        return  (buf[off  ] & 0xFFL)        | ((buf[off+1] & 0xFFL) <<  8)
                | ((buf[off+2] & 0xFFL) << 16) | ((buf[off+3] & 0xFFL) << 24)
                | ((buf[off+4] & 0xFFL) << 32) | ((buf[off+5] & 0xFFL) << 40)
                | ((buf[off+6] & 0xFFL) << 48) | ((buf[off+7] & 0xFFL) << 56);
    }

    /** Write little-endian 64-bit word. */
    static void wle64(byte[] buf, int off, long v) {
        for (int i = 0; i < 8; i++) { buf[off+i] = (byte)(v & 0xFF); v >>>= 8; }
    }

    /** Encode int as 4 little-endian bytes. */
    static byte[] le32(int v) {
        return new byte[]{ (byte)v, (byte)(v>>>8), (byte)(v>>>16), (byte)(v>>>24) };
    }
}