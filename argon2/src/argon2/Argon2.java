package argon2;

import java.util.Arrays;
import java.util.Base64;

public final class Argon2 {

    // ─────────────────────────────────────────────────────────────────────────
    //  Types & constants
    // ─────────────────────────────────────────────────────────────────────────

    public enum Type {
        ARGON2D (0, "argon2d"),
        ARGON2I (1, "argon2i"),
        ARGON2ID(2, "argon2id");
        final int id; final String label;
        Type(int id, String label) { this.id = id; this.label = label; }
    }

    public static final int VERSION     = 0x13;   // 19
    private static final int BLOCK_BYTES = 1024;
    private static final int BLOCK_WORDS = 128;   // 1024 / 8

    // ─────────────────────────────────────────────────────────────────────────
    //  Public API
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Hash a password and return the raw tag bytes.
     *
     * @param type          Argon2d / Argon2i / Argon2id
     * @param password      password bytes
     * @param salt          salt (≥ 8 bytes recommended)
     * @param timeCost      number of passes  (≥ 1)
     * @param memoryCostKB  memory in KiB     (≥ 8 × parallelism)
     * @param parallelism   lanes             (≥ 1)
     * @param tagLength     output length     (≥ 4)
     * @return raw tag
     */
    public static byte[] hash(
            Type type, byte[] password, byte[] salt,
            int timeCost, int memoryCostKB, int parallelism, int tagLength) {
        return hash(type, password, salt, new byte[0], new byte[0],
                timeCost, memoryCostKB, parallelism, tagLength);
    }

    /**
     * Hash a password with optional secret and associated data.
     */
    public static byte[] hash(
            Type type, byte[] password, byte[] salt, byte[] secret, byte[] ad,
            int timeCost, int memoryCostKB, int parallelism, int tagLength) {

        validate(password, salt, secret, ad, timeCost, memoryCostKB, parallelism, tagLength);

        int segLen    = Math.max(1, memoryCostKB / (4 * parallelism));
        int laneLen   = 4 * segLen;
        int totalBlocks = laneLen * parallelism;

        // Step 1 — H₀
        byte[] h0 = computeH0(type, password, salt, secret, ad,
                timeCost, memoryCostKB, parallelism, tagLength);

        // Step 2 — initialise memory, columns 0 and 1 of every lane
        long[][] mem = new long[totalBlocks][BLOCK_WORDS];
        for (int lane = 0; lane < parallelism; lane++) {
            copy(mem[lane * laneLen    ], variableHashToBlock(h0, 0, lane));
            copy(mem[lane * laneLen + 1], variableHashToBlock(h0, 1, lane));
        }

        // Step 3 — fill memory
        for (int pass = 0; pass < timeCost; pass++)
            for (int slice = 0; slice < 4; slice++)
                for (int lane = 0; lane < parallelism; lane++)
                    fillSegment(mem, type, pass, lane, slice,
                            parallelism, laneLen, segLen, timeCost);

        // Step 4 — XOR last-column blocks of all lanes
        long[] xor = Arrays.copyOf(mem[laneLen - 1], BLOCK_WORDS);
        for (int lane = 1; lane < parallelism; lane++)
            xorWords(xor, mem[lane * laneLen + laneLen - 1]);

        // Step 5 — H′ of the XOR block
        return variableHash(tagLength, blockToBytes(xor));
    }

    /**
     * Hash and return a PHC-format encoded string:
     * {@code $argon2id$v=19$m=65536,t=3,p=4$<salt-b64>$<hash-b64>}
     */
    public static String hashEncoded(
            Type type, byte[] password, byte[] salt,
            int timeCost, int memoryCostKB, int parallelism, int tagLength) {
        byte[] tag = hash(type, password, salt, timeCost, memoryCostKB, parallelism, tagLength);
        Base64.Encoder enc = Base64.getEncoder().withoutPadding();
        return String.format("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
                type.label, VERSION, memoryCostKB, timeCost, parallelism,
                enc.encodeToString(salt), enc.encodeToString(tag));
    }

    /**
     * Verify a password against a PHC-encoded hash.
     * Uses constant-time comparison to prevent timing attacks.
     *
     * @return true if the password is correct
     */
    public static boolean verify(String encoded, byte[] password) {
        String[] p = encoded.split("\\$");
        if (p.length < 6) throw new IllegalArgumentException("Invalid encoded hash");

        Type type;
        switch (p[1]) {
            case "argon2d":  type = Type.ARGON2D;  break;
            case "argon2i":  type = Type.ARGON2I;  break;
            case "argon2id": type = Type.ARGON2ID; break;
            default: throw new IllegalArgumentException("Unknown type: " + p[1]);
        }

        int m = 0, t = 0, lanes = 0;
        for (String kv : p[3].split(",")) {
            if (kv.startsWith("m="))      m     = Integer.parseInt(kv.substring(2));
            else if (kv.startsWith("t=")) t     = Integer.parseInt(kv.substring(2));
            else if (kv.startsWith("p=")) lanes = Integer.parseInt(kv.substring(2));
        }

        Base64.Decoder dec = Base64.getDecoder();
        byte[] salt     = dec.decode(p[4]);
        byte[] expected = dec.decode(p[5]);
        byte[] computed = hash(type, password, salt, t, m, lanes, expected.length);
        return constantTimeEq(expected, computed);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  H₀  (pre-hashing digest)
    // ─────────────────────────────────────────────────────────────────────────

    private static byte[] computeH0(
            Type type, byte[] pwd, byte[] salt, byte[] secret, byte[] ad,
            int t, int m, int p, int tau) {
        Blake2b b = new Blake2b(64);
        b.update(Blake2b.le32(p));
        b.update(Blake2b.le32(tau));
        b.update(Blake2b.le32(m));
        b.update(Blake2b.le32(t));
        b.update(Blake2b.le32(VERSION));
        b.update(Blake2b.le32(type.id));
        b.update(Blake2b.le32(pwd.length));    b.update(pwd);
        b.update(Blake2b.le32(salt.length));   b.update(salt);
        b.update(Blake2b.le32(secret.length)); b.update(secret);
        b.update(Blake2b.le32(ad.length));     b.update(ad);
        return b.digest();
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Variable-length hash  H′  (RFC 9106 §3.2)
    // ─────────────────────────────────────────────────────────────────────────

    static byte[] variableHash(int tau, byte[] input) {
        if (tau <= 64) {
            Blake2b b = new Blake2b(tau);
            b.update(Blake2b.le32(tau));
            b.update(input);
            return b.digest();
        }
        // τ > 64: chain 64-byte blocks, take 32 bytes from each except the last
        int r = (tau + 31) / 32 - 2;
        byte[] out = new byte[tau];
        int pos = 0;

        Blake2b b = new Blake2b(64);
        b.update(Blake2b.le32(tau));
        b.update(input);
        byte[] prev = b.digest();
        System.arraycopy(prev, 0, out, pos, 32); pos += 32;

        for (int i = 1; i <= r; i++) {
            prev = Blake2b.digest(64, prev);
            System.arraycopy(prev, 0, out, pos, 32); pos += 32;
        }
        byte[] last = Blake2b.digest(tau - pos, prev);
        System.arraycopy(last, 0, out, pos, last.length);
        return out;
    }

    private static long[] variableHashToBlock(byte[] h0, int col, int lane) {
        byte[] input = new byte[72];
        System.arraycopy(h0,               0, input,  0, 64);
        System.arraycopy(Blake2b.le32(col), 0, input, 64,  4);
        System.arraycopy(Blake2b.le32(lane),0, input, 68,  4);
        return bytesToBlock(variableHash(BLOCK_BYTES, input));
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Segment filling
    // ─────────────────────────────────────────────────────────────────────────

    private static void fillSegment(
            long[][] mem, Type type, int pass, int lane, int slice,
            int par, int laneLen, int segLen, int t) {

        int base    = lane * laneLen;
        int segOff  = slice * segLen;
        boolean indep = (type == Type.ARGON2I) ||
                (type == Type.ARGON2ID && pass == 0 && slice < 2);

        long[] pseudoRands = indep
                ? generateAddresses(mem, pass, lane, slice, par, laneLen, t, type.id, segLen)
                : null;

        for (int idx = 0; idx < segLen; idx++) {
            int absPos = segOff + idx;
            if (pass == 0 && slice == 0 && idx < 2) continue;

            int    prevPos  = (absPos == 0) ? laneLen - 1 : absPos - 1;
            long[] prev     = mem[base + prevPos];
            long   prand    = indep ? pseudoRands[idx] : prev[0];
            long   j1       = prand & 0xFFFFFFFFL;
            long   j2       = (prand >>> 32) & 0xFFFFFFFFL;

            int refLane = (pass == 0 && slice == 0) ? lane : (int)(j2 % par);
            int refIdx  = mapIndex(pass, lane, slice, absPos, idx,
                    refLane, j1, par, laneLen, segLen);

            fillBlock(prev, mem[refLane * laneLen + refIdx],
                    mem[base + absPos], pass > 0);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Index mapping  (quadratic distribution, RFC 9106 §3.3)
    // ─────────────────────────────────────────────────────────────────────────

    private static int mapIndex(
            int pass, int lane, int slice, int absPos, int idxInSeg,
            int refLane, long j1, int par, int laneLen, int segLen) {

        boolean same = (refLane == lane);
        int area;
        if (pass == 0) {
            if (slice == 0)   area = idxInSeg - 1;
            else if (same)    area = slice * segLen + idxInSeg - 1;
            else              area = slice * segLen - (idxInSeg == 0 ? 1 : 0);
        } else {
            if (same)         area = laneLen - segLen + idxInSeg - 1;
            else              area = laneLen - segLen - (idxInSeg == 0 ? 1 : 0);
        }
        if (area < 1) area = 1;

        long x      = (j1 * j1) >>> 32;
        long relPos = area - 1 - ((long) area * x >>> 32);
        int  start  = (pass == 0) ? 0 : ((slice == 3) ? 0 : (slice + 1) * segLen);
        return (int)((start + relPos) % laneLen);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Argon2i address-block generation
    // ─────────────────────────────────────────────────────────────────────────

    private static long[] generateAddresses(
            long[][] mem, int pass, int lane, int slice,
            int par, int laneLen, int t, int typeId, int segLen) {

        long[] result = new long[segLen];
        long[] zero   = new long[BLOCK_WORDS];
        long[] input  = new long[BLOCK_WORDS];
        long[] tmp    = new long[BLOCK_WORDS];
        long[] addr   = new long[BLOCK_WORDS];
        input[0]=pass; input[1]=lane; input[2]=slice;
        input[3]=mem.length; input[4]=t; input[5]=typeId;

        int done = 0, ctr = 0;
        while (done < segLen) {
            input[6] = ++ctr;
            fillBlock(zero, input, tmp,  false);
            fillBlock(zero, tmp,   addr, false);
            int n = Math.min(BLOCK_WORDS, segLen - done);
            System.arraycopy(addr, 0, result, done, n);
            done += n;
        }
        return result;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Block compression  G(prev, ref) → dest
    // ─────────────────────────────────────────────────────────────────────────

    private static void fillBlock(long[] prev, long[] ref, long[] dest, boolean xorMode) {
        long[] R = new long[BLOCK_WORDS];
        for (int i = 0; i < BLOCK_WORDS; i++) R[i] = prev[i] ^ ref[i];

        long[] tmp = R.clone();

        // 8 column rounds (16 consecutive words each)
        for (int col = 0; col < 8; col++) bRound(tmp, col * 16);
        // 8 row rounds (strided)
        for (int row = 0; row < 8; row++) bRoundStride(tmp, row);

        if (xorMode) { for (int i=0;i<BLOCK_WORDS;i++) dest[i] ^= tmp[i] ^ R[i]; }
        else         { for (int i=0;i<BLOCK_WORDS;i++) dest[i]  = tmp[i] ^ R[i]; }
    }

    private static void bRound(long[] v, int b) {
        bG(v,b+0,b+4,b+ 8,b+12); bG(v,b+1,b+5,b+ 9,b+13);
        bG(v,b+2,b+6,b+10,b+14); bG(v,b+3,b+7,b+11,b+15);
        bG(v,b+0,b+5,b+10,b+15); bG(v,b+1,b+6,b+11,b+12);
        bG(v,b+2,b+7,b+ 8,b+13); bG(v,b+3,b+4,b+ 9,b+14);
    }

    private static void bRoundStride(long[] v, int row) {
        int b=2*row;
        int a0=b,a1=b+1,a2=b+16,a3=b+17,a4=b+32,a5=b+33,a6=b+48,a7=b+49;
        int a8=b+64,a9=b+65,a10=b+80,a11=b+81,a12=b+96,a13=b+97,a14=b+112,a15=b+113;
        bG(v,a0,a4, a8,a12); bG(v,a1,a5, a9,a13);
        bG(v,a2,a6,a10,a14); bG(v,a3,a7,a11,a15);
        bG(v,a0,a5,a10,a15); bG(v,a1,a6,a11,a12);
        bG(v,a2,a7, a8,a13); bG(v,a3,a4, a9,a14);
    }

    /** Argon2 G mixing step with fBlaMka multiplication. */
    private static void bG(long[] v, int a, int b, int c, int d) {
        v[a]=mka(v[a],v[b]); v[d]=rotr(v[d]^v[a],32);
        v[c]=mka(v[c],v[d]); v[b]=rotr(v[b]^v[c],24);
        v[a]=mka(v[a],v[b]); v[d]=rotr(v[d]^v[a],16);
        v[c]=mka(v[c],v[d]); v[b]=rotr(v[b]^v[c],63);
    }

    /** fBlaMka: x + y + 2·lo32(x)·lo32(y)  (mod 2⁶⁴). */
    private static long mka(long x, long y) {
        return x + y + 2L * (x & 0xFFFFFFFFL) * (y & 0xFFFFFFFFL);
    }

    private static long rotr(long x, int n) { return (x>>>n)|(x<<(64-n)); }

    // ─────────────────────────────────────────────────────────────────────────
    //  Block ↔ byte conversion
    // ─────────────────────────────────────────────────────────────────────────

    static long[] bytesToBlock(byte[] bytes) {
        long[] b = new long[BLOCK_WORDS];
        for (int i = 0; i < BLOCK_WORDS; i++) b[i] = Blake2b.rle64(bytes, i*8);
        return b;
    }

    static byte[] blockToBytes(long[] block) {
        byte[] b = new byte[BLOCK_BYTES];
        for (int i = 0; i < BLOCK_WORDS; i++) Blake2b.wle64(b, i*8, block[i]);
        return b;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Utilities
    // ─────────────────────────────────────────────────────────────────────────

    private static void validate(byte[] pwd, byte[] salt, byte[] secret, byte[] ad,
                                 int t, int m, int p, int tau) {
        if (pwd    == null) throw new IllegalArgumentException("password is null");
        if (salt   == null) throw new IllegalArgumentException("salt is null");
        if (secret == null) throw new IllegalArgumentException("secret is null");
        if (ad     == null) throw new IllegalArgumentException("ad is null");
        if (t  < 1)         throw new IllegalArgumentException("timeCost >= 1");
        if (p  < 1)         throw new IllegalArgumentException("parallelism >= 1");
        if (m  < 8*p)       throw new IllegalArgumentException("memoryCost >= 8*parallelism");
        if (tau < 4)        throw new IllegalArgumentException("tagLength >= 4");
    }

    /** Constant-time equality — prevents timing oracles. */
    private static boolean constantTimeEq(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int d = 0;
        for (int i = 0; i < a.length; i++) d |= a[i] ^ b[i];
        return d == 0;
    }

    private static void copy(long[] dst, long[] src) { System.arraycopy(src,0,dst,0,BLOCK_WORDS); }
    private static void xorWords(long[] dst, long[] src) { for(int i=0;i<BLOCK_WORDS;i++) dst[i]^=src[i]; }

    /** Hex-encode a byte array (lowercase). */
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }
}