package appConsole;

import sha256.SHA256;

/**
 * SHA-256 Counter-Mode PRNG — implemented from scratch.
 * NO java.security or any cryptographic library used.
 *
 * Design: CTR-DRBG-lite
 *   state = SHA-256( seed ‖ counter )
 *   Each call to nextBytes() generates blocks of 32 bytes and increments counter.
 *
 * Seed entropy sources (all from standard java.lang / java.io):
 *   • System.nanoTime()          — nanosecond wall clock
 *   • System.currentTimeMillis() — millisecond wall clock
 *   • Runtime.freeMemory()       — JVM heap state
 *   • Thread.currentThread().getId() — thread identifier
 *   • System.identityHashCode()  — object address bits
 *
 * Security note: Sufficient for generating random salts in this project.
 * For production use, seed with /dev/urandom or a hardware RNG.
 */
public final class CryptoPRNG {

    private final SHA256 sha   = new SHA256();
    private final byte[] seed  = new byte[32];   // 256-bit internal state
    private long         counter = 0L;

    // ── Constructor: gather entropy from the environment ──────────────────────

    public CryptoPRNG() {
        // Mix multiple low-level timing and runtime sources into the seed.
        // No single source is required to be perfectly random.
        long e1 = System.nanoTime();
        long e2 = System.currentTimeMillis();
        long e3 = Runtime.getRuntime().freeMemory();
        long e4 = Runtime.getRuntime().totalMemory();
        long e5 = Thread.currentThread().getId();
        long e6 = System.identityHashCode(this);
        long e7 = System.identityHashCode(sha);
        long e8 = System.nanoTime();   // second reading: captures time elapsed since e1

        // Pack into 64 bytes and hash them to produce the initial 32-byte state
        byte[] entropy = new byte[64];
        writeLong(entropy,  0, e1);
        writeLong(entropy,  8, e2);
        writeLong(entropy, 16, e3);
        writeLong(entropy, 24, e4);
        writeLong(entropy, 32, e5);
        writeLong(entropy, 40, e6);
        writeLong(entropy, 48, e7);
        writeLong(entropy, 56, e8);

        byte[] initial = sha.hash(entropy);
        System.arraycopy(initial, 0, seed, 0, 32);
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Fill {@code out} with pseudo-random bytes.
     *
     * @param out byte array to fill
     */
    public void nextBytes(byte[] out) {
        int pos = 0;
        while (pos < out.length) {
            // Generate one 32-byte block:  SHA-256( seed ‖ LE64(counter) )
            byte[] block = generateBlock();
            int toCopy = Math.min(32, out.length - pos);
            System.arraycopy(block, 0, out, pos, toCopy);
            pos += toCopy;
        }
        // Reseed after every output to provide forward secrecy:
        // new_seed = SHA-256( old_seed ‖ LE64(counter) )
        reseed();
    }

    /**
     * Return a new byte array of {@code length} pseudo-random bytes.
     */
    public byte[] nextBytes(int length) {
        byte[] out = new byte[length];
        nextBytes(out);
        return out;
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /** Produce one 32-byte output block and advance the counter. */
    private byte[] generateBlock() {
        byte[] input = new byte[40];                  // seed(32) + counter(8)
        System.arraycopy(seed, 0, input, 0, 32);
        writeLong(input, 32, counter);
        counter++;
        return sha.hash(input);
    }

    /** Update the internal seed (forward-secrecy / backtracking resistance). */
    private void reseed() {
        byte[] input = new byte[40];
        System.arraycopy(seed, 0, input, 0, 32);
        writeLong(input, 32, counter);
        counter++;
        byte[] newSeed = sha.hash(input);
        System.arraycopy(newSeed, 0, seed, 0, 32);
    }

    /** Write a 64-bit value as big-endian into buf at offset off. */
    private static void writeLong(byte[] buf, int off, long v) {
        for (int i = 7; i >= 0; i--) {
            buf[off + i] = (byte)(v & 0xFF);
            v >>>= 8;
        }
    }
}