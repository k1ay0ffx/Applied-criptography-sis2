package sha256;

import java.nio.charset.StandardCharsets;

public class SHA256 {

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

    private static final int[] H0 = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // ── Static core ───────────────────────────────────────────────────────────

    public static byte[] hash(byte[] message) {
        byte[] padded = padMessage(message);
        int[]  H      = H0.clone();
        for (int chunk = 0; chunk < padded.length; chunk += 64)
            processChunk(padded, chunk, H);
        return hashToBytes(H);
    }

    // ── Instance methods  (AppConsole: new SHA256() → sha256.hashHex(...)) ───

    /** Hash a UTF-8 string and return raw bytes. */
    public byte[] hash(String text) {
        return hash(text.getBytes(StandardCharsets.UTF_8));
    }

    /** Hash raw bytes and return lowercase hex. */
    public String hashHex(byte[] message) {
        return toHex(hash(message));
    }

    /** Hash a UTF-8 string and return lowercase hex. */
    public String hashHex(String text) {
        return toHex(hash(text));
    }

    // ── Educational mode

    public static String intermediateState(String text) {
        byte[] msg    = text.getBytes(StandardCharsets.UTF_8);
        byte[] padded = padMessage(msg);
        int[]  H      = H0.clone();
        StringBuilder sb = new StringBuilder();

        sb.append("=== SHA-256 Intermediate State ===\n");
        sb.append(String.format("Input: \"%s\"%n", text));
        sb.append(String.format("Length: %d bytes → padded to %d bytes (%d blocks)%n%n",
            msg.length, padded.length, padded.length / 64));

        for (int b = 0; b < padded.length / 64; b++) {
            sb.append(String.format("── Block %d ──%n", b));
            int[] W = new int[64];
            int base = b * 64;
            for (int i = 0;  i < 16; i++) W[i] = readBE32(padded, base + i * 4);
            for (int i = 16; i < 64; i++) {
                int s0 = rightRotate(W[i-15],7)^rightRotate(W[i-15],18)^(W[i-15]>>>3);
                int s1 = rightRotate(W[i-2],17) ^rightRotate(W[i-2],19) ^(W[i-2]>>>10);
                W[i] = W[i-16]+s0+W[i-7]+s1;
            }
            int a=H[0],bv=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
            sb.append(String.format("Init: a=%08x b=%08x c=%08x d=%08x%n",  a,bv,c,d));
            sb.append(String.format("      e=%08x f=%08x g=%08x h=%08x%n",  e,f,g,h));
            for (int i = 0; i < 64; i++) {
                int S1=rightRotate(e,6)^rightRotate(e,11)^rightRotate(e,25);
                int ch=(e&f)^(~e&g);
                int t1=h+S1+ch+K[i]+W[i];
                int S0=rightRotate(a,2)^rightRotate(a,13)^rightRotate(a,22);
                int maj=(a&bv)^(a&c)^(bv&c);
                int t2=S0+maj;
                h=g; g=f; f=e; e=d+t1; d=c; c=bv; bv=a; a=t1+t2;
                if ((i+1) % 16 == 0)
                    sb.append(String.format("  Round %2d: a=%08x  e=%08x%n", i+1, a, e));
            }
            H[0]+=a; H[1]+=bv; H[2]+=c; H[3]+=d;
            H[4]+=e; H[5]+=f;  H[6]+=g; H[7]+=h;
        }
        sb.append("\nFinal: ").append(toHex(hashToBytes(H))).append("\n");
        return sb.toString();
    }

    // ── Padding ───────────────────────────────────────────────────────────────

    private static byte[] padMessage(byte[] message) {
        long bitLen = (long) message.length * 8;
        int padLen  = 64 - ((message.length + 9) % 64);
        if (padLen == 64) padLen = 0;
        int total = message.length + 1 + padLen + 8;
        byte[] padded = new byte[total];
        System.arraycopy(message, 0, padded, 0, message.length);
        padded[message.length] = (byte) 0x80;
        for (int i = 0; i < 8; i++)
            padded[total - 8 + i] = (byte)(bitLen >>> (56 - i * 8));
        return padded;
    }

    // ── Compression ───────────────────────────────────────────────────────────

    private static void processChunk(byte[] msg, int offset, int[] H) {
        int[] W = new int[64];
        for (int t = 0; t < 16; t++) W[t] = readBE32(msg, offset + t * 4);
        for (int t = 16; t < 64; t++) {
            int s0 = rightRotate(W[t-15],7) ^ rightRotate(W[t-15],18) ^ (W[t-15]>>>3);
            int s1 = rightRotate(W[t-2],17) ^ rightRotate(W[t-2],19)  ^ (W[t-2]>>>10);
            W[t] = W[t-16]+s0+W[t-7]+s1;
        }
        int a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
        for (int t = 0; t < 64; t++) {
            int S1=rightRotate(e,6)^rightRotate(e,11)^rightRotate(e,25);
            int ch=(e&f)^(~e&g);
            int t1=h+S1+ch+K[t]+W[t];
            int S0=rightRotate(a,2)^rightRotate(a,13)^rightRotate(a,22);
            int maj=(a&b)^(a&c)^(b&c);
            int t2=S0+maj;
            h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d;
        H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static int rightRotate(int v, int n) { return (v>>>n)|(v<<(32-n)); }

    private static int readBE32(byte[] b, int o) {
        return ((b[o]&0xFF)<<24)|((b[o+1]&0xFF)<<16)|((b[o+2]&0xFF)<<8)|(b[o+3]&0xFF);
    }

    private static byte[] hashToBytes(int[] H) {
        byte[] out = new byte[32];
        for (int i = 0; i < 8; i++) {
            out[i*4]=(byte)(H[i]>>>24); out[i*4+1]=(byte)(H[i]>>>16);
            out[i*4+2]=(byte)(H[i]>>>8); out[i*4+3]=(byte)H[i];
        }
        return out;
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }

    public static String hashString(String input) {
        return toHex(hash(input.getBytes(StandardCharsets.UTF_8)));
    }
}