package appConsole;

import sha256.SHA256;
import sha512.SHA512;
import hmac.HMAC;
import pbkdf2.PBKDF2;
import hkdf.HKDF;
import argon2.Argon2;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class AppConsole {

    private final Scanner    sc      = new Scanner(System.in, "UTF-8");
    private final SHA256     sha256  = new SHA256();
    private final SHA512     sha512  = new SHA512();
    private final HMAC       hmac    = new HMAC();
    private final PBKDF2     pbkdf2  = new PBKDF2();
    private final HKDF       hkdf    = new HKDF();
    private final CryptoPRNG rng     = new CryptoPRNG();

    private static final String DB_FILE = "password_store.json";

    // ── Entry point ───────────────────────────────────────────────────────────

    public void run() {
        banner();
        while (true) {
            mainMenu();
            int choice = readInt("Select option", 1, 9);
            switch (choice) {
                case 1 -> hashingTool();
                case 2 -> hmacTool();
                case 3 -> passwordManager();
                case 4 -> keyDerivationTool();
                case 5 -> fileIntegrityChecker();
                case 6 -> testVectors();
                case 7 -> functionalDemos();
                case 8 -> performanceBenchmarks();
                case 9 -> { System.out.println("\nGoodbye!"); return; }
            }
        }
    }

    // ── 1. Hashing Tool ───────────────────────────────────────────────────────

    private void hashingTool() {
        section("HASHING TOOL");
        System.out.println("  1. Hash text (SHA-256)");
        System.out.println("  2. Hash text (SHA-512)");
        System.out.println("  3. Hash file (SHA-256)");
        System.out.println("  4. Hash file (SHA-512)");
        System.out.println("  5. Compare two hashes");
        System.out.println("  6. Educational mode (SHA-256 intermediate states)");
        int c = readInt("Select", 1, 6);

        switch (c) {
            case 1 -> {
                String txt = readLine("Enter text");
                System.out.println("SHA-256: " + sha256.hashHex(txt));
            }
            case 2 -> {
                String txt = readLine("Enter text");
                System.out.println("SHA-512: " + sha512.hashHex(txt));
            }
            case 3 -> hashFile(readLine("Enter file path"), false);
            case 4 -> hashFile(readLine("Enter file path"), true);
            case 5 -> {
                String h1 = readLine("Enter first hash (hex)").trim().toLowerCase();
                String h2 = readLine("Enter second hash (hex)").trim().toLowerCase();
                if (h1.equals(h2)) System.out.println("✓ Hashes MATCH");
                else { System.out.println("✗ Hashes DO NOT match"); printDiff(h1, h2); }
            }
            // FIX: was SHA256.intermediateState — correct, it IS static
            case 6 -> System.out.println(SHA256.intermediateState(readLine("Enter text")));
        }
    }

    private void hashFile(String path, boolean use512) {
        try {
            byte[] data = Files.readAllBytes(Path.of(path));
            String h    = use512 ? sha512.hashHex(data) : sha256.hashHex(data);
            System.out.printf("%s (%s): %s%n", use512 ? "SHA-512" : "SHA-256", path, h);
        } catch (IOException e) { System.out.println("Error: " + e.getMessage()); }
    }

    // ── 2. HMAC Tool ──────────────────────────────────────────────────────────

    private void hmacTool() {
        section("HMAC TOOL (HMAC-SHA256)");
        System.out.println("  1. Generate HMAC tag");
        System.out.println("  2. Verify HMAC tag");
        System.out.println("  3. HMAC on file");
        int c = readInt("Select", 1, 3);

        switch (c) {
            case 1 -> {
                byte[] key = readKeyBytes();
                byte[] msg = readLine("Enter message").getBytes(StandardCharsets.UTF_8);
                System.out.println("HMAC-SHA256: " + hmac.computeHex(key, msg));
            }
            case 2 -> {
                byte[] key      = readKeyBytes();
                byte[] msg      = readLine("Enter message").getBytes(StandardCharsets.UTF_8);
                String expected = readLine("Enter expected tag (hex)").trim();
                System.out.println(hmac.verifyHex(key, msg, expected) ? "✓ Tag VALID" : "✗ Tag INVALID");
            }
            case 3 -> {
                byte[] key  = readKeyBytes();
                String path = readLine("Enter file path");
                try {
                    byte[] data = Files.readAllBytes(Path.of(path));
                    System.out.printf("HMAC-SHA256 (%s): %s%n", path, hmac.computeHex(key, data));
                } catch (IOException e) { System.out.println("Error: " + e.getMessage()); }
            }
        }
    }

    // ── 3. Password Manager ───────────────────────────────────────────────────

    private void passwordManager() {
        section("PASSWORD MANAGER");
        System.out.println("  1. Store new password  (PBKDF2)");
        System.out.println("  2. Verify password     (PBKDF2)");
        System.out.println("  3. Store new password  (Argon2id)");
        System.out.println("  4. Verify password     (Argon2id)");
        System.out.println("  5. List stored usernames");
        int c = readInt("Select", 1, 5);
        switch (c) {
            case 1 -> storePassword(false);
            case 2 -> verifyPassword(false);
            case 3 -> storePassword(true);
            case 4 -> verifyPassword(true);
            case 5 -> listUsers();
        }
    }

    private void storePassword(boolean useArgon2) {
        String user = readLine("Username");
        String pass = readLine("Password");
        String entry;

        if (useArgon2) {
            byte[] salt = new byte[16]; rng.nextBytes(salt);
            String encoded = Argon2.hashEncoded(Argon2.Type.ARGON2ID,
                pass.getBytes(StandardCharsets.UTF_8), salt, 3, 65536, 1, 32);
            entry = String.format("{\"user\":\"%s\",\"algo\":\"argon2id\",\"hash\":\"%s\"}%n",
                user, encoded);
        } else {
            byte[] salt = new byte[16]; rng.nextBytes(salt);
            // FIX: PBKDF2.derive is static, 5-arg — keep consistent
            byte[] dk = PBKDF2.derive(pass.getBytes(StandardCharsets.UTF_8),
                                       salt, 100_000, 32, PBKDF2.SHA256);
            entry = String.format(
                "{\"user\":\"%s\",\"algo\":\"pbkdf2\",\"salt\":\"%s\",\"hash\":\"%s\"}%n",
                // FIX: was Pbkdf2.toHex (wrong name) → PBKDF2.toHex
                user, PBKDF2.toHex(salt), PBKDF2.toHex(dk));
        }

        try (FileWriter fw = new FileWriter(DB_FILE, true)) {
            fw.write(entry);
            System.out.println("✓ Password stored for user: " + user);
        } catch (IOException e) { System.out.println("Error: " + e.getMessage()); }
    }

    private void verifyPassword(boolean useArgon2) {
        String user = readLine("Username");
        String pass = readLine("Password");
        Map<String, String> rec = findUser(user);
        if (rec == null) { System.out.println("User not found."); return; }

        String  algo = rec.getOrDefault("algo", "pbkdf2");
        boolean ok;

        if ("argon2id".equals(algo)) {
            ok = Argon2.verify(rec.get("hash"), pass.getBytes(StandardCharsets.UTF_8));
        } else {
            // FIX: was Hmac.fromHex (wrong name) → HMAC.fromHex
            byte[] salt     = HMAC.fromHex(rec.get("salt"));
            byte[] stored   = HMAC.fromHex(rec.get("hash"));
            byte[] computed = PBKDF2.derive(pass.getBytes(StandardCharsets.UTF_8),
                                             salt, 100_000, 32, PBKDF2.SHA256);
            ok = Arrays.equals(stored, computed);
        }
        System.out.println(ok ? "✓ Password CORRECT" : "✗ Password WRONG");
    }

    private void listUsers() {
        File f = new File(DB_FILE);
        if (!f.exists()) { System.out.println("No entries stored yet."); return; }
        System.out.println("Stored users:");
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                String user = extractField(line, "user");
                String algo = extractField(line, "algo");
                if (user != null) System.out.printf("  %s  [%s]%n", user, algo);
            }
        } catch (IOException e) { System.out.println("Error: " + e.getMessage()); }
    }

    // ── 4. Key Derivation Tool ────────────────────────────────────────────────

    private void keyDerivationTool() {
        section("KEY DERIVATION TOOL");
        System.out.println("  1. PBKDF2-HMAC-SHA256");
        System.out.println("  2. HKDF-SHA256");
        int c = readInt("Select", 1, 2);

        if (c == 1) {
            String pwd  = readLine("Password");
            String salt = readLine("Salt (text)");
            int    iter = readInt("Iterations", 1, Integer.MAX_VALUE);
            int    len  = readInt("Output length (bytes)", 1, 1024);
            // FIX: was pbkdf2.deriveHex — instance method now exists in PBKDF2
            System.out.println("Derived key: " + pbkdf2.deriveHex(pwd, salt, iter, len));
        } else {
            String ikm  = readLine("Input key material (text)");
            String salt = readLine("Salt (text, or press Enter for default)");
            String info = readLine("Info / context label");
            int    len  = readInt("Output length (bytes)", 1, 8160);
            byte[] saltB = salt.isEmpty() ? new byte[0] : salt.getBytes(StandardCharsets.UTF_8);
            // FIX: was hkdf.deriveKeyHex — instance method now exists in HKDF
            String okm = hkdf.deriveKeyHex(
                ikm.getBytes(StandardCharsets.UTF_8),
                saltB,
                info.getBytes(StandardCharsets.UTF_8),
                len);
            System.out.println("OKM: " + okm);
        }
    }

    // ── 5. File Integrity Checker ─────────────────────────────────────────────

    private void fileIntegrityChecker() {
        section("FILE INTEGRITY CHECKER");
        System.out.println("  1. Hash a single file");
        System.out.println("  2. Create manifest for a directory");
        System.out.println("  3. Verify files against manifest");
        int c = readInt("Select", 1, 3);
        switch (c) {
            case 1 -> hashFile(readLine("File path"), false);
            case 2 -> createManifest();
            case 3 -> verifyManifest();
        }
    }

    private void createManifest() {
        String dir     = readLine("Directory path");
        String outFile = readLine("Manifest output file (e.g. manifest.txt)");
        try {
            List<String> lines = new ArrayList<>();
            Files.walk(Path.of(dir)).filter(Files::isRegularFile).forEach(p -> {
                try {
                    lines.add(sha256.hashHex(Files.readAllBytes(p)) + "  " + p);
                } catch (IOException ignored) {}
            });
            Files.write(Path.of(outFile), lines);
            System.out.printf("✓ Manifest written (%d files): %s%n", lines.size(), outFile);
        } catch (IOException e) { System.out.println("Error: " + e.getMessage()); }
    }

    private void verifyManifest() {
        String manifest = readLine("Manifest file path");
        int ok = 0, tampered = 0, missing = 0;
        try {
            for (String line : Files.readAllLines(Path.of(manifest))) {
                if (line.isBlank()) continue;
                String[] parts = line.split("  ", 2);
                if (parts.length < 2) continue;
                String expected = parts[0].trim();
                Path   p        = Path.of(parts[1].trim());
                if (!Files.exists(p)) { System.out.println("  MISSING: " + p); missing++; }
                else {
                    String actual = sha256.hashHex(Files.readAllBytes(p));
                    if (actual.equals(expected)) ok++;
                    else { System.out.println("  TAMPERED: " + p); tampered++; }
                }
            }
            System.out.printf("%nSummary: %d OK | %d tampered | %d missing%n", ok, tampered, missing);
        } catch (IOException e) { System.out.println("Error: " + e.getMessage()); }
    }

    // ── 6. Test Vectors ───────────────────────────────────────────────────────

    private void testVectors() {
        section("TEST VECTORS");
        System.out.println("  1. SHA-256 NIST test vectors");
        System.out.println("  2. HMAC-SHA256 RFC 4231 test vectors");
        System.out.println("  3. PBKDF2 RFC 6070 test vectors");
        System.out.println("  4. SHA-512 NIST test vectors");
        System.out.println("  5. Run all");
        int c = readInt("Select", 1, 5);
        if (c == 1 || c == 5) runSHA256Vectors();
        if (c == 2 || c == 5) runHMACVectors();
        if (c == 3 || c == 5) runPBKDF2Vectors();
        if (c == 4 || c == 5) runSHA512Vectors();
    }

    private void runSHA256Vectors() {
        System.out.println("\n── SHA-256 Test Vectors (NIST) ──");
        // FIX: was sha256.hashHex — instance method now exists
        check("SHA256-1 (\"abc\")",
            sha256.hashHex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        check("SHA256-2 (empty)",
            sha256.hashHex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        check("SHA256-3 (448-bit)",
            sha256.hashHex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        byte[] million = new byte[1_000_000]; Arrays.fill(million, (byte)'a');
        check("SHA256-4 (1M × 'a')",
            sha256.hashHex(million),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    private void runHMACVectors() {
        System.out.println("\n── HMAC-SHA256 Test Vectors (RFC 4231) ──");
        // FIX: was Hmac.fromHex → HMAC.fromHex
        byte[] k1 = HMAC.fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] m1 = "Hi There".getBytes(StandardCharsets.UTF_8);
        // FIX: was hmac.computeHex — instance method now exists
        check("HMAC-1", hmac.computeHex(k1, m1),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

        byte[] k2 = "Jefe".getBytes(StandardCharsets.UTF_8);
        byte[] m2 = "what do ya want for nothing?".getBytes(StandardCharsets.UTF_8);
        check("HMAC-2", hmac.computeHex(k2, m2),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964a72424");

        byte[] k3 = HMAC.fromHex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaa");
        byte[] m3 = "Test Using Larger Than Block-Size Key - Hash Key First"
                        .getBytes(StandardCharsets.UTF_8);
        check("HMAC-3 (large key)", hmac.computeHex(k3, m3),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    private void runPBKDF2Vectors() {
        System.out.println("\n── PBKDF2-HMAC-SHA256 Test Vectors ──");
        // FIX: was pbkdf2.deriveHex — instance method now exists
        check("PBKDF2-1 (iter=1, len=20)",
            pbkdf2.deriveHex("password", "salt", 1, 20),
            "120fb6cffccd202497978ad05fc7f1dcbf5a");
        check("PBKDF2-2 (iter=2, len=20)",
            pbkdf2.deriveHex("password", "salt", 2, 20),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8e");
        check("PBKDF2-3 (iter=4096, len=20)",
            pbkdf2.deriveHex("password", "salt", 4096, 20),
            "c5e478d59288c841aa530db6845c4c8d962893a0");
    }

    private void runSHA512Vectors() {
        System.out.println("\n── SHA-512 Test Vectors (NIST) ──");
        check("SHA512-1 (\"abc\")",
            sha512.hashHex("abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        check("SHA512-2 (empty)",
            sha512.hashHex(""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        check("SHA512-3 (448-bit)",
            sha512.hashHex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335" +
            "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
    }

    // ── 7. Functional Demos ───────────────────────────────────────────────────

    private void functionalDemos() {
        section("FUNCTIONAL DEMOS");
        System.out.println("  1.  Collision resistance");
        System.out.println("  2.  Avalanche effect");
        System.out.println("  3.  File integrity demo");
        System.out.println("  4.  HMAC verification demo");
        System.out.println("  5.  Password storage demo");
        System.out.println("  6.  Different salts → different keys");
        int c = readInt("Select", 1, 6);
        switch (c) {
            case 1 -> demoCollision();
            case 2 -> demoAvalanche();
            case 3 -> demoFileIntegrity();
            case 4 -> demoHmacVerify();
            case 5 -> demoPasswordStorage();
            case 6 -> demoDifferentSalts();
        }
    }

    private void demoCollision() {
        System.out.println("\n── Collision Resistance ──");
        String[] inputs = {"hello","hello!","Hello","HELLO","hello world","hell0"};
        System.out.printf("%-20s  %s%n", "Input", "SHA-256");
        System.out.println("-".repeat(75));
        for (String s : inputs)
            System.out.printf("%-20s  %s%n", "\""+s+"\"", sha256.hashHex(s));
    }

    private void demoAvalanche() {
        System.out.println("\n── Avalanche Effect ──");
        String base    = "hello";
        // FIX: sha256.hash(String) — instance method now exists
        byte[] hBase   = sha256.hash(base);
        byte[] altered = base.getBytes(StandardCharsets.UTF_8).clone();
        altered[0] ^= 0x01;
        byte[] hAlt    = SHA256.hash(altered);   // static call also fine

        int diffBits = 0;
        for (int i = 0; i < 32; i++)
            diffBits += Integer.bitCount((hBase[i] & 0xFF) ^ (hAlt[i] & 0xFF));

        System.out.printf("Original : \"%s\"%n", base);
        System.out.printf("Modified : (1 bit flipped in first byte)%n");
        // FIX: was Sha256.toHex (wrong case) → SHA256.toHex
        System.out.printf("Hash A   : %s%n", SHA256.toHex(hBase));
        System.out.printf("Hash B   : %s%n", SHA256.toHex(hAlt));
        System.out.printf("Bits changed: %d / 256  (%.1f%%)%n", diffBits, 100.0*diffBits/256.0);
    }

    private void demoFileIntegrity() {
        System.out.println("\n── File Integrity Demo ──");
        try {
            Path tmp = Files.createTempFile("integrity_demo", ".txt");
            Files.writeString(tmp, "This is the original file content.");
            String h1 = sha256.hashHex(Files.readAllBytes(tmp));
            System.out.println("Original hash: " + h1);
            Files.writeString(tmp, "This is the original file content!");
            String h2 = sha256.hashHex(Files.readAllBytes(tmp));
            System.out.println("Tampered hash: " + h2);
            System.out.println(h1.equals(h2) ? "✗ SAME (bug!)" : "✓ Tampering DETECTED");
            Files.delete(tmp);
        } catch (IOException e) { System.out.println("Error: " + e.getMessage()); }
    }

    private void demoHmacVerify() {
        System.out.println("\n── HMAC Verification Demo ──");
        byte[] key = "secret-key".getBytes(StandardCharsets.UTF_8);
        byte[] msg = "transfer $100 to Alice".getBytes(StandardCharsets.UTF_8);
        // FIX: was hmac.computeHex — instance method now exists
        String tag = hmac.computeHex(key, msg);
        System.out.println("Message : " + new String(msg));
        System.out.println("HMAC tag: " + tag);
        // FIX: was hmac.verifyHex — instance method now exists
        System.out.println("Verify original  : " + (hmac.verifyHex(key, msg, tag) ? "✓ VALID" : "✗ INVALID"));
        byte[] tampered = "transfer $900 to Alice".getBytes(StandardCharsets.UTF_8);
        System.out.println("Verify tampered  : " + (hmac.verifyHex(key, tampered, tag) ? "✗ ACCEPTED" : "✓ REJECTED"));
        byte[] wrongKey = "wrong-key".getBytes(StandardCharsets.UTF_8);
        System.out.println("Verify wrong key : " + (hmac.verifyHex(wrongKey, msg, tag) ? "✗ ACCEPTED" : "✓ REJECTED"));
    }

    private void demoPasswordStorage() {
        System.out.println("\n── Password Storage Demo ──");
        String password = "MySecureP@ss!";
        byte[] salt1 = new byte[16]; rng.nextBytes(salt1);
        // FIX: was pbkdf2.derive(4 args) → use 5-arg static or 4-arg instance
        byte[] dk1 = pbkdf2.derive(password.getBytes(StandardCharsets.UTF_8), salt1, 10_000, 32);
        byte[] dk2 = pbkdf2.derive(password.getBytes(StandardCharsets.UTF_8), salt1, 10_000, 32);
        System.out.println("Password  : " + password);
        // FIX: was Pbkdf2.toHex (wrong case) → PBKDF2.toHex
        System.out.println("Run 1 DK  : " + PBKDF2.toHex(dk1));
        System.out.println("Run 2 DK  : " + PBKDF2.toHex(dk2));
        System.out.println("Match     : " + Arrays.equals(dk1, dk2));
        byte[] dkWrong = pbkdf2.derive("WrongPass".getBytes(StandardCharsets.UTF_8), salt1, 10_000, 32);
        System.out.println("Wrong DK  : " + PBKDF2.toHex(dkWrong));
        System.out.println("Reject    : " + !Arrays.equals(dk1, dkWrong));
    }

    private void demoDifferentSalts() {
        System.out.println("\n── Different Salts → Different Keys ──");
        String password = "samePassword";
        for (int i = 0; i < 4; i++) {
            byte[] salt = new byte[16]; rng.nextBytes(salt);
            byte[] dk   = pbkdf2.derive(password.getBytes(StandardCharsets.UTF_8), salt, 1000, 16);
            System.out.printf("Salt %d: %s → DK: %s%n", i+1, PBKDF2.toHex(salt), PBKDF2.toHex(dk));
        }
    }

    // ── 8. Performance Benchmarks ─────────────────────────────────────────────

    private void performanceBenchmarks() {
        section("PERFORMANCE BENCHMARKS");

        byte[] data1MB = new byte[1 << 20]; rng.nextBytes(data1MB);

        long t = System.nanoTime();
        for (int i = 0; i < 10; i++) SHA256.hash(data1MB);
        System.out.printf("SHA-256 speed      : %.1f MB/s%n",
            10.0 / ((System.nanoTime() - t) / 1e9));

        t = System.nanoTime();
        for (int i = 0; i < 10; i++) sha512.hash(data1MB);
        System.out.printf("SHA-512 speed      : %.1f MB/s%n",
            10.0 / ((System.nanoTime() - t) / 1e9));

        byte[] key = "benchmark-key".getBytes(StandardCharsets.UTF_8);
        t = System.nanoTime();
        for (int i = 0; i < 10; i++) hmac.compute(key, data1MB);
        System.out.printf("HMAC-SHA256 speed  : %.1f MB/s%n",
            10.0 / ((System.nanoTime() - t) / 1e9));

        byte[] pwd  = "benchmarkpwd".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "benchmarksalt".getBytes(StandardCharsets.UTF_8);
        System.out.print("PBKDF2 (100k iter) : ");
        t = System.nanoTime();
        // FIX: was pbkdf2.derive(4 args) → instance 4-arg overload
        pbkdf2.derive(pwd, salt, 100_000, 32);
        System.out.printf("%.2f ms%n", (System.nanoTime() - t) / 1e6);

        System.out.println("\nFile hashing (SHA-256):");
        for (int kb : new int[]{1, 64, 1024, 10240}) {
            byte[] buf = new byte[kb * 1024];
            t = System.nanoTime();
            for (int i = 0; i < 5; i++) SHA256.hash(buf);
            double elapsed = (System.nanoTime() - t) / 5e9;
            System.out.printf("  %6d KB : %.3f ms  (%.1f MB/s)%n",
                kb, elapsed*1000, (kb/1024.0)/elapsed);
        }

        byte[] apwd  = "argon2bench".getBytes(StandardCharsets.UTF_8);
        byte[] asalt = "argon2salt12".getBytes(StandardCharsets.UTF_8);
        System.out.print("Argon2id (t=3,m=64MB,p=1): ");
        t = System.nanoTime();
        Argon2.hash(Argon2.Type.ARGON2ID, apwd, asalt, 3, 65536, 1, 32);
        System.out.printf("%.2f ms%n", (System.nanoTime() - t) / 1e6);
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private void banner() {
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║       Applied Cryptography — SIS2                    ║");
        System.out.println("║  SHA-256 · SHA-512 · HMAC · PBKDF2 · HKDF · Argon2   ║");
        System.out.println("╚══════════════════════════════════════════════════════╝");
    }

    private void mainMenu() {
        System.out.println("\n══════════════════ MAIN MENU ══════════════════");
        System.out.println("  1. Hashing Tool          (SHA-256 / SHA-512)");
        System.out.println("  2. HMAC Tool             (HMAC-SHA256)");
        System.out.println("  3. Password Manager      (PBKDF2 / Argon2id)");
        System.out.println("  4. Key Derivation Tool   (PBKDF2 / HKDF)");
        System.out.println("  5. File Integrity Checker");
        System.out.println("  6. Test Vectors          (SHA-256, HMAC, PBKDF2, SHA-512)");
        System.out.println("  7. Functional Demos      (Avalanche, Collision, …)");
        System.out.println("  8. Performance Benchmarks");
        System.out.println("  9. Exit");
        System.out.println("═══════════════════════════════════════════════");
    }

    private void section(String t) {
        System.out.println("\n── " + t + " " + "─".repeat(Math.max(0, 50 - t.length())));
    }

    private int readInt(String prompt, int min, int max) {
        while (true) {
            System.out.print(prompt + " [" + min + "-" + max + "]: ");
            try {
                int v = Integer.parseInt(sc.nextLine().trim());
                if (v >= min && v <= max) return v;
            } catch (NumberFormatException ignored) {}
            System.out.println("  Enter a number between " + min + " and " + max);
        }
    }

    private String readLine(String prompt) {
        System.out.print(prompt + ": ");
        return sc.nextLine();
    }

    private byte[] readKeyBytes() {
        System.out.println("  Key format:  1) text  2) hex");
        int    fmt = readInt("  Format", 1, 2);
        String raw = readLine("  Enter key");
        // FIX: was Hmac.fromHex (wrong case) → HMAC.fromHex
        return (fmt == 2) ? HMAC.fromHex(raw) : raw.getBytes(StandardCharsets.UTF_8);
    }

    private void check(String label, String got, String expected) {
        boolean ok = got.equalsIgnoreCase(expected.replaceAll("\\s", ""));
        System.out.printf("  %-40s %s%n", label, ok ? "PASS ✓" : "FAIL ✗");
        if (!ok) {
            System.out.println("    expected: " + expected.toLowerCase().replaceAll("\\s",""));
            System.out.println("    got:      " + got.toLowerCase());
        }
    }

    private void printDiff(String h1, String h2) {
        for (int i = 0; i < Math.min(h1.length(), h2.length()); i++)
            if (h1.charAt(i) != h2.charAt(i))
                System.out.printf("  pos %3d: '%c' vs '%c'%n", i, h1.charAt(i), h2.charAt(i));
    }

    // ── JSON mini-parser ──────────────────────────────────────────────────────

    private Map<String, String> findUser(String user) {
        File f = new File(DB_FILE);
        if (!f.exists()) return null;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null)
                if (line.contains("\"" + user + "\"")) return parseJsonLine(line);
        } catch (IOException ignored) {}
        return null;
    }

    private Map<String, String> parseJsonLine(String line) {
        Map<String, String> map = new LinkedHashMap<>();
        for (String token : line.replaceAll("[{}]","").split(",(?=\\s*\")")) {
            String[] kv = token.split("\":\\s*\"", 2);
            if (kv.length == 2)
                map.put(kv[0].replaceAll("\"","").trim(), kv[1].replaceAll("\"","").trim());
        }
        return map;
    }

    private String extractField(String line, String field) {
        String key = "\"" + field + "\":\"";
        int s = line.indexOf(key);
        if (s < 0) return null;
        s += key.length();
        int e = line.indexOf("\"", s);
        return (e < 0) ? null : line.substring(s, e);
    }
}