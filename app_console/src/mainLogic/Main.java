package mainLogic;

import appConsole.AppConsole;

/**
 * Main entry point for the Applied Cryptography console application.
 *
 * Compile (from project root):
 *   javac -d out -sourcepath src \
 *     src/sha256/Sha256.java \
 *     src/sha512/SHA512.java \
 *     src/hmac/Hmac.java \
 *     src/pbkdf2/Pbkdf2.java \
 *     src/hkdf/Hkdf.java \
 *     src/argon2/Blake2b.java \
 *     src/argon2/Argon2.java \
 *     src/appConsole/AppConsole.java \
 *     src/mainLogic/Main.java
 *
 * Run:
 *   java -cp out mainLogic.Main
 */
public class Main {
    public static void main(String[] args) {
        new AppConsole().run();
    }
}