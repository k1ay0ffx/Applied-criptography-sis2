# Applied Cryptography — SIS2

## Project Structure

```
Applied-criptography-sis2/
│
├── argon2/
│   └── src/argon2/
│       ├── Argon2.java       ← Argon2d / Argon2i / Argon2id (RFC 9106)
│       └── Blake2b.java      ← BLAKE2b primitive (package-private)
│
├── sha512/
│   └── src/sha512/
│       └── SHA512.java       ← SHA-512 (FIPS 180-4)
│
├── sha256/
│   └── src/sha256/
│       └── Sha256.java       ← SHA-256 (FIPS 180-4)
│
├── hmac/
│   └── src/hmac/
│       └── Hmac.java         ← HMAC-SHA256 (RFC 2104)
│
├── pbkdf2/
│   └── src/pbkdf2/
│       └── Pbkdf2.java       ← PBKDF2-HMAC-SHA256 (RFC 8018)
│
├── hkdf/
│   └── src/hkdf/
│       └── Hkdf.java         ← HKDF-SHA256 (RFC 5869)
│
└── app_console/
    └── src/
        ├── appConsole/
        │   └── AppConsole.java   ← Interactive menu console
        └── mainLogic/
            └── Main.java         ← Entry point
```

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Java        | 17 +    |
| JDK         | OpenJDK or Oracle JDK |

No external dependencies — **zero Maven/Gradle required**.

---

## Compile

From the `app_console/` directory (or wherever all `src/` packages live together):

```bash
javac -d out -sourcepath src \
  src/sha256/Sha256.java \
  src/sha512/SHA512.java \
  src/hmac/Hmac.java \
  src/pbkdf2/Pbkdf2.java \
  src/hkdf/Hkdf.java \
  src/argon2/Blake2b.java \
  src/argon2/Argon2.java \
  src/appConsole/AppConsole.java \
  src/mainLogic/Main.java
```

> **Windows:** replace `\` with `^` (cmd) or use PowerShell with backticks.

---

## Run

```bash
java -cp out mainLogic.Main
```

You will see the main menu:

```
╔══════════════════════════════════════════════════════╗
║       Applied Cryptography — SIS2 Project            ║
║  SHA-256 · SHA-512 · HMAC · PBKDF2 · HKDF · Argon2   ║
╚══════════════════════════════════════════════════════╝

══════════════════════ MAIN MENU ══════════════════════
  1. Hashing Tool          (SHA-256 / SHA-512)
  2. HMAC Tool             (HMAC-SHA256)
  3. Password Manager      (PBKDF2 / Argon2id)
  4. Key Derivation Tool   (PBKDF2 / HKDF)
  5. File Integrity Checker
  6. Test Vectors          (SHA-256, HMAC, PBKDF2, SHA-512)
  7. Functional Demos      (Avalanche, Collision, …)
  8. Performance Benchmarks
  9. Exit
═══════════════════════════════════════════════════════
```

---

## Features

### 1 — Hashing Tool
- Hash any text or file with **SHA-256** or **SHA-512**
- Compare two hashes side-by-side
- **Educational mode**: shows internal state (a,e values) after every 16 rounds

### 2 — HMAC Tool
- Generate HMAC-SHA256 tag from text or file
- Key input as plain text or hex string
- Constant-time tag verification (prevents timing attacks)

### 3 — Password Manager
- Store passwords with **PBKDF2** (100,000 iterations, random 16-byte salt)
- Store passwords with **Argon2id** (t=3, m=64 MB)
- Verify passwords against stored hashes
- File-based storage in `password_store.json`

### 4 — Key Derivation Tool
- **PBKDF2**: configure password, salt, iterations, output length
- **HKDF**: configure IKM, salt, info string, output length (up to 8160 bytes)

### 5 — File Integrity Checker
- Hash a single file (SHA-256)
- Create a **manifest file** (SHA-256 hash per file in a directory)
- Verify directory against manifest — detects tampered and missing files

### 6 — Test Vectors
| Suite | Source |
|-------|--------|
| SHA-256 | NIST FIPS 180-4 |
| SHA-512 | NIST FIPS 180-4 |
| HMAC-SHA256 | RFC 4231 |
| PBKDF2-HMAC-SHA256 | RFC 6070 / RFC 7914 |

### 7 — Functional Demos
1. **Collision resistance** — unique inputs → unique hashes
2. **Avalanche effect** — 1-bit input change → ~50% output bits change
3. **File integrity** — detect single-character file modification
4. **HMAC verification** — valid tag accepted, tampered/wrong-key rejected
5. **Password storage** — deterministic PBKDF2 with same salt, rejection with wrong password
6. **Different salts** — same password, different salts → different derived keys

### 8 — Performance Benchmarks
- SHA-256 and SHA-512 throughput (MB/s)
- HMAC-SHA256 throughput (MB/s)
- PBKDF2 time for 100,000 iterations
- File hashing at 1 KB / 64 KB / 1 MB / 10 MB
- Argon2id timing (t=3, m=64 MB)

---

## Git Branch Strategy

| Branch | Contents |
|--------|----------|
| `sha512-impl`  | `sha512/` module only |
| `argon2-impl`  | `argon2/` module only |
| `main`         | All modules + `app_console/` |

---

## Cryptographic Specifications

| Algorithm | Standard | Key size / Output |
|-----------|----------|-------------------|
| SHA-256   | FIPS 180-4 | 256-bit digest |
| SHA-512   | FIPS 180-4 | 512-bit digest |
| BLAKE2b   | RFC 7693   | 1–512-bit digest |
| HMAC-SHA256 | RFC 2104 | 256-bit tag |
| PBKDF2-HMAC-SHA256 | RFC 8018 | Variable |
| HKDF-SHA256 | RFC 5869 | Up to 8160 bytes |
| Argon2id  | RFC 9106   | Variable |
:
---

## Security Notes

- All tag/hash comparisons use **constant-time equality** to prevent timing side-channels.
- PBKDF2 uses **100,000 iterations** minimum (NIST SP 800-132 recommendation).
- Argon2id parameters follow RFC 9106 §4 recommendations for interactive logins.
- Password store writes salts and hashes only — plaintext passwords are never persisted.
