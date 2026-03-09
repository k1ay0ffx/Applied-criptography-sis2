# HMAC (Hash-based Message Authentication Code) Guide

## What is HMAC?

HMAC is a cryptographic algorithm that provides **message authentication** and **integrity verification** using a hash function and a secret key.

**Key Properties:**
- ✅ Verifies message authenticity (sender has the secret key)
- ✅ Detects message tampering
- ✅ Based on standard hash functions (SHA-256, SHA-1, etc.)
- ✅ More secure than simple hash(key + message)
- ✅ Resistant to length extension attacks

---

## HMAC Algorithm (RFC 2104)

### Mathematical Definition

```
HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
```

Where:
- **K** = Secret key
- **m** = Message to authenticate
- **H** = Hash function (SHA-256, SHA-1, etc.)
- **K'** = Key adjusted to hash block size
- **ipad** = Inner padding (0x36 repeated)
- **opad** = Outer padding (0x5C repeated)
- **||** = Concatenation
- **⊕** = XOR operation

### Step-by-Step Process

#### Step 1: Prepare the Key

```
If len(K) > blockSize:
    K' = H(K) padded with zeros to blockSize
Else if len(K) < blockSize:
    K' = K padded with zeros to blockSize
Else:
    K' = K
```

**Example (SHA-256, blockSize = 64 bytes):**

```java
// Key: "secret" (6 bytes)
// Need to pad to 64 bytes

K' = [0x73, 0x65, 0x63, 0x72, 0x65, 0x74,  // "secret"
      0x00, 0x00, 0x00, ..., 0x00]          // 58 zeros
```

#### Step 2: Create Inner and Outer Keys

```
Inner Key = K' ⊕ ipad  (XOR each byte with 0x36)
Outer Key = K' ⊕ opad  (XOR each byte with 0x5C)
```

**Example:**

```
K'[0] = 0x73
ipad  = 0x36
Inner[0] = 0x73 ⊕ 0x36 = 0x45

K'[0] = 0x73
opad  = 0x5C
Outer[0] = 0x73 ⊕ 0x5C = 0x2F
```

**Why these specific values?**
- `ipad = 0x36 = 00110110` (binary)
- `opad = 0x5C = 01011100` (binary)
- Differ in exactly 2 bits for maximum avalanche effect
- Chosen to avoid specific cryptographic weaknesses

#### Step 3: Compute Inner Hash

```
innerHash = H((K' ⊕ ipad) || message)
```

**Visual:**

```
┌────────────────┬──────────┐
│ K' ⊕ ipad      │ message  │
│ (64 bytes)     │ (n bytes)│
└────────────────┴──────────┘
         │
         ▼
    Hash Function
         │
         ▼
   ┌─────────┐
   │innerHash│ (32 bytes for SHA-256)
   └─────────┘
```

#### Step 4: Compute Outer Hash

```
HMAC = H((K' ⊕ opad) || innerHash)
```

**Visual:**

```
┌────────────────┬───────────┐
│ K' ⊕ opad      │ innerHash │
│ (64 bytes)     │ (32 bytes)│
└────────────────┴───────────┘
         │
         ▼
    Hash Function
         │
         ▼
   ┌──────────┐
   │   HMAC   │ (32 bytes for SHA-256)
   └──────────┘
```

---

## Complete Example: HMAC-SHA256("secret", "message")

### Input
```
Key:     "secret" (6 bytes)
Message: "message" (7 bytes)
```

### Step 1: Prepare Key (K')

```
Original key: 73 65 63 72 65 74
Padded to 64 bytes:
73 65 63 72 65 74 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

### Step 2: Create Inner and Outer Keys

**Inner Key (K' ⊕ 0x36):**
```
Byte 0: 0x73 ⊕ 0x36 = 0x45
Byte 1: 0x65 ⊕ 0x36 = 0x53
Byte 2: 0x63 ⊕ 0x36 = 0x55
Byte 3: 0x72 ⊕ 0x36 = 0x44
Byte 4: 0x65 ⊕ 0x36 = 0x53
Byte 5: 0x74 ⊕ 0x36 = 0x42
Byte 6-63: 0x00 ⊕ 0x36 = 0x36

Result: 45 53 55 44 53 42 36 36 36 ... (58 more 0x36)
```

**Outer Key (K' ⊕ 0x5C):**
```
Byte 0: 0x73 ⊕ 0x5C = 0x2F
Byte 1: 0x65 ⊕ 0x5C = 0x39
Byte 2: 0x63 ⊕ 0x5C = 0x3F
Byte 3: 0x72 ⊕ 0x5C = 0x2E
Byte 4: 0x65 ⊕ 0x5C = 0x39
Byte 5: 0x74 ⊕ 0x5C = 0x28
Byte 6-63: 0x00 ⊕ 0x5C = 0x5C

Result: 2F 39 3F 2E 39 28 5C 5C 5C ... (58 more 0x5C)
```

### Step 3: Compute Inner Hash

```
Input to SHA-256:
[Inner Key (64 bytes)] || [Message (7 bytes)]
= [45 53 55 44 53 42 36 36 ...] || [6D 65 73 73 61 67 65]

innerHash = SHA256(input)
          = 8910a1e5b168dd05ef7c0b3e61d0b7b58fe45e0e8249e3c6e6e3c3e97b0e5c3a
          (example value)
```

### Step 4: Compute Outer Hash (Final HMAC)

```
Input to SHA-256:
[Outer Key (64 bytes)] || [innerHash (32 bytes)]
= [2F 39 3F 2E 39 28 5C 5C ...] || [89 10 a1 e5 ...]

HMAC = SHA256(input)
     = [final 32-byte HMAC value]
```

---

## Implementation Details

### Key Preparation Function

```java
private byte[] prepareKey(byte[] key, int blockSize) {
    byte[] keyPrime = new byte[blockSize];
    
    if (key.length > blockSize) {
        // If key too long, hash it first
        byte[] hashedKey = hashFunction.hash(key);
        System.arraycopy(hashedKey, 0, keyPrime, 0, hashedKey.length);
        // Rest padded with zeros
    } else {
        // If key shorter, just copy and pad
        System.arraycopy(key, 0, keyPrime, 0, key.length);
        // Rest padded with zeros
    }
    
    return keyPrime;
}
```

### XOR with Padding

```java
private byte[] xorWithPad(byte[] data, byte pad) {
    byte[] result = new byte[data.length];
    for (int i = 0; i < data.length; i++) {
        result[i] = (byte) (data[i] ^ pad);
    }
    return result;
}
```

### Main HMAC Computation

```java
public byte[] compute(byte[] key, byte[] message) {
    int blockSize = hashFunction.getBlockSize();
    
    // Step 1: Prepare key
    byte[] keyPrime = prepareKey(key, blockSize);
    
    // Step 2: Create padded keys
    byte[] innerKey = xorWithPad(keyPrime, IPAD);  // 0x36
    byte[] outerKey = xorWithPad(keyPrime, OPAD);  // 0x5C
    
    // Step 3: Inner hash
    byte[] innerInput = concatenate(innerKey, message);
    byte[] innerHash = hashFunction.hash(innerInput);
    
    // Step 4: Outer hash
    byte[] outerInput = concatenate(outerKey, innerHash);
    byte[] hmac = hashFunction.hash(outerInput);
    
    return hmac;
}
```

---

## Security Features

### 1. Protection Against Length Extension Attacks

**Problem with naive hash(key || message):**
```
If you know hash(key || message), you can compute hash(key || message || extra)
without knowing the key!
```

**HMAC Solution:**
- Uses two rounds of hashing
- The outer hash prevents extension attacks
- Attacker can't extend the inner hash without knowing the outer key

### 2. Constant-Time Comparison

**Why needed:**
Prevent timing attacks that could leak MAC information

```java
public static boolean secureCompare(byte[] a, byte[] b) {
    if (a.length != b.length) {
        return false;
    }
    
    int result = 0;
    for (int i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];  // Always check all bytes
    }
    
    return result == 0;
}
```

**Bad (timing attack vulnerable):**
```java
// DON'T DO THIS!
for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;  // Early exit leaks timing info
}
```

### 3. Key Size Recommendations

| Hash Function | Block Size | Output Size | Recommended Key Size |
|---------------|------------|-------------|---------------------|
| SHA-256       | 64 bytes   | 32 bytes    | 32+ bytes           |
| SHA-512       | 128 bytes  | 64 bytes    | 64+ bytes           |
| SHA-1         | 64 bytes   | 20 bytes    | 20+ bytes (deprecated) |

**Best Practice:** Use a key size equal to the hash output size

---

## Common Use Cases

### 1. API Request Signing

```java
// Client side
String apiKey = "secret_api_key";
String timestamp = String.valueOf(System.currentTimeMillis());
String endpoint = "/api/users/create";
String body = "{\"name\":\"John\"}";

String signatureBase = endpoint + "\n" + timestamp + "\n" + body;
byte[] signature = hmac.compute(apiKey.getBytes(), signatureBase.getBytes());

// Send request with headers:
// X-Timestamp: {timestamp}
// X-Signature: {hex(signature)}
```

```java
// Server side
String receivedSignature = request.getHeader("X-Signature");
byte[] expectedSignature = hmac.compute(apiKey.getBytes(), signatureBase.getBytes());

if (hmac.verify(apiKey.getBytes(), signatureBase.getBytes(), 
                fromHex(receivedSignature))) {
    // Request is authentic
} else {
    // Request is forged or tampered
}
```

### 2. Secure Cookie/Session Tokens

```java
String userId = "12345";
String timestamp = "1678901234";
String sessionData = userId + "|" + timestamp;

byte[] signature = hmac.compute(serverSecret.getBytes(), sessionData.getBytes());
String token = sessionData + "|" + toHex(signature);

// Cookie value: "12345|1678901234|a3b2c1d4e5f6..."
```

### 3. Webhook Verification (GitHub, Stripe, etc.)

```java
// GitHub webhook
String payload = request.getBody();
String githubSignature = request.getHeader("X-Hub-Signature-256");

byte[] expectedSignature = hmac.compute(
    webhookSecret.getBytes(), 
    payload.getBytes()
);

String expectedHex = "sha256=" + toHex(expectedSignature);

if (githubSignature.equals(expectedHex)) {
    // Webhook is from GitHub
    processWebhook(payload);
}
```

### 4. Password-Based Key Derivation (PBKDF2)

```java
public byte[] deriveKey(String password, String salt, int iterations) {
    byte[] derivedKey = password.getBytes();
    
    for (int i = 0; i < iterations; i++) {
        derivedKey = hmac.compute(salt.getBytes(), derivedKey);
    }
    
    return derivedKey;
}

// Usage
byte[] encryptionKey = deriveKey("user_password", "random_salt", 10000);
// Use this key for AES encryption
```

### 5. Message Integrity in Encrypted Communications

```java
// Encrypt-then-MAC pattern
byte[] ciphertext = aes.encrypt(plaintext);
byte[] mac = hmac.compute(macKey, ciphertext);

// Send: ciphertext || mac

// Verify MAC before decrypting
if (hmac.verify(macKey, receivedCiphertext, receivedMac)) {
    byte[] plaintext = aes.decrypt(receivedCiphertext);
} else {
    throw new SecurityException("Message tampered!");
}
```

---

## HMAC vs Other MACs

### HMAC vs Simple Hash

| Approach | Security |
|----------|----------|
| `hash(message)` | ✗ No authentication - anyone can compute |
| `hash(key + message)` | ✗ Vulnerable to length extension attacks |
| `hash(message + key)` | ✗ Vulnerable to collision attacks |
| `HMAC(key, message)` | ✓ Secure - resistant to known attacks |

### HMAC vs CMAC

| Feature | HMAC | CMAC |
|---------|------|------|
| Based on | Hash function | Block cipher |
| Speed | Fast | Slower |
| Key size | Flexible | Fixed (cipher key size) |
| Standardization | RFC 2104, FIPS 198 | NIST SP 800-38B |
| Common use | Most applications | When AES already used |

### HMAC vs Poly1305

| Feature | HMAC-SHA256 | Poly1305 |
|---------|-------------|----------|
| Speed | Moderate | Very fast |
| Security | 256-bit | 128-bit |
| Implementation | Easy | Requires careful impl. |
| Use case | General purpose | High-performance networking |

---

## RFC Test Vectors (RFC 4231)

### Test Case 1
```
Key:  0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
Data: "Hi There"
HMAC: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
```

### Test Case 2
```
Key:  "Jefe"
Data: "what do ya want for nothing?"
HMAC: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
```

### Test Case 3
```
Key:  0xaa repeated 20 times
Data: 0xdd repeated 50 times
HMAC: 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe
```

---

## Best Practices

### ✅ DO:
1. **Use HMAC for message authentication** - Don't roll your own MAC
2. **Use constant-time comparison** - Prevent timing attacks
3. **Use strong hash functions** - SHA-256 or SHA-512
4. **Generate random keys** - Use cryptographically secure RNG
5. **Keep keys secret** - Never expose in logs, URLs, or client-side code
6. **Use different keys** - Separate keys for encryption and MAC

### ✗ DON'T:
1. **Don't use MD5 or SHA-1** - These are cryptographically broken
2. **Don't truncate HMAC** - Use full output (unless following specific standard)
3. **Don't reuse keys** - Each purpose should have its own key
4. **Don't use short keys** - Minimum 128 bits, preferably match hash output
5. **Don't implement constant-time comparison incorrectly** - Use provided function
6. **Don't MAC-then-encrypt** - Use encrypt-then-MAC pattern

---

## Integration with AES

### Encrypt-then-MAC Pattern (Recommended)

```java
// Encryption
byte[] iv = generateRandomIV();
byte[] ciphertext = aes.encrypt(plaintext, iv);
byte[] dataToMac = concatenate(iv, ciphertext);
byte[] mac = hmac.compute(macKey, dataToMac);

// Package: iv || ciphertext || mac

// Decryption
byte[] receivedIv = extractIV(package);
byte[] receivedCiphertext = extractCiphertext(package);
byte[] receivedMac = extractMAC(package);

byte[] dataToVerify = concatenate(receivedIv, receivedCiphertext);
if (hmac.verify(macKey, dataToVerify, receivedMac)) {
    byte[] plaintext = aes.decrypt(receivedCiphertext, receivedIv);
    return plaintext;
} else {
    throw new SecurityException("MAC verification failed - message tampered!");
}
```

### Key Derivation for Encryption + MAC

```java
// Derive two keys from master key
byte[] masterKey = "shared_secret".getBytes();

byte[] encryptionKey = hmac.compute(masterKey, "encryption".getBytes());
byte[] macKey = hmac.compute(masterKey, "authentication".getBytes());

// Now use separate keys
byte[] ciphertext = aes.encrypt(plaintext, encryptionKey);
byte[] mac = hmac.compute(macKey, ciphertext);
```

---

## Performance Considerations

### Computational Cost

For HMAC-SHA256:
- 2 SHA-256 operations per HMAC
- Key preparation overhead (minimal if key reused)
- ~2x slower than plain SHA-256

### Optimization Tips

1. **Reuse prepared keys** if computing many HMACs with same key
2. **Batch verification** when checking multiple MACs
3. **Use hardware acceleration** (AES-NI for CMAC, though HMAC less benefit)
4. **Consider Poly1305** for extreme performance needs

---

## Conclusion

HMAC is the **industry standard** for message authentication codes. It's:
- ✅ Secure (no known practical attacks)
- ✅ Simple to implement correctly
- ✅ Widely supported and standardized
- ✅ Flexible (works with any hash function)
- ✅ Battle-tested in real-world applications

Use HMAC whenever you need to verify message authenticity and integrity!
