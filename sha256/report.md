# SHA-256 Implementation Guide

## Overview

SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function that produces a 256-bit (32-byte) hash value from arbitrary input data. It's part of the SHA-2 family designed by the NSA.

## How SHA-256 Works - Step by Step

### Step 1: Message Padding

The input message must be padded to a length that is a multiple of 512 bits (64 bytes).

**Padding Rules:**
1. Append a single '1' bit to the message
2. Append '0' bits until length ≡ 448 (mod 512)
3. Append the original message length as a 64-bit big-endian integer

**Example:**
```
Original message: "abc" (24 bits)
In binary: 01100001 01100010 01100011

After padding:
01100001 01100010 01100011 1 000...000 [423 zeros] [64-bit length = 24]
└────── message ──────┘ └1 bit┘ └─ zeros ─┘ └─ length ─┘
                       (total = 512 bits)
```

**Code:**
```java
private static byte[] padMessage(byte[] message) {
    long messageLengthBits = (long) message.length * 8;
    
    // Calculate padding needed
    int paddingLength = 64 - ((message.length + 9) % 64);
    if (paddingLength == 64) paddingLength = 0;
    
    int totalLength = message.length + 1 + paddingLength + 8;
    byte[] padded = new byte[totalLength];
    
    // Copy original message
    System.arraycopy(message, 0, padded, 0, message.length);
    
    // Append '1' bit (0x80 = 10000000)
    padded[message.length] = (byte) 0x80;
    
    // Append length (last 8 bytes)
    for (int i = 0; i < 8; i++) {
        padded[totalLength - 8 + i] = (byte) (messageLengthBits >>> (56 - i * 8));
    }
    
    return padded;
}
```

### Step 2: Initialize Hash Values

SHA-256 uses 8 initial hash values (H0 through H7). These are the first 32 bits of the fractional parts of the square roots of the first 8 prime numbers.

```
H[0] = 0x6a09e667  (√2)
H[1] = 0xbb67ae85  (√3)
H[2] = 0x3c6ef372  (√5)
H[3] = 0xa54ff53a  (√7)
H[4] = 0x510e527f  (√11)
H[5] = 0x9b05688c  (√13)
H[6] = 0x1f83d9ab  (√17)
H[7] = 0x5be0cd19  (√19)
```

**How to derive (example for √2):**
```
√2 = 1.41421356237309504880168872420969807856967187537694...

Fractional part: 0.41421356237309504880168872420969807856967187537694...

First 32 bits in hex:
0.41421356... × 2^32 = 0x6a09e667
```

### Step 3: Process Each 512-bit Chunk

#### 3.1 Create Message Schedule (W array)

Expand the 512-bit chunk into 64 32-bit words:

```java
int[] W = new int[64];

// First 16 words come directly from the chunk
for (int t = 0; t < 16; t++) {
    W[t] = bytesToInt(chunk, t * 4);
}

// Extend into remaining 48 words
for (int t = 16; t < 64; t++) {
    int s0 = rightRotate(W[t-15], 7) ^ rightRotate(W[t-15], 18) ^ (W[t-15] >>> 3);
    int s1 = rightRotate(W[t-2], 17) ^ rightRotate(W[t-2], 19) ^ (W[t-2] >>> 10);
    W[t] = W[t-16] + s0 + W[t-7] + s1;
}
```

**Visual representation:**
```
Chunk (512 bits = 16 words of 32 bits):
┌────┬────┬────┬────┐───┬────┐
│ W0 │ W1 │ W2 │ W3 │...│W15 │
└────┴────┴────┴────┘───┴────┘

Extended (64 words):
┌────┬────┬────┬────┐───┬────┐
│ W0 │ W1 │ W2 │ W3 │...│W63 │  ← W[16..63] computed using σ0 and σ1
└────┴────┴────┴────┘───┴────┘
```

**The σ functions:**
```
σ0(x) = ROTR^7(x) ⊕ ROTR^18(x) ⊕ SHR^3(x)
σ1(x) = ROTR^17(x) ⊕ ROTR^19(x) ⊕ SHR^10(x)

where:
- ROTR^n = Rotate right by n bits
- SHR^n = Shift right by n bits
- ⊕ = XOR
```

#### 3.2 Initialize Working Variables

```java
int a = H[0];
int b = H[1];
int c = H[2];
int d = H[3];
int e = H[4];
int f = H[5];
int g = H[6];
int h = H[7];
```

#### 3.3 Main Compression Loop (64 Rounds)

Each round performs these operations:

```java
for (int t = 0; t < 64; t++) {
    // Σ1 function
    int S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
    
    // Ch (Choose) function: if e then f else g
    int ch = (e & f) ^ (~e & g);
    
    // Temporary word 1
    int temp1 = h + S1 + ch + K[t] + W[t];
    
    // Σ0 function
    int S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
    
    // Maj (Majority) function
    int maj = (a & b) ^ (a & c) ^ (b & c);
    
    // Temporary word 2
    int temp2 = S0 + maj;
    
    // Update working variables
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
}
```

**Visual representation of one round:**

```
       a   b   c   d   e   f   g   h
       │   │   │   │   │   │   │   │
       │   │   │   │   │ ┌─┴─┐ │   │
       │   │   │   │   └─┤ Ch├─┘   │
       │   │   │   │     └─┬─┘     │
       │   │   │   │       │       │
       │   │   │   │     ┌─┴──┐    │
       │   │   │   │     │ Σ1 │    │
       │   │   │   │     └─┬──┘    │
       │   │   │   │       │       │
       │   │   │   │    ┌──┴───┐   │
       │   │   │   │    │  +   ├───┤ h
       │   │   │   │    │ K[t] │   │
       │   │   │   │    │ W[t] │   │
       │   │   │   │    └──┬───┘   │
       │   │   │   │       │       │
       │   │   │   │  ┌────┴────┐  │
       │   │   │   └──┤    +    │  │ temp1
       │   │   │      └────┬────┘  │
       │   │   │           │       │
       │ ┌─┴─┐ │           │       │
       └─┤Maj├─┘           │       │
         └─┬─┘             │       │
       ┌───┴────┐          │       │
       │   Σ0   │          │       │
       └───┬────┘          │       │
           │    ┌──────────┘       │
           │    │                  │
         ┌─┴────┴─┐                │
         │   +    │ temp2          │
         └───┬────┘                │
             │                     │
         ┌───┴────┐                │
         │   +    │◄───────────────┘
         └───┬────┘
             │
             ▼
          new a

Variables shift:
a ← temp1 + temp2
b ← a
c ← b
d ← c
e ← d + temp1
f ← e
g ← f
h ← g
```

**The functions explained:**

1. **Ch (Choose)**: `(e & f) ^ (~e & g)`
   - If bit in e is 1, choose bit from f
   - If bit in e is 0, choose bit from g

2. **Maj (Majority)**: `(a & b) ^ (a & c) ^ (b & c)`
   - Output is the majority bit from a, b, c

3. **Σ0**: `ROTR^2(a) ⊕ ROTR^13(a) ⊕ ROTR^22(a)`

4. **Σ1**: `ROTR^6(e) ⊕ ROTR^11(e) ⊕ ROTR^25(e)`

#### 3.4 Update Hash Values

After 64 rounds, add the working variables to the hash values:

```java
H[0] += a;
H[1] += b;
H[2] += c;
H[3] += d;
H[4] += e;
H[5] += f;
H[6] += g;
H[7] += h;
```

### Step 4: Produce Final Hash

After processing all chunks, concatenate the 8 hash values:

```
Final Hash = H[0] || H[1] || H[2] || H[3] || H[4] || H[5] || H[6] || H[7]
```

Each H[i] is 32 bits, so total = 256 bits = 32 bytes

```java
private static byte[] hashToBytes(int[] H) {
    byte[] hash = new byte[32];
    for (int i = 0; i < 8; i++) {
        hash[i * 4]     = (byte) (H[i] >>> 24);
        hash[i * 4 + 1] = (byte) (H[i] >>> 16);
        hash[i * 4 + 2] = (byte) (H[i] >>> 8);
        hash[i * 4 + 3] = (byte) H[i];
    }
    return hash;
}
```

---

## Complete Example: Hash "abc"

### Input
```
Message: "abc"
Bytes: 0x61 0x62 0x63
Binary: 01100001 01100010 01100011
```

### Step 1: Padding
```
Original: 01100001 01100010 01100011 (24 bits)
+ 1 bit:  01100001 01100010 01100011 1
+ zeros:  01100001 01100010 01100011 10000000 00000000 ... (56 bytes of zeros)
+ length: ... 00000000 00000000 00000000 00011000 (24 in 64-bit big-endian)

Total: 512 bits (64 bytes)
```

### Step 2: Initialize
```
H[0] = 0x6a09e667
H[1] = 0xbb67ae85
H[2] = 0x3c6ef372
H[3] = 0xa54ff53a
H[4] = 0x510e527f
H[5] = 0x9b05688c
H[6] = 0x1f83d9ab
H[7] = 0x5be0cd19
```

### Step 3: Process Chunk

**Message Schedule W[0..15]:**
```
W[0]  = 0x61626380
W[1]  = 0x00000000
W[2]  = 0x00000000
...
W[14] = 0x00000000
W[15] = 0x00000018
```

**Extend to W[16..63]:**
```
W[16] = W[0] + σ0(W[1]) + W[9] + σ1(W[14])
      = 0x61626380 + ... = 0x...
...
```

**64 Rounds of compression...**

### Step 4: Final Hash
```
After processing:
H[0] = 0xba7816bf
H[1] = 0x8f01cfea
H[2] = 0x414140de
H[3] = 0x5dae2223
H[4] = 0xb00361a3
H[5] = 0x96177a9c
H[6] = 0xb410ff61
H[7] = 0xf20015ad

Final hash (hex):
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

---

## Constants Explained

### Round Constants (K)

The 64 round constants are the first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers.

```
K[0]  = 0x428a2f98  (∛2)
K[1]  = 0x71374491  (∛3)
K[2]  = 0xb5c0fbcf  (∛5)
K[3]  = 0xe9b5dba5  (∛7)
...
K[63] = 0xc67178f2  (∛311)
```

**Why these specific constants?**
- Derived from mathematical constants (nothing up my sleeve numbers)
- Ensures no backdoors or weaknesses
- Makes the algorithm cryptographically strong

---

## Key Properties of SHA-256

1. **Deterministic**: Same input always produces same output
2. **Fast to compute**: Efficient algorithm
3. **Avalanche effect**: Small input change → completely different hash
4. **One-way**: Computationally infeasible to reverse
5. **Collision resistant**: Hard to find two inputs with same hash
6. **Fixed output size**: Always 256 bits (32 bytes)

---

## Bitwise Operations Guide

### Right Rotate (ROTR)
```java
private static int rightRotate(int value, int bits) {
    return (value >>> bits) | (value << (32 - bits));
}
```

**Example: ROTR^7(0xABCD1234)**
```
Original: 10101011 11001101 00010010 00110100
          │                              │
          └──────────────────────────────┘
                      shift by 7 →
Result:   01001101 01010111 10011010 00010010
```

### Right Shift (SHR)
```java
value >>> bits  // Zero-fill right shift
```

**Example: SHR^3(0xABCD1234)**
```
Original: 10101011 11001101 00010010 00110100
Result:   00010101 01111001 10100010 01000110
          ^^^← filled with zeros
```

### XOR (⊕)
```java
a ^ b
```

**Example:**
```
  10101100
⊕ 11110000
= 01011100
```

---

## Common Use Cases

1. **Password Hashing** (with salt)
```java
String password = "myPassword123";
String salt = "randomSalt";
String hash = SHA256.hashString(password + salt);
```

2. **File Integrity Verification**
```java
byte[] fileContent = Files.readAllBytes(Paths.get("file.txt"));
byte[] hash = SHA256.hash(fileContent);
```

3. **Digital Signatures**
```java
byte[] message = "Important message".getBytes();
byte[] hash = SHA256.hash(message);
// Sign the hash with private key
```

4. **Blockchain (Double SHA-256)**
```java
byte[] data = "Block data".getBytes();
byte[] hash1 = SHA256.hash(data);
byte[] hash2 = SHA256.hash(hash1);  // Bitcoin uses this
```

---

## Security Considerations

### ✓ SHA-256 is secure for:
- Digital signatures
- Certificate generation
- Blockchain applications
- File integrity checks
- Password verification (with proper salting)

### ✗ SHA-256 is NOT suitable for:
- Direct password storage (use bcrypt, scrypt, or Argon2)
- Key derivation without PBKDF2/HKDF
- MAC without HMAC construction

### Best Practices:

1. **Always use salt** for password hashing
2. **Never truncate** the hash for security applications
3. **Use HMAC-SHA256** for message authentication
4. **Consider SHA-3** for new applications (quantum resistance)

---

## Performance Tips

1. **Reuse objects**: Avoid creating new arrays in loops
2. **Batch processing**: Process multiple messages without recreating constants
3. **Hardware acceleration**: Use SHA-NI instructions when available
4. **Parallel processing**: Multiple independent hashes can be computed in parallel

---

## Testing Your Implementation

Always validate with standard test vectors:

```java
// NIST Test Vectors
testHash("", 
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

testHash("abc",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

testHash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
```

All tests should pass for a correct implementation!
