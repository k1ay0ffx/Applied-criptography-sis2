

---

#  HKDF Security Properties

**Extract-then-expand design:**
HKDF (HMAC-based Key Derivation Function) derives secure cryptographic keys from input key material using a two-step process: **Extract** and **Expand**.

The **Extract** phase converts possibly weak or non-uniform input key material into a pseudorandom key (PRK):

```text
PRK = HMAC(salt, IKM)
```

This step ensures that the derived key material is uniformly distributed even if the original input key has limited entropy.

---

**Secure key expansion:**
The **Expand** phase generates the required amount of output key material (OKM) using the pseudorandom key.

The output blocks are generated iteratively:

```text
T1 = HMAC(PRK, info || 0x01)
T2 = HMAC(PRK, T1 || info || 0x02)
T3 = HMAC(PRK, T2 || info || 0x03)
...
```

The final output key material is constructed as:

```text
OKM = T1 || T2 || ... || Tn
```

This design allows HKDF to generate keys of arbitrary length while maintaining cryptographic security.

---

**Context separation using info:**
HKDF includes an optional **info parameter**, which allows different applications or protocols to derive independent keys from the same input key material.

This prevents accidental key reuse across different contexts.

For example:

```
Key1 = HKDF(IKM, salt, "encryption")
Key2 = HKDF(IKM, salt, "authentication")
```

Even though the same input key material is used, the derived keys will be different.

---

**Bounded output length:**
HKDF restricts the maximum output length to:

```
255 × HashLength
```

For example:

* SHA-256 → 255 × 32 = **8160 bytes**
* SHA-512 → 255 × 64 = **16320 bytes**

This limit prevents misuse and ensures the security assumptions of the construction remain valid.

---

**Security based on HMAC:**
The security of HKDF relies on the pseudorandomness of **HMAC**, which itself depends on the cryptographic strength of the underlying hash function such as SHA-256 or SHA-512.

HKDF is standardized in **RFC 5869** and widely used in modern cryptographic protocols including TLS 1.3.

---

---

#  PBKDF2 Security Properties

**Password-based key strengthening:**
PBKDF2 (Password-Based Key Derivation Function 2) is designed to convert a human password into a cryptographically strong key.
Because human passwords usually have low entropy, PBKDF2 applies a large number of hash iterations to increase the computational cost of guessing attacks.

**Iterative hashing for brute-force resistance:**
The function applies the underlying pseudorandom function (HMAC) repeatedly:

```
U1 = HMAC(P, S || INT(i))
U2 = HMAC(P, U1)
...
Uc = HMAC(P, Uc-1)
```

The final block output is computed as:

```
Ti = U1 ⊕ U2 ⊕ ... ⊕ Uc
```

Where **c** is the number of iterations.

Increasing the iteration count linearly increases the computational cost for attackers performing brute-force or dictionary attacks.

**Salt protection against rainbow tables:**
PBKDF2 uses a random **salt** value that is appended to the password before hashing.

```
salt || blockIndex
```

The salt ensures that identical passwords produce different derived keys.
This prevents the use of precomputed rainbow tables for password cracking.

**Block-based key expansion:**
PBKDF2 can generate derived keys longer than the hash output size.
This is achieved by computing multiple blocks:

```
DK = T1 || T2 || ... || Tn
```

Each block is generated independently using the block index appended to the salt.

**Dependence on HMAC security:**
PBKDF2 relies on HMAC as its pseudorandom function.
Therefore, its security depends on the collision resistance and pseudorandomness of the underlying hash function (e.g., SHA-256 or SHA-512).

---



5.1 SHA-512 Security Properties
Pre-image resistance: Given a hash h, it is computationally infeasible to find
any m such that SHA-512(m) = h. The 512-bit output makes exhaustive search
require 2⁵¹² operations.
Collision resistance: Finding any two distinct inputs m₁ ≠ m₂ with the same
hash requires approximately 2²⁵⁶ operations by the birthday paradox.
Avalanche effect: A single bit change in the input cascades through the
compression function to change approximately half (128 of 256 visible bytes in
hex) of the output bits. This was verified experimentally in the console
application's Functional Demo #2.
Length extension attacks: SHA-512 (like SHA-256) is vulnerable to length
extension attacks: given H(m) and the length of m, an attacker can compute
H(m ‖ padding ‖ m') without knowing m. This is why HMAC wraps SHA-256/512
with inner and outer key pads rather than using a simple keyed hash.
5.2 Argon2 Security Properties
Memory hardness: The large, configurable memory requirement means that an
attacker cannot run many parallel guesses without a proportional increase in
hardware cost. At 64 MB per hash, running 10,000 parallel guesses requires 640 GB
of RAM.
Time-memory trade-off (TMTO) resistance: Argon2id's hybrid access pattern
(data-independent in the first half, data-dependent in the second) forces
attackers to actually hold the full memory state, rather than recomputing blocks
on demand.
Side-channel resistance: Argon2i's data-independent addressing means the
memory access pattern reveals nothing about the password, protecting against
cache-timing attacks on shared hardware.

Section 6: Challenges and Lessons Learned
1. Endianness discipline. SHA-512 uses big-endian 64-bit words; BLAKE2b uses
little-endian. Mixing these up caused early test failures. The fix was to keep
separate readBE64/writeBE64 helpers for SHA-512 and rle64/wle64 helpers
for BLAKE2b, with clear naming conventions.
2. Java's signed 64-bit arithmetic. Java has no unsigned long type. All 64-bit
arithmetic wraps silently (which is correct), but comparisons and division require
Long.compareUnsigned and Long.remainderUnsigned in some places, particularly
in the Argon2 index-mapping formula and Blake2b's 128-bit counter.
3. Argon2 index mapping. The quadratic reference block distribution formula is
subtle. The RFC description and reference C implementation slightly differ in
corner cases (when idxInSeg == 0 and a different lane is referenced). Careful
reading of both sources was required to match the official test vectors.
4. H' variable-length hash chaining. The off-by-one in the chain length
(r = ⌈τ/32⌉ - 2) was easy to miscount. The fix was to unit-test H' independently
on boundary values (τ = 32, 33, 64, 65, 1024) before integrating it.
5. BLAKE2b finalization flag. The last block in BLAKE2b must set f[0] = 0xFFFF…
(all ones). Forgetting to XOR with ~IV[6] instead of just IV[6] produced
wrong digests only on short, single-block inputs — a subtle bug caught by the
empty-string test vector.
