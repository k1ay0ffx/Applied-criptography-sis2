
---

#PBKDF2 Security Properties

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


