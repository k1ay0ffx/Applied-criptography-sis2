

---

# HKDF Security Properties

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

