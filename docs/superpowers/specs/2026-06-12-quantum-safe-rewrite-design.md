# ShortyQ v2.0.0 — Quantum-Safe Rewrite (Design)

**Date:** 2026-06-12
**Status:** Approved

## Problem

ShortyQ v1 markets itself as "a secure URL shortener using quantum-inspired
encryption techniques." Neither claim holds:

1. **The "quantum noise" is `Math.sin`.** `generateQuantumNoise()` derives key
   material from `Math.sin(seed * i + timestamp)` — deterministic, predictable,
   and weaker than `crypto.randomBytes()`.
2. **The encryption protects nothing.** `encryptUrl()` returns the ciphertext
   *and all key material needed to decrypt it* in the same object
   (`{ data, noise, iv }`). Anyone who can read the stored record can decrypt
   it. The three AES layers, PBKDF2, and SHA3 are theater.
3. Supporting issues: PBKDF2 at 10 iterations (~6 orders of magnitude below
   OWASP guidance), CryptoJS passphrase mode silently ignoring the explicit IV,
   and `crypto-js` itself being discontinued.

## Goal

Make ShortyQ's quantum claim *true* by rebuilding the crypto on
NIST-standardized post-quantum cryptography, with a real security model:
the database stores only ciphertext; decryption requires a secret key the
caller holds elsewhere.

Honest claim after this work: "URLs encrypted with NIST-standardized
post-quantum cryptography (ML-KEM-768); a leaked database reveals nothing."

**Scope caveat:** "quantum-safe" protects the stored URLs from future quantum
decryption. Short codes remain plain random IDs (as they should be).

## Design

### Crypto stack

All from the audited noble family — pure JS, zero native dependencies, runs in
Node and browsers:

- `@noble/post-quantum` — **ML-KEM-768** (NIST FIPS 203, standardized Kyber).
  Key encapsulation; this is the quantum-safe part.
- `@noble/ciphers` — **AES-256-GCM** for URL encryption (authenticated;
  tampering is detected, unlike v1's CBC).

Removed: `crypto-js`, the `Math.sin` noise generator, the three-layer AES,
PBKDF2, SHA3.

### Construction (standard hybrid KEM + DEM)

1. **`generateKeyPair(): { publicKey, secretKey }`** — module-level function,
   called once. The app stores `secretKey` in an env var or KMS — never in the
   database.
2. **`createShortUrl(url): { shortCode, payload }`** — encapsulates against the
   configured public key (ML-KEM produces a fresh shared secret +
   `kemCiphertext`), then AES-256-GCM-encrypts the URL with that secret using a
   random nonce. `payload = { kemCiphertext, nonce, ciphertext }` — safe to
   store in the DB; useless without the secret key. Every call uses a fresh
   encapsulation (no key reuse across URLs).
3. **`decryptUrl(payload, secretKey): string | null`** — decapsulates the
   shared secret, decrypts, verifies the GCM auth tag. Returns the original
   URL, or `null` if the key is wrong, the payload is malformed, or the data
   was tampered with.

### API shape

- `ShortyQ` class constructed with `{ publicKey, urlLength? }`. The instance
  only needs the public key (shorten path). `decryptUrl` takes the secret key
  as an argument.
- Payload fields are base64-encoded strings so the payload is JSON/DB-friendly
  (base64 over hex: ML-KEM-768 ciphertexts are 1088 bytes, so the more compact
  encoding matters).

### Kept from v1

- nanoid short codes, configurable length 4–100 (default 8)
- URL validation via `new URL()`, empty-URL error, 4096-char max
- `decryptUrl` returns `null` on any failure (never throws)

### Removed from v1 (breaking — v2.0.0)

- `quantumSeed`, `saltRounds` options
- `EncryptedData` shape (`data`/`noise`/`iv`) — replaced by `payload`
  (`kemCiphertext`/`nonce`/`ciphertext`); key material no longer travels with
  ciphertext

### Tests

- Round-trip: shorten → decrypt returns original URL
- Wrong secret key → `null`
- Tampered `ciphertext`, `nonce`, or `kemCiphertext` → `null`
- Two `createShortUrl` calls produce different `kemCiphertext` (fresh
  encapsulation each time)
- Validation: empty URL, invalid URL, over-length URL, urlLength bounds
- Malformed payload (missing fields, garbage) → `null`

### Documentation

README rewritten with honest claims: what ML-KEM-768 is, the key-handling
model (secret key in env/KMS, ciphertext in DB), the threat model (DB leak
reveals nothing; quantum-safe at rest), and migration notes from v1.
`package.json` description and keywords updated to match. Version bumped to
2.0.0.
