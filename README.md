# ShortyQ

A quantum-safe URL shortener. ShortyQ encrypts URLs with **ML-KEM-768**
(NIST FIPS 203, the standardized Kyber) and **AES-256-GCM**, so the encrypted
URLs you store remain confidential even against future quantum computers —
and a leaked database reveals nothing without your secret key.

## What "quantum-safe" means here

- URLs are encrypted using a [KEM+DEM construction](https://en.wikipedia.org/wiki/Hybrid_cryptosystem):
  each URL gets a fresh shared secret encapsulated with ML-KEM-768, then is
  encrypted with AES-256-GCM.
- ML-KEM is the post-quantum key-encapsulation standard published by NIST
  (FIPS 203) and deployed by Signal, Chrome, and iMessage.
- Decryption requires a secret key that you keep **outside the database**
  (env var, KMS). Database contents alone are useless to an attacker.
- Short codes themselves are random IDs (nanoid) — they carry no information
  about the URL.
- Crypto comes from the audited [noble](https://paulmillr.com/noble/)
  libraries: [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum)
  and [@noble/ciphers](https://github.com/paulmillr/noble-ciphers).

## Features

- 🔐 Real post-quantum encryption (ML-KEM-768, NIST FIPS 203)
- 🔑 Public-key model: shorten anywhere, decrypt only with the secret key
- ✅ Authenticated encryption (AES-256-GCM) — tampered data fails closed
- ⏳ Encrypted expiry & metadata — enforced inside the ciphertext
- 🔏 Password-protected links (scrypt-hardened)
- 🔁 Key rotation with keyId stamping
- 🎯 Deterministic and vanity short codes
- 🧰 `npx shortyq keygen` CLI
- ⚙️ Configurable short code length (4-100 chars)
- 💾 Bring your own storage (PostgreSQL, MongoDB, Redis, ...)
- 📝 TypeScript-first with full type definitions

## Installation

```bash
npm install shortyq
```

Requires Node >= 18.

## Quick Start

```typescript
import { ShortyQ, generateKeyPair, decryptUrl } from "shortyq";

// 1. One-time setup: generate a key pair.
//    Store secretKey in an env var or KMS — NEVER in the database.
const { publicKey, secretKey } = generateKeyPair();

// 2. Shorten + encrypt (only needs the public key)
const shortyQ = new ShortyQ({ publicKey });
const { shortCode, payload } = shortyQ.createShortUrl(
  "https://example.com/long/path"
);

// 3. Store shortCode + payload in your database.
//    The payload is useless without the secret key.
await db.save({ shortCode, payload });

// 4. Resolve: load the payload and decrypt with the secret key
const stored = await db.get(shortCode);
const originalUrl = decryptUrl(stored.payload, secretKey);
// -> "https://example.com/long/path", or null if the key is wrong
//    or the data was tampered with
```

> See the `examples` folder for PostgreSQL, MongoDB, and Redis integrations.

## API

### `generateKeyPair(): KeyPair`

Generates an ML-KEM-768 key pair as base64 strings:
`{ publicKey, secretKey, codeKey }`. Call once; reuse the keys.

### `new ShortyQ(options)`

| Option      | Type   | Required | Default | Description                                  |
| ----------- | ------ | -------- | ------- | -------------------------------------------- |
| `publicKey` | string | yes      | —       | Base64 public key from `generateKeyPair()`   |
| `urlLength` | number | no       | 8       | Short code length (4-100)                    |
| `codeKey`   | string | no       | —       | Base64 codeKey enabling deterministic codes  |

### `shortyQ.createShortUrl(url): { shortCode, payload }`

Validates the URL (must parse, max 4096 chars), generates a nanoid short
code, and encrypts the URL against the public key. Every call uses a fresh
ML-KEM encapsulation. The returned `payload` is
`{ kemCiphertext, nonce, ciphertext }` — all base64 strings, safe to store.

Throws on empty, invalid, or over-long URLs.

### `decryptUrl(payload, secretKey | secretKey[], options?): string | null`

Decapsulates and decrypts. Returns the original URL, or `null` if the secret
key is wrong, the password is wrong/missing, the link has expired, the
payload is malformed, or the data was tampered with. Never throws.

### `decryptPayload(payload, secretKey | secretKey[], options?): { url, metadata?, expiresAt? } | null`

Like `decryptUrl`, but returns the full decrypted contents. Pass an array of
secret keys to support key rotation — each is tried until one authenticates.

### `getKeyId(publicKey): string`

Advisory 8-byte identifier (base64) for a public key. Every payload carries
the `keyId` of the key that encrypted it, so apps can index their keys.

### `shortyQ.createShortUrls(items): Array<{ shortCode, payload }>`

Batch variant. Items are URLs or `{ url, options }` objects. Throws on the
first invalid item (no partial results).

## v2.1 features

### Encrypted expiry & metadata

```typescript
const { payload } = shortyQ.createShortUrl("https://example.com/sale", {
  expiresAt: new Date("2026-12-31"),       // Date or epoch millis
  metadata: { campaign: "winter", owner: "ayush" },
});

const result = decryptPayload(payload, secretKey);
// { url, metadata, expiresAt } — or null once expired
```

Expiry and metadata live **inside the authenticated ciphertext**: whoever
holds the database can neither read nor extend them.

### Password-protected links

```typescript
const { payload } = shortyQ.createShortUrl(url, { password: "hunter2" });
decryptUrl(payload, secretKey);                          // null
decryptUrl(payload, secretKey, { password: "hunter2" }); // url
```

The password is stretched with scrypt (N=2^15) and mixed into the AES key:
decryption requires the secret key **and** the password — even the operator
holding the secret key cannot read these links without it.

### Key rotation

```typescript
const NEW = generateKeyPair();
// new links use NEW.publicKey; old links still decrypt:
decryptUrl(payload, [NEW.secretKey, OLD.secretKey]);
```

### Deterministic & vanity short codes

```typescript
const shortyQ = new ShortyQ({ publicKey, codeKey }); // codeKey from generateKeyPair()

// Same URL -> same code (dedupe). Opt-in: reveals URL-equality in your DB.
shortyQ.createShortUrl(url, { deterministic: true });

// Vanity code (4-100 chars of A-Za-z0-9_-); collision checks are your job
shortyQ.createShortUrl(url, { shortCode: "summer-sale" });
```

Deterministic codes are capped at 43 characters (the full HMAC digest).

### CLI

```bash
npx shortyq keygen          # prints SHORTYQ_PUBLIC_KEY / SECRET_KEY / CODE_KEY
npx shortyq keygen --json   # same as JSON
```

## Key handling

```typescript
// Generate once (e.g. a setup script), then keep the secret key in
// your secret manager:
const { publicKey, secretKey } = generateKeyPair();
console.log("SHORTYQ_PUBLIC_KEY=" + publicKey);
console.log("SHORTYQ_SECRET_KEY=" + secretKey); // -> env var / KMS

// In your app:
const shortyQ = new ShortyQ({ publicKey: process.env.SHORTYQ_PUBLIC_KEY! });
const url = decryptUrl(payload, process.env.SHORTYQ_SECRET_KEY!);
```

**Threat model:** an attacker with a full copy of your database (short codes +
payloads) learns nothing about the original URLs, including against
harvest-now-decrypt-later quantum attacks. An attacker with your secret key
can decrypt everything — guard it accordingly.

## Performance

Measured with `npm run bench` (`benchmarks/compare.ts`) on Node v22.13.1,
x64, against the old shortyq v1 (from npm) and popular alternatives:

| Operation                               | avg (ms) | p95 (ms) | ops/sec |
| --------------------------------------- | -------- | -------- | ------- |
| **shortyq v2.1: createShortUrl**        | 0.51     | 0.72     | ~1,980  |
| **shortyq v2.1: decryptUrl**            | 0.44     | 0.61     | ~2,260  |
| **shortyq v2.1: generateKeyPair**       | 0.40     | 0.60     | ~2,490  |
| shortyq v2.1: create with password      | 139      | 211      | ~7      |
| shortyq v2.1: decrypt with password     | 123      | 251      | ~8      |
| shortyq v1.0.1 (old): createShortUrl    | 0.77     | 2.61     | ~1,300  |
| shortyq v1.0.1 (old): decryptUrl        | 1.46     | 3.34     | ~680    |
| node crypto AES-256-GCM: encrypt        | 0.006    | 0.007    | ~180,000 |
| tweetnacl box (X25519): encrypt         | 0.51     | 0.71     | ~1,940  |
| tweetnacl box (X25519): decrypt         | 0.53     | 1.53     | ~1,890  |

Takeaways:

- **Post-quantum at classical speed:** ML-KEM-768 + AES-256-GCM shortens and
  decrypts at the same speed as tweetnacl's classical X25519 box — while
  being quantum-safe.
- **Faster than v1:** ~1.5x faster shortening and ~3x faster decryption than
  the old crypto-js implementation, with real security instead of theater.
- **Password links are slow on purpose:** ~130ms per operation is the scrypt
  work factor (N=2^15) doing its job against brute force.
- Raw AES is microseconds; the public-key step dominates — that's the price
  of "shorten anywhere, decrypt only with the secret key" regardless of
  which public-key crypto you pick.

## Migrating from v1

v1's encryption stored its key material alongside the ciphertext, so it was
obfuscation rather than encryption — that's why v2 is a breaking rewrite.

- `quantumSeed` and `saltRounds` options are gone.
- `EncryptedData` (`data`/`noise`/`iv`) is replaced by `EncryptedPayload`
  (`kemCiphertext`/`nonce`/`ciphertext`).
- `decryptUrl` moved from an instance method to a module-level function and
  requires the secret key.
- To keep old records: decrypt them with `shortyq@1` (possible from stored
  data alone) and re-encrypt with v2.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

[MIT](LICENSE)
