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
`{ publicKey, secretKey }`. Call once; reuse the keys.

### `new ShortyQ(options)`

| Option      | Type   | Required | Default | Description                                |
| ----------- | ------ | -------- | ------- | ------------------------------------------ |
| `publicKey` | string | yes      | —       | Base64 public key from `generateKeyPair()` |
| `urlLength` | number | no       | 8       | Short code length (4-100)                  |

### `shortyQ.createShortUrl(url): { shortCode, payload }`

Validates the URL (must parse, max 4096 chars), generates a nanoid short
code, and encrypts the URL against the public key. Every call uses a fresh
ML-KEM encapsulation. The returned `payload` is
`{ kemCiphertext, nonce, ciphertext }` — all base64 strings, safe to store.

Throws on empty, invalid, or over-long URLs.

### `decryptUrl(payload, secretKey): string | null`

Decapsulates and decrypts. Returns the original URL, or `null` if the secret
key is wrong, the payload is malformed, or the data was tampered with. Never
throws.

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
