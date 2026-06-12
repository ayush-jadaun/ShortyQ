# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-06-12

### Changed — BREAKING

- Replaced the "quantum-inspired" crypto with real NIST-standardized
  post-quantum cryptography: ML-KEM-768 (FIPS 203) + AES-256-GCM via the
  audited @noble/post-quantum and @noble/ciphers libraries.
- New key model: `generateKeyPair()` produces a key pair; URLs are encrypted
  against the public key and can only be decrypted with the secret key.
  Store the secret key in an env var or KMS — a leaked database reveals
  nothing.
- `createShortUrl` now returns `{ shortCode, payload }` where `payload` is
  `{ kemCiphertext, nonce, ciphertext }` (all base64). The v1 `EncryptedData`
  shape (`data`/`noise`/`iv`) is gone — it stored the decryption keys next to
  the ciphertext.
- `decryptUrl(payload, secretKey)` is now a module-level function requiring
  the secret key. Still returns `null` on any failure.
- `ShortyQ` constructor now requires `{ publicKey }`; `quantumSeed` and
  `saltRounds` options removed.
- Encryption is authenticated (AES-256-GCM): tampered data fails decryption.
- Node >= 18 required.

### Removed

- `crypto-js` dependency (discontinued upstream) and the Math.sin-based
  "quantum noise" generator.
- v1 payloads cannot be decrypted by v2. There is no migration path because
  v1 "encryption" was reversible from stored data alone: decrypt v1 records
  with shortyq@1 and re-encrypt with v2 if you need to keep them.

[2.0.0]: https://github.com/ayush-jadaun/ShortyQ/releases/tag/v2.0.0

## [1.0.1] - 2024-03-24

### Added

- Initial release of ShortyQ
- Quantum-inspired encryption for URL shortening
- Multi-layer encryption system with AES, PBKDF2, and SHA3
- Configurable URL length and salt rounds
- Comprehensive test suite with 98%+ coverage
- TypeScript support with full type definitions
- Database integration examples (PostgreSQL, MongoDB, Redis)

### Features

- 🔒 Quantum-inspired encryption for enhanced security
- ⚙️ Fully configurable URL length (4-100 chars) and salt rounds
- 🔄 Multiple rounds of encryption using different algorithms
- 💾 Flexible storage integration
- 📝 TypeScript support with full type definitions
- ✅ Comprehensive test coverage
- 🚨 Robust error handling
- ⚡ High performance with concurrent operation support

### Security

- Quantum-inspired noise generation
- Multiple layers of AES encryption
- PBKDF2 key derivation
- SHA3 hashing
- Unique encryption for each URL
- Input validation and sanitization
- Maximum URL length limit (4096 characters)

### Performance

- Average encryption time: 463.4ms
- Average decryption time: 457.13ms
- Concurrent operations: 45.62ms
- Memory-efficient implementation
- Scalable design

### Documentation

- Comprehensive README with examples
- API documentation
- Security best practices
- Performance optimization tips
- Database integration guides

[1.0.1]: https://github.com/ayush-jadaun/ShortyQ/releases/tag/v1.0.1
