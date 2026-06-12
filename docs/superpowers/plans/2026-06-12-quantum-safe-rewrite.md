# ShortyQ v2.0.0 Quantum-Safe Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace ShortyQ's fake "quantum noise" crypto with real NIST-standardized post-quantum cryptography (ML-KEM-768 + AES-256-GCM) and a caller-held-key security model.

**Architecture:** Standard KEM+DEM construction. `generateKeyPair()` produces an ML-KEM-768 keypair (base64 strings). `ShortyQ` (constructed with the public key) encapsulates a fresh 32-byte shared secret per URL and encrypts the URL with AES-256-GCM. Module-level `decryptUrl(payload, secretKey)` decapsulates and decrypts, returning `null` on any failure. Everything lives in `src/index.ts` (single-file package, matching v1 layout).

**Tech Stack:** TypeScript (CommonJS, ts-jest), `@noble/post-quantum@^0.4.1` (ML-KEM-768, FIPS 203), `@noble/ciphers@^1.3.0` (AES-256-GCM), `nanoid@^3` (kept), Node built-in `crypto.randomBytes` for nonces.

**Version pinning rationale (do not "upgrade"):** noble 2.x / post-quantum 0.6.x are ESM-only and break this project's CommonJS + ts-jest setup. `@noble/post-quantum@0.4.1` and `@noble/ciphers@1.3.0` are dual CJS/ESM and implement the same final FIPS 203 standard.

**API reference for the noble libraries (verified against 0.4.1):**

```typescript
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
// ml_kem768.keygen() -> { publicKey: Uint8Array(1184), secretKey: Uint8Array(2400) }
// ml_kem768.encapsulate(publicKey) -> { cipherText: Uint8Array(1088), sharedSecret: Uint8Array(32) }
//   NOTE: capital T in "cipherText"
// ml_kem768.decapsulate(cipherText, secretKey) -> Uint8Array(32)
//   NOTE: wrong-but-valid secret key does NOT throw (implicit rejection);
//   it returns a different shared secret, and AES-GCM auth then fails.

import { gcm } from "@noble/ciphers/aes";
// gcm(key32, nonce12).encrypt(bytes) -> ciphertext||tag
// gcm(key32, nonce12).decrypt(bytes) -> plaintext, THROWS on auth failure
```

**Commit message rule:** plain descriptive messages, NO attribution lines of any kind.

---

### Task 1: Install post-quantum dependencies

Keep `crypto-js` installed for now (old `src/index.ts` still imports it until Task 2) so every commit stays green. It is removed in Task 7.

**Files:**
- Modify: `package.json` (dependencies only, via npm)
- Modify: `package-lock.json` (via npm)
- Commit pre-existing: `CHANGELOG.md` (untracked), `package.json` version bump

- [ ] **Step 0: Commit the pre-existing v1.0.1 housekeeping**

The working tree has an uncommitted `1.0.0 -> 1.0.1` version bump in `package.json` and an untracked `CHANGELOG.md` documenting the 1.0.1 release. Commit them separately so they don't mix into the v2 work:

```bash
git add package.json CHANGELOG.md
git commit -m "Bump version to 1.0.1 and add changelog"
```

- [ ] **Step 1: Install the noble libraries at the dual-format majors**

Run: `npm install @noble/post-quantum@^0.4.1 @noble/ciphers@^1.3.0`
Expected: success; `package.json` dependencies now include both alongside `crypto-js` and `nanoid`.

- [ ] **Step 2: Verify the imports resolve under CommonJS**

Run: `node -e "const { ml_kem768 } = require('@noble/post-quantum/ml-kem'); const { gcm } = require('@noble/ciphers/aes'); const kp = ml_kem768.keygen(); console.log(kp.publicKey.length, kp.secretKey.length);"`
Expected output: `1184 2400`

- [ ] **Step 3: Verify existing tests still pass**

Run: `npm test`
Expected: all existing v1 tests PASS (nothing changed yet).

- [ ] **Step 4: Commit**

```bash
git add package.json package-lock.json
git commit -m "Add @noble/post-quantum and @noble/ciphers dependencies"
```

---

### Task 2: Replace v1 implementation with v2 skeleton + generateKeyPair

This is the breaking cutover: both `src/index.ts` and `src/index.test.ts` are fully replaced. The v1 test suite tests removed behavior (quantumSeed, saltRounds, EncryptedData) and goes away with it.

**Files:**
- Rewrite: `src/index.ts`
- Rewrite: `src/index.test.ts`

- [ ] **Step 1: Replace the test file with the keypair tests**

Replace the ENTIRE contents of `src/index.test.ts` with:

```typescript
import { generateKeyPair } from "./index";

describe("generateKeyPair", () => {
  it("returns base64-encoded keys with correct ML-KEM-768 sizes", () => {
    const { publicKey, secretKey } = generateKeyPair();
    expect(Buffer.from(publicKey, "base64")).toHaveLength(1184);
    expect(Buffer.from(secretKey, "base64")).toHaveLength(2400);
  });

  it("generates a different key pair on each call", () => {
    const pair1 = generateKeyPair();
    const pair2 = generateKeyPair();
    expect(pair1.publicKey).not.toBe(pair2.publicKey);
    expect(pair1.secretKey).not.toBe(pair2.secretKey);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx jest src/index.test.ts`
Expected: FAIL — `generateKeyPair` is not exported / TS compile error.

- [ ] **Step 3: Replace src/index.ts with the v2 skeleton**

Replace the ENTIRE contents of `src/index.ts` with:

```typescript
import { ml_kem768 } from "@noble/post-quantum/ml-kem";

/** Byte sizes fixed by the ML-KEM-768 parameter set (FIPS 203) */
const PUBLIC_KEY_BYTES = 1184;
const SECRET_KEY_BYTES = 2400;
const KEM_CIPHERTEXT_BYTES = 1088;
/** AES-GCM standard nonce size */
const NONCE_BYTES = 12;

/**
 * An ML-KEM-768 key pair, base64-encoded for easy storage.
 * Store the secretKey in an env var or KMS — never in the database.
 */
export interface KeyPair {
  /** Base64-encoded ML-KEM-768 public key (safe to embed in app config) */
  publicKey: string;
  /** Base64-encoded ML-KEM-768 secret key (keep out of the database) */
  secretKey: string;
}

/**
 * Encrypted URL payload. Safe to store in a database —
 * useless without the secret key.
 */
export interface EncryptedPayload {
  /** Base64 ML-KEM-768 encapsulation ciphertext (1088 bytes) */
  kemCiphertext: string;
  /** Base64 AES-GCM nonce (12 bytes) */
  nonce: string;
  /** Base64 AES-256-GCM ciphertext including auth tag */
  ciphertext: string;
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

/**
 * Generates an ML-KEM-768 key pair. Call once; reuse the public key
 * for shortening and keep the secret key for decryption.
 */
export function generateKeyPair(): KeyPair {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { publicKey: toBase64(publicKey), secretKey: toBase64(secretKey) };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx jest src/index.test.ts`
Expected: 2 tests PASS.

- [ ] **Step 5: Verify the package still builds**

Run: `npm run build`
Expected: clean compile, `dist/index.js` and `dist/index.d.ts` regenerated.

- [ ] **Step 6: Commit**

```bash
git add src/index.ts src/index.test.ts
git commit -m "Replace fake quantum crypto with ML-KEM-768 key generation"
```

---

### Task 3: ShortyQ class with createShortUrl

**Files:**
- Modify: `src/index.ts`
- Modify: `src/index.test.ts`

- [ ] **Step 1: Add failing tests for the class and createShortUrl**

Change the existing import at the top of `src/index.test.ts` to:

```typescript
import { ShortyQ, generateKeyPair } from "./index";
```

Then append this describe block (do NOT add a second import statement):

```typescript
describe("ShortyQ.createShortUrl", () => {
  const { publicKey } = generateKeyPair();

  it("generates short codes of the default length 8", () => {
    const shortyQ = new ShortyQ({ publicKey });
    const { shortCode } = shortyQ.createShortUrl("https://example.com");
    expect(shortCode).toHaveLength(8);
  });

  it("respects a custom short code length", () => {
    const shortyQ = new ShortyQ({ publicKey, urlLength: 10 });
    const { shortCode } = shortyQ.createShortUrl("https://example.com");
    expect(shortCode).toHaveLength(10);
  });

  it("generates different codes for the same URL", () => {
    const shortyQ = new ShortyQ({ publicKey });
    const result1 = shortyQ.createShortUrl("https://example.com");
    const result2 = shortyQ.createShortUrl("https://example.com");
    expect(result1.shortCode).not.toBe(result2.shortCode);
  });

  it("returns a payload with base64 fields of the expected sizes", () => {
    const shortyQ = new ShortyQ({ publicKey });
    const { payload } = shortyQ.createShortUrl("https://example.com");
    expect(Buffer.from(payload.kemCiphertext, "base64")).toHaveLength(1088);
    expect(Buffer.from(payload.nonce, "base64")).toHaveLength(12);
    expect(
      Buffer.from(payload.ciphertext, "base64").length
    ).toBeGreaterThan(16); // at least the GCM tag
  });

  it("uses a fresh encapsulation for every call", () => {
    const shortyQ = new ShortyQ({ publicKey });
    const result1 = shortyQ.createShortUrl("https://example.com");
    const result2 = shortyQ.createShortUrl("https://example.com");
    expect(result1.payload.kemCiphertext).not.toBe(
      result2.payload.kemCiphertext
    );
    expect(result1.payload.nonce).not.toBe(result2.payload.nonce);
    expect(result1.payload.ciphertext).not.toBe(result2.payload.ciphertext);
  });
});
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `npx jest src/index.test.ts`
Expected: keypair tests PASS, new tests FAIL (`ShortyQ` not exported).

- [ ] **Step 3: Implement the class**

Add to `src/index.ts` — new imports at the top:

```typescript
import { nanoid } from "nanoid";
import { gcm } from "@noble/ciphers/aes";
import { randomBytes } from "crypto";
```

New interface after `EncryptedPayload`:

```typescript
/**
 * Configuration options for the ShortyQ URL shortener
 */
export interface ShortyQOptions {
  /** Base64-encoded ML-KEM-768 public key from generateKeyPair() */
  publicKey: string;
  /** Length of generated short codes (default: 8, range: 4-100) */
  urlLength?: number;
}
```

New class at the end of the file:

```typescript
/**
 * ShortyQ - a quantum-safe URL shortener.
 *
 * Encrypts URLs with ML-KEM-768 (NIST FIPS 203) + AES-256-GCM.
 * The instance only holds the public key; decryption requires the
 * secret key via the module-level decryptUrl().
 */
export class ShortyQ {
  private readonly publicKey: Uint8Array;
  private readonly urlLength: number;
  /** Maximum allowed length for input URLs */
  private readonly MAX_URL_LENGTH = 4096;
  /** Minimum allowed length for short codes */
  private readonly MIN_CODE_LENGTH = 4;
  /** Maximum allowed length for short codes */
  private readonly MAX_CODE_LENGTH = 100;

  /**
   * Creates a new ShortyQ instance
   * @param options Configuration; publicKey is required
   * @throws Error if the public key is missing/invalid or urlLength is out of bounds
   */
  constructor(options: ShortyQOptions) {
    if (!options || !options.publicKey) {
      throw new Error("Public key is required");
    }
    this.publicKey = fromBase64(options.publicKey);
    if (this.publicKey.length !== PUBLIC_KEY_BYTES) {
      throw new Error("Invalid ML-KEM-768 public key");
    }

    const urlLength = options.urlLength ?? 8;
    if (urlLength < this.MIN_CODE_LENGTH) {
      throw new Error(
        `URL length must be at least ${this.MIN_CODE_LENGTH} characters`
      );
    }
    if (urlLength > this.MAX_CODE_LENGTH) {
      throw new Error("URL length cannot exceed 100 characters");
    }
    this.urlLength = urlLength;
  }

  /**
   * Creates a short code and encrypts the URL against the public key.
   * Each call uses a fresh ML-KEM encapsulation (no key reuse across URLs).
   * @param originalUrl The URL to shorten
   * @returns The short code and an encrypted payload safe for DB storage
   * @throws Error if URL is empty, invalid, or exceeds maximum length
   */
  public createShortUrl(originalUrl: string): {
    shortCode: string;
    payload: EncryptedPayload;
  } {
    if (!originalUrl) {
      throw new Error("URL cannot be empty");
    }
    try {
      new URL(originalUrl);
    } catch (e) {
      throw new Error("Invalid URL format");
    }
    if (originalUrl.length > this.MAX_URL_LENGTH) {
      throw new Error(
        `URL length cannot exceed ${this.MAX_URL_LENGTH} characters`
      );
    }

    const { cipherText, sharedSecret } = ml_kem768.encapsulate(this.publicKey);
    const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
    const ciphertext = gcm(sharedSecret, nonce).encrypt(
      new Uint8Array(Buffer.from(originalUrl, "utf8"))
    );

    return {
      shortCode: nanoid(this.urlLength),
      payload: {
        kemCiphertext: toBase64(cipherText),
        nonce: toBase64(nonce),
        ciphertext: toBase64(ciphertext),
      },
    };
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx jest src/index.test.ts`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/index.ts src/index.test.ts
git commit -m "Add ShortyQ class with ML-KEM-768 + AES-256-GCM encryption"
```

---

### Task 4: decryptUrl round-trip

**Files:**
- Modify: `src/index.ts`
- Modify: `src/index.test.ts`

- [ ] **Step 1: Add failing round-trip tests**

Append to `src/index.test.ts` (add `decryptUrl` to the import from `./index`):

```typescript
describe("decryptUrl round-trip", () => {
  const { publicKey, secretKey } = generateKeyPair();
  const shortyQ = new ShortyQ({ publicKey });

  it.each([
    ["simple", "https://example.com/simple"],
    ["query params", "https://api.example.com/v1/users?id=123&format=json"],
    [
      "special chars",
      "https://example.com/path/with/special/chars/!@#$%^&*()",
    ],
    ["unicode", "https://example.com/unicode/path/🚀/测试/тест"],
    ["fragment", "https://example.com/page#section1"],
  ])("round-trips a URL with %s", (_label, url) => {
    const { payload } = shortyQ.createShortUrl(url);
    expect(decryptUrl(payload, secretKey)).toBe(url);
  });

  it("round-trips a maximum-length URL", () => {
    const url = `https://example.com/${"a".repeat(2048)}`;
    const { payload } = shortyQ.createShortUrl(url);
    expect(decryptUrl(payload, secretKey)).toBe(url);
  });

  it("round-trips many URLs concurrently", async () => {
    const urls = Array.from(
      { length: 100 },
      (_, i) => `https://example.com/test/${i}`
    );
    const results = await Promise.all(
      urls.map((url) => {
        const { payload } = shortyQ.createShortUrl(url);
        return { url, decrypted: decryptUrl(payload, secretKey) };
      })
    );
    results.forEach(({ url, decrypted }) => expect(decrypted).toBe(url));
  });
});
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `npx jest src/index.test.ts`
Expected: round-trip tests FAIL (`decryptUrl` not exported).

- [ ] **Step 3: Implement decryptUrl**

Add to `src/index.ts` after `generateKeyPair`:

```typescript
/**
 * Decrypts an encrypted URL payload using the secret key.
 * @param payload The encrypted payload from createShortUrl
 * @param secretKey Base64-encoded ML-KEM-768 secret key from generateKeyPair()
 * @returns The original URL, or null if the key is wrong, the payload is
 *          malformed, or the data was tampered with. Never throws.
 */
export function decryptUrl(
  payload: EncryptedPayload,
  secretKey: string
): string | null {
  try {
    if (
      !payload ||
      !payload.kemCiphertext ||
      !payload.nonce ||
      !payload.ciphertext ||
      !secretKey
    ) {
      return null;
    }

    const secretKeyBytes = fromBase64(secretKey);
    if (secretKeyBytes.length !== SECRET_KEY_BYTES) {
      return null;
    }
    const kemCiphertext = fromBase64(payload.kemCiphertext);
    if (kemCiphertext.length !== KEM_CIPHERTEXT_BYTES) {
      return null;
    }
    const nonce = fromBase64(payload.nonce);
    if (nonce.length !== NONCE_BYTES) {
      return null;
    }

    // A wrong-but-valid secret key doesn't throw here (ML-KEM implicit
    // rejection); it yields a different shared secret and GCM auth fails below.
    const sharedSecret = ml_kem768.decapsulate(kemCiphertext, secretKeyBytes);
    const plaintext = gcm(sharedSecret, nonce).decrypt(
      fromBase64(payload.ciphertext)
    );
    return Buffer.from(plaintext).toString("utf8");
  } catch (error) {
    return null;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx jest src/index.test.ts`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/index.ts src/index.test.ts
git commit -m "Add decryptUrl with ML-KEM decapsulation and GCM verification"
```

---

### Task 5: Failure modes — wrong key, tampering, malformed payloads

The implementation from Task 4 should already handle all of these; this task pins the security contract with tests. If any test fails, fix `decryptUrl` (the guards and try/catch are the only places to touch).

**Files:**
- Modify: `src/index.test.ts`
- Possibly modify: `src/index.ts` (only if a test exposes a gap)

- [ ] **Step 1: Add the failure-mode tests**

Append to `src/index.test.ts`:

```typescript
describe("decryptUrl failure modes", () => {
  const { publicKey, secretKey } = generateKeyPair();
  const shortyQ = new ShortyQ({ publicKey });
  const url = "https://example.com/secret/path";

  /** Flips the first character of a base64 string to corrupt the bytes */
  function corrupt(value: string): string {
    const replacement = value[0] === "A" ? "B" : "A";
    return replacement + value.slice(1);
  }

  it("returns null with a wrong secret key", () => {
    const otherPair = generateKeyPair();
    const { payload } = shortyQ.createShortUrl(url);
    expect(decryptUrl(payload, otherPair.secretKey)).toBeNull();
  });

  it("returns null when ciphertext is tampered with", () => {
    const { payload } = shortyQ.createShortUrl(url);
    const tampered = { ...payload, ciphertext: corrupt(payload.ciphertext) };
    expect(decryptUrl(tampered, secretKey)).toBeNull();
  });

  it("returns null when nonce is tampered with", () => {
    const { payload } = shortyQ.createShortUrl(url);
    const tampered = { ...payload, nonce: corrupt(payload.nonce) };
    expect(decryptUrl(tampered, secretKey)).toBeNull();
  });

  it("returns null when kemCiphertext is tampered with", () => {
    const { payload } = shortyQ.createShortUrl(url);
    const tampered = {
      ...payload,
      kemCiphertext: corrupt(payload.kemCiphertext),
    };
    expect(decryptUrl(tampered, secretKey)).toBeNull();
  });

  it("returns null for garbage payload fields", () => {
    const garbage = {
      kemCiphertext: "not-real-data",
      nonce: "nope",
      ciphertext: "garbage",
    };
    expect(decryptUrl(garbage, secretKey)).toBeNull();
  });

  it("returns null for a partial payload", () => {
    const { payload } = shortyQ.createShortUrl(url);
    const partial = {
      kemCiphertext: payload.kemCiphertext,
      nonce: payload.nonce,
    } as EncryptedPayload;
    expect(decryptUrl(partial, secretKey)).toBeNull();
  });

  it("returns null for a null payload", () => {
    expect(decryptUrl(null as any, secretKey)).toBeNull();
  });

  it("returns null for an empty secret key", () => {
    const { payload } = shortyQ.createShortUrl(url);
    expect(decryptUrl(payload, "")).toBeNull();
  });

  it("returns null for a malformed secret key", () => {
    const { payload } = shortyQ.createShortUrl(url);
    expect(decryptUrl(payload, "dG9vLXNob3J0")).toBeNull();
  });
});
```

Also add `EncryptedPayload` to the type import at the top of the test file:

```typescript
import {
  ShortyQ,
  generateKeyPair,
  decryptUrl,
  EncryptedPayload,
} from "./index";
```

(This consolidates the imports added in Tasks 2-4 into one statement.)

- [ ] **Step 2: Run the tests**

Run: `npx jest src/index.test.ts`
Expected: all tests PASS (implementation already guards these paths). If any FAIL, fix the corresponding guard in `decryptUrl` and re-run.

- [ ] **Step 3: Commit**

```bash
git add src/index.test.ts
git commit -m "Pin decryptUrl security contract with tampering and wrong-key tests"
```

---

### Task 6: Input validation and configuration errors

Like Task 5, the implementation from Task 3 should already pass these; the tests pin v1's preserved validation contract.

**Files:**
- Modify: `src/index.test.ts`
- Possibly modify: `src/index.ts` (only if a test exposes a gap)

- [ ] **Step 1: Add validation tests**

Append to `src/index.test.ts`:

```typescript
describe("validation", () => {
  const { publicKey } = generateKeyPair();
  const shortyQ = new ShortyQ({ publicKey });

  it("throws for an empty URL", () => {
    expect(() => shortyQ.createShortUrl("")).toThrow("URL cannot be empty");
  });

  it("throws for undefined and null URLs", () => {
    expect(() => shortyQ.createShortUrl(undefined as any)).toThrow(
      "URL cannot be empty"
    );
    expect(() => shortyQ.createShortUrl(null as any)).toThrow(
      "URL cannot be empty"
    );
  });

  it("throws for an invalid URL format", () => {
    expect(() => shortyQ.createShortUrl("not-a-valid-url")).toThrow(
      "Invalid URL format"
    );
  });

  it("throws for URLs exceeding 4096 characters", () => {
    const url = `https://example.com/${"a".repeat(8192)}`;
    expect(() => shortyQ.createShortUrl(url)).toThrow(
      "URL length cannot exceed 4096 characters"
    );
  });

  it("throws when constructed without a public key", () => {
    expect(() => new ShortyQ({} as any)).toThrow("Public key is required");
    expect(() => new ShortyQ(undefined as any)).toThrow(
      "Public key is required"
    );
  });

  it("throws for a public key of the wrong size", () => {
    const tooShort = Buffer.from("short").toString("base64");
    expect(() => new ShortyQ({ publicKey: tooShort })).toThrow(
      "Invalid ML-KEM-768 public key"
    );
  });

  it("throws for urlLength below 4", () => {
    expect(() => new ShortyQ({ publicKey, urlLength: 3 })).toThrow(
      "URL length must be at least 4 characters"
    );
  });

  it("throws for urlLength above 100", () => {
    expect(() => new ShortyQ({ publicKey, urlLength: 101 })).toThrow(
      "URL length cannot exceed 100 characters"
    );
  });
});
```

- [ ] **Step 2: Run the tests**

Run: `npx jest src/index.test.ts`
Expected: all tests PASS. If any FAIL, fix the corresponding check in the constructor or `createShortUrl` and re-run.

- [ ] **Step 3: Commit**

```bash
git add src/index.test.ts
git commit -m "Pin input validation contract with tests"
```

---

### Task 7: Remove crypto-js and verify the full build

**Files:**
- Modify: `package.json` (via npm)
- Modify: `package-lock.json` (via npm)

- [ ] **Step 1: Uninstall crypto-js**

Run: `npm uninstall crypto-js @types/crypto-js`
Expected: removed from `package.json`; only `@noble/ciphers`, `@noble/post-quantum`, `nanoid` remain as dependencies.

- [ ] **Step 2: Full verification**

Run: `npm test`
Expected: full suite PASS.

Run: `npm run build`
Expected: clean compile.

- [ ] **Step 3: Commit**

```bash
git add package.json package-lock.json
git commit -m "Remove crypto-js"
```

---

### Task 8: Update examples and benchmarks to the v2 API

These files are documentation-grade (not compiled by `npm run build`, not shipped to npm), but they must show the new API, including the key-handling model.

**Files:**
- Rewrite: `examples/demo.ts`
- Rewrite: `examples/databases/postgres.ts`
- Rewrite: `examples/databases/mongodb.ts`
- Rewrite: `examples/databases/redis.ts`
- Modify: `examples/README.md`
- Modify: `benchmarks/performance.ts`

- [ ] **Step 1: Rewrite examples/demo.ts**

Replace the ENTIRE contents with:

```typescript
import { ShortyQ, generateKeyPair, decryptUrl } from "shortyq";

// One-time setup: generate a key pair. In a real app, do this once and
// store the secret key in an env var or KMS — never in the database.
const { publicKey, secretKey } = generateKeyPair();

// Example 1: Basic Usage
function basicDemo() {
  console.log("\n🚀 Basic Usage Demo");
  console.log("==================");

  const shortyQ = new ShortyQ({ publicKey });

  const url = "https://example.com/very/long/path/that/needs/shortening";
  const { shortCode, payload } = shortyQ.createShortUrl(url);

  console.log("Original URL:", url);
  console.log("Short Code:", shortCode);
  console.log("Payload (safe to store):", payload);

  // Decryption requires the secret key
  const decryptedUrl = decryptUrl(payload, secretKey);
  console.log("Decrypted URL:", decryptedUrl);
  console.log("URLs match:", url === decryptedUrl);
}

// Example 2: Custom Configuration
function configDemo() {
  console.log("\n⚙️ Configuration Demo");
  console.log("=====================");

  const shortyQ = new ShortyQ({
    publicKey,
    urlLength: 10, // Longer short codes (4-100, default 8)
  });

  const url = "https://api.example.com/v1/users?sort=desc&limit=100";
  const { shortCode, payload } = shortyQ.createShortUrl(url);

  console.log("Original URL:", url);
  console.log("Short Code (10 chars):", shortCode);
  console.log("KEM ciphertext bytes:", Buffer.from(payload.kemCiphertext, "base64").length);
}

// Example 3: Error Handling
function errorHandlingDemo() {
  console.log("\n🚨 Error Handling Demo");
  console.log("=====================");

  const shortyQ = new ShortyQ({ publicKey });

  try {
    shortyQ.createShortUrl("");
  } catch (error: any) {
    console.log("Empty URL Error:", error.message);
  }

  try {
    shortyQ.createShortUrl("not-a-valid-url");
  } catch (error: any) {
    console.log("Invalid URL Error:", error.message);
  }

  const longUrl = "https://example.com/" + "a".repeat(5000);
  try {
    shortyQ.createShortUrl(longUrl);
  } catch (error: any) {
    console.log("Long URL Error:", error.message);
  }

  // Wrong key: decryption fails closed with null, never throws
  const { payload } = shortyQ.createShortUrl("https://example.com");
  const wrongKey = generateKeyPair().secretKey;
  console.log("Wrong key result:", decryptUrl(payload, wrongKey));
}

// Example 4: Different URL Types
function urlTypesDemo() {
  console.log("\n🌐 Different URL Types Demo");
  console.log("==========================");

  const shortyQ = new ShortyQ({ publicKey });

  const urls = [
    "https://example.com", // Basic URL
    "https://api.example.com/search?q=test&sort=desc", // Query parameters
    "https://example.com/path/with/special/chars/!@#$%^&*()", // Special characters
    "https://example.com/unicode/path/🚀/测试/тест", // Unicode characters
    "https://example.com/page#section1", // URL fragment
  ];

  urls.forEach((url, index) => {
    const { shortCode, payload } = shortyQ.createShortUrl(url);
    const decryptedUrl = decryptUrl(payload, secretKey);

    console.log(`\nURL ${index + 1}:`);
    console.log("Original:", url);
    console.log("Short Code:", shortCode);
    console.log("Decrypted:", decryptedUrl);
    console.log("Match:", url === decryptedUrl);
  });
}

// Run all demos
console.log("🎬 Starting ShortyQ Demos\n");
basicDemo();
configDemo();
errorHandlingDemo();
urlTypesDemo();
console.log("\n✨ All demos completed!");
```

- [ ] **Step 2: Rewrite examples/databases/postgres.ts**

Replace the ENTIRE contents with:

```typescript
import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  BaseEntity,
} from "typeorm";
import { ShortyQ, decryptUrl, EncryptedPayload } from "../../src/index";

@Entity("shortened_urls")
export class ShortenedURL extends BaseEntity {
  @PrimaryColumn()
  shortCode!: string;

  // Safe to store: useless without the secret key
  @Column("jsonb")
  payload!: EncryptedPayload;

  @CreateDateColumn()
  createdAt!: Date;

  @Column({ type: "timestamp", nullable: true })
  expiresAt?: Date;
}

export class PostgresURLService {
  private shortyQ: ShortyQ;
  private secretKey: string;

  /**
   * @param publicKey base64 ML-KEM-768 public key (from generateKeyPair)
   * @param secretKey base64 secret key — load from an env var or KMS,
   *                  e.g. process.env.SHORTYQ_SECRET_KEY
   */
  constructor(publicKey: string, secretKey: string, urlLength?: number) {
    this.shortyQ = new ShortyQ({ publicKey, urlLength });
    this.secretKey = secretKey;
  }

  async shortenUrl(url: string, expiresIn?: number): Promise<string> {
    const { shortCode, payload } = this.shortyQ.createShortUrl(url);

    const shortenedURL = new ShortenedURL();
    shortenedURL.shortCode = shortCode;
    shortenedURL.payload = payload;
    if (expiresIn) {
      shortenedURL.expiresAt = new Date(Date.now() + expiresIn);
    }

    await shortenedURL.save();
    return shortCode;
  }

  async getOriginalUrl(shortCode: string): Promise<string | null> {
    const record = await ShortenedURL.findOne({
      where: {
        shortCode,
        expiresAt: {
          $gt: new Date(),
        },
      },
    });

    if (!record) return null;
    return decryptUrl(record.payload, this.secretKey);
  }

  async deleteUrl(shortCode: string): Promise<void> {
    await ShortenedURL.delete({ shortCode });
  }

  async cleanup(): Promise<void> {
    // Delete expired URLs
    await ShortenedURL.delete({
      expiresAt: {
        $lt: new Date(),
      },
    });
  }
}
```

- [ ] **Step 3: Rewrite examples/databases/mongodb.ts**

Replace the ENTIRE contents with:

```typescript
import mongoose, { Schema, Document } from "mongoose";
import { ShortyQ, decryptUrl, EncryptedPayload } from "../../src/index";

interface IShortenedURL extends Document {
  shortCode: string;
  payload: EncryptedPayload;
  createdAt: Date;
  expiresAt?: Date;
}

const ShortenedURLSchema = new Schema({
  shortCode: { type: String, required: true, unique: true, index: true },
  // Safe to store: useless without the secret key
  payload: {
    kemCiphertext: { type: String, required: true },
    nonce: { type: String, required: true },
    ciphertext: { type: String, required: true },
  },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date },
});

// Create TTL index for auto-expiration
ShortenedURLSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const ShortenedURL = mongoose.model<IShortenedURL>(
  "ShortenedURL",
  ShortenedURLSchema
);

export class MongoURLService {
  private shortyQ: ShortyQ;
  private secretKey: string;

  /**
   * @param publicKey base64 ML-KEM-768 public key (from generateKeyPair)
   * @param secretKey base64 secret key — load from an env var or KMS,
   *                  e.g. process.env.SHORTYQ_SECRET_KEY
   */
  constructor(publicKey: string, secretKey: string, urlLength?: number) {
    this.shortyQ = new ShortyQ({ publicKey, urlLength });
    this.secretKey = secretKey;
  }

  async shortenUrl(url: string, expiresIn?: number): Promise<string> {
    const { shortCode, payload } = this.shortyQ.createShortUrl(url);

    await ShortenedURL.create({
      shortCode,
      payload,
      expiresAt: expiresIn ? new Date(Date.now() + expiresIn) : undefined,
    });

    return shortCode;
  }

  async getOriginalUrl(shortCode: string): Promise<string | null> {
    const record = await ShortenedURL.findOne({
      shortCode,
      $or: [
        { expiresAt: { $exists: false } },
        { expiresAt: { $gt: new Date() } },
      ],
    });

    if (!record) return null;
    return decryptUrl(record.payload, this.secretKey);
  }

  async deleteUrl(shortCode: string): Promise<void> {
    await ShortenedURL.deleteOne({ shortCode });
  }

  async cleanup(): Promise<void> {
    // MongoDB TTL index handles cleanup automatically
    // This method is kept for API consistency
  }
}
```

- [ ] **Step 4: Rewrite examples/databases/redis.ts**

Replace the ENTIRE contents with:

```typescript
import Redis from "ioredis";
import { ShortyQ, decryptUrl, EncryptedPayload } from "../../src/index";

export class RedisURLService {
  private shortyQ: ShortyQ;
  private secretKey: string;
  private redis: Redis;
  private prefix: string;

  /**
   * @param publicKey base64 ML-KEM-768 public key (from generateKeyPair)
   * @param secretKey base64 secret key — load from an env var or KMS,
   *                  e.g. process.env.SHORTYQ_SECRET_KEY
   */
  constructor(
    publicKey: string,
    secretKey: string,
    redisOptions = {},
    urlLength?: number,
    prefix = "shortyq:"
  ) {
    this.shortyQ = new ShortyQ({ publicKey, urlLength });
    this.secretKey = secretKey;
    this.redis = new Redis(redisOptions);
    this.prefix = prefix;
  }

  private getKey(shortCode: string): string {
    return `${this.prefix}${shortCode}`;
  }

  async shortenUrl(url: string, expiresIn?: number): Promise<string> {
    const { shortCode, payload } = this.shortyQ.createShortUrl(url);
    const key = this.getKey(shortCode);

    // Store as hash to maintain data structure
    await this.redis
      .multi()
      .hmset(key, {
        kemCiphertext: payload.kemCiphertext,
        nonce: payload.nonce,
        ciphertext: payload.ciphertext,
      })
      .expire(key, Math.floor((expiresIn || 2592000000) / 1000)) // Default 30 days
      .exec();

    return shortCode;
  }

  async getOriginalUrl(shortCode: string): Promise<string | null> {
    const key = this.getKey(shortCode);
    const data = await this.redis.hgetall(key);

    if (!data || !data.kemCiphertext || !data.nonce || !data.ciphertext) {
      return null;
    }

    const payload: EncryptedPayload = {
      kemCiphertext: data.kemCiphertext,
      nonce: data.nonce,
      ciphertext: data.ciphertext,
    };

    return decryptUrl(payload, this.secretKey);
  }

  async deleteUrl(shortCode: string): Promise<void> {
    await this.redis.del(this.getKey(shortCode));
  }

  async cleanup(): Promise<void> {
    // Redis TTL handles cleanup automatically
    // This method is kept for API consistency
  }

  async disconnect(): Promise<void> {
    await this.redis.quit();
  }
}
```

- [ ] **Step 5: Update benchmarks/performance.ts**

In `benchmarks/performance.ts`, make these changes:

Replace the import line:

```typescript
import { ShortyQ, generateKeyPair, decryptUrl } from "../src/index";
```

Replace the constructor:

```typescript
  constructor(iterations = 1000) {
    const { publicKey, secretKey } = generateKeyPair();
    this.shortyQ = new ShortyQ({ publicKey });
    this.secretKey = secretKey;
    this.iterations = iterations;
  }
```

Add the field declaration next to the other private fields:

```typescript
  private secretKey: string;
```

Replace `runDecryptionBenchmark` with:

```typescript
  async runDecryptionBenchmark() {
    const url = "https://example.com/test";
    const { payload } = this.shortyQ.createShortUrl(url);
    await this.measure("URL Decryption", async () => {
      for (let i = 0; i < this.iterations; i++) {
        decryptUrl(payload, this.secretKey);
      }
    });
  }
```

Everything else in the file is API-compatible and stays unchanged.

- [ ] **Step 6: Update examples/README.md**

Replace the "Database Integration Examples" section's three code blocks with constructor calls matching the new signatures, and remove all mentions of `saltRounds`/`quantumSeed`. Replace the three code blocks with:

```typescript
import { generateKeyPair } from "shortyq";
import { PostgresURLService } from "shortyq/examples/databases/postgres";

// One-time: generate keys, store secretKey in an env var or KMS
const { publicKey, secretKey } = generateKeyPair();

const postgresService = new PostgresURLService(
  publicKey,
  process.env.SHORTYQ_SECRET_KEY!
);

// Create short URL with 24-hour expiration
const shortCode = await postgresService.shortenUrl(
  "https://example.com",
  24 * 60 * 60 * 1000
);
```

```typescript
import { MongoURLService } from "shortyq/examples/databases/mongodb";

const mongoService = new MongoURLService(
  publicKey,
  process.env.SHORTYQ_SECRET_KEY!
);

await mongoService.shortenUrl("https://example.com");
```

```typescript
import { RedisURLService } from "shortyq/examples/databases/redis";

const redisService = new RedisURLService(
  publicKey,
  process.env.SHORTYQ_SECRET_KEY!,
  { host: "localhost", port: 6379 }
);

// Create short URL with 1-hour expiration
await redisService.shortenUrl("https://example.com", 3600);
```

In the "Demo Contents" section, change item 2 from "Custom URL length / Custom salt rounds / Fixed quantum seed" to "Custom URL length / Key pair generation and handling", and remove item 5 ("Performance") since the demo no longer includes a perf section.

- [ ] **Step 7: Type-check the benchmark against the new API**

Run: `npx tsc --noEmit benchmarks/performance.ts`
Expected: clean — the benchmark imports from `../src/index` directly, so this verifies the v2 API usage compiles. (The `examples/` files import third-party packages like `typeorm`/`mongoose`/`ioredis` that aren't installed here; they are reviewed by eye, not compiled.)

- [ ] **Step 8: Commit**

```bash
git add examples benchmarks
git commit -m "Update examples and benchmarks to v2 key pair API"
```

---

### Task 9: Package metadata, CHANGELOG, README

**Files:**
- Modify: `package.json`
- Modify: `CHANGELOG.md`
- Rewrite: `README.md`

- [ ] **Step 1: Update package.json metadata**

Change these fields (leave everything else untouched):

```json
"version": "2.0.0",
"description": "A quantum-safe URL shortener using NIST-standardized post-quantum cryptography (ML-KEM-768)",
"keywords": [
  "url-shortener",
  "post-quantum",
  "quantum-safe",
  "ml-kem",
  "kyber",
  "encryption",
  "typescript",
  "secure",
  "url",
  "shortener",
  "crypto"
],
"engines": {
  "node": ">=18.0.0"
}
```

(The pre-existing 1.0.1 bump was already committed in Task 1 Step 0, so this is a clean `1.0.1 -> 2.0.0` change.)

- [ ] **Step 2: Add CHANGELOG entry**

Add above the `## [1.0.1]` entry in `CHANGELOG.md`:

```markdown
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
```

Also fix the Keep a Changelog link in the file header: change `https://keepachangelog.com/en/1.0.1/` to `https://keepachangelog.com/en/1.0.0/` (the canonical URL).

- [ ] **Step 3: Rewrite README.md**

Replace the ENTIRE contents with:

```markdown
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

| Option      | Type   | Required | Default | Description                          |
| ----------- | ------ | -------- | ------- | ------------------------------------ |
| `publicKey` | string | yes      | —       | Base64 public key from `generateKeyPair()` |
| `urlLength` | number | no       | 8       | Short code length (4-100)            |

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
```

- [ ] **Step 4: Final verification**

Run: `npm test`
Expected: full suite PASS.

Run: `npm run build`
Expected: clean compile.

- [ ] **Step 5: Commit**

```bash
git add package.json CHANGELOG.md README.md
git commit -m "Release v2.0.0: quantum-safe rewrite with ML-KEM-768"
```
