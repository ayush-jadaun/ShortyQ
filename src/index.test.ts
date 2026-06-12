import {
  ShortyQ,
  generateKeyPair,
  decryptUrl,
  decryptPayload,
  getKeyId,
  EncryptedPayload,
} from "./index";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { gcm } from "@noble/ciphers/aes";
import { randomBytes } from "crypto";

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

describe("envelope: expiry and metadata", () => {
  const { publicKey, secretKey } = generateKeyPair();
  const shortyQ = new ShortyQ({ publicKey });
  const url = "https://example.com/campaign";

  afterEach(() => {
    jest.useRealTimers();
  });

  it("round-trips a plain URL through decryptPayload", () => {
    const { payload } = shortyQ.createShortUrl(url);
    expect(decryptPayload(payload, secretKey)).toEqual({ url });
  });

  it("round-trips metadata", () => {
    const metadata = { creator: "ayush", tags: ["promo", 7], nested: { a: 1 } };
    const { payload } = shortyQ.createShortUrl(url, { metadata });
    const result = decryptPayload(payload, secretKey);
    expect(result?.url).toBe(url);
    expect(result?.metadata).toEqual(metadata);
  });

  it("round-trips expiry and exposes it as a Date", () => {
    jest.useFakeTimers({ now: new Date("2026-06-12T00:00:00Z") });
    const expiresAt = new Date("2026-06-12T01:00:00Z");
    const { payload } = shortyQ.createShortUrl(url, { expiresAt });
    const result = decryptPayload(payload, secretKey);
    expect(result?.url).toBe(url);
    expect(result?.expiresAt).toEqual(expiresAt);
  });

  it("returns null from both decrypt functions after expiry", () => {
    jest.useFakeTimers({ now: new Date("2026-06-12T00:00:00Z") });
    const { payload } = shortyQ.createShortUrl(url, {
      expiresAt: new Date("2026-06-12T01:00:00Z"),
    });
    expect(decryptUrl(payload, secretKey)).toBe(url);
    jest.setSystemTime(new Date("2026-06-12T02:00:00Z"));
    expect(decryptUrl(payload, secretKey)).toBeNull();
    expect(decryptPayload(payload, secretKey)).toBeNull();
  });

  it("accepts expiresAt as epoch millis", () => {
    jest.useFakeTimers({ now: new Date("2026-06-12T00:00:00Z") });
    const epoch = new Date("2026-06-12T01:00:00Z").getTime();
    const { payload } = shortyQ.createShortUrl(url, { expiresAt: epoch });
    expect(decryptPayload(payload, secretKey)?.expiresAt).toEqual(
      new Date(epoch)
    );
  });

  it("throws for an expiresAt in the past", () => {
    expect(() =>
      shortyQ.createShortUrl(url, { expiresAt: Date.now() - 1000 })
    ).toThrow("expiresAt must be in the future");
  });

  it("throws for non-JSON-serializable metadata", () => {
    expect(() =>
      shortyQ.createShortUrl(url, { metadata: () => 42 })
    ).toThrow("Metadata must be JSON-serializable");
    const circular: any = {};
    circular.self = circular;
    expect(() =>
      shortyQ.createShortUrl(url, { metadata: circular })
    ).toThrow("Metadata must be JSON-serializable");
  });

  it("decrypts v2.0-era payloads (bare URL, no extra fields)", () => {
    const pk = new Uint8Array(Buffer.from(publicKey, "base64"));
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(pk);
    const nonce = new Uint8Array(randomBytes(12));
    const ct = gcm(sharedSecret, nonce).encrypt(
      new Uint8Array(Buffer.from(url, "utf8"))
    );
    const legacy: EncryptedPayload = {
      kemCiphertext: Buffer.from(cipherText).toString("base64"),
      nonce: Buffer.from(nonce).toString("base64"),
      ciphertext: Buffer.from(ct).toString("base64"),
    };
    expect(decryptUrl(legacy, secretKey)).toBe(url);
    expect(decryptPayload(legacy, secretKey)).toEqual({ url });
  });
});

describe("password-protected links", () => {
  const { publicKey, secretKey } = generateKeyPair();
  const shortyQ = new ShortyQ({ publicKey });
  const url = "https://example.com/private";

  it("round-trips with the correct password", () => {
    const { payload } = shortyQ.createShortUrl(url, { password: "hunter2" });
    expect(payload.kdfSalt).toBeDefined();
    expect(Buffer.from(payload.kdfSalt!, "base64")).toHaveLength(16);
    expect(decryptUrl(payload, secretKey, { password: "hunter2" })).toBe(url);
  });

  it("returns null with a wrong password", () => {
    const { payload } = shortyQ.createShortUrl(url, { password: "hunter2" });
    expect(decryptUrl(payload, secretKey, { password: "hunter3" })).toBeNull();
  });

  it("returns null when the password is missing", () => {
    const { payload } = shortyQ.createShortUrl(url, { password: "hunter2" });
    expect(decryptUrl(payload, secretKey)).toBeNull();
  });

  it("returns null when a password is supplied for a passwordless link", () => {
    const { payload } = shortyQ.createShortUrl(url);
    expect(decryptUrl(payload, secretKey, { password: "hunter2" })).toBeNull();
  });

  it("combines password with metadata and expiry", () => {
    jest.useFakeTimers({ now: new Date("2026-06-12T00:00:00Z") });
    const { payload } = shortyQ.createShortUrl(url, {
      password: "hunter2",
      metadata: { tier: "vip" },
      expiresAt: new Date("2026-06-12T01:00:00Z"),
    });
    const result = decryptPayload(payload, secretKey, { password: "hunter2" });
    expect(result?.url).toBe(url);
    expect(result?.metadata).toEqual({ tier: "vip" });
    expect(result?.expiresAt).toEqual(new Date("2026-06-12T01:00:00Z"));
    jest.useRealTimers();
  });
});

describe("key rotation", () => {
  const pairA = generateKeyPair();
  const pairB = generateKeyPair();
  const url = "https://example.com/rotated";

  it("stamps payloads with the public key's keyId", () => {
    const shortyQ = new ShortyQ({ publicKey: pairA.publicKey });
    const { payload } = shortyQ.createShortUrl(url);
    expect(payload.keyId).toBe(getKeyId(pairA.publicKey));
    expect(Buffer.from(payload.keyId!, "base64")).toHaveLength(8);
  });

  it("gives different keyIds for different public keys", () => {
    expect(getKeyId(pairA.publicKey)).not.toBe(getKeyId(pairB.publicKey));
  });

  it("throws for an invalid public key", () => {
    expect(() => getKeyId("bm9wZQ==")).toThrow("Invalid ML-KEM-768 public key");
  });

  it("decrypts with an array containing the right key", () => {
    const shortyQ = new ShortyQ({ publicKey: pairA.publicKey });
    const { payload } = shortyQ.createShortUrl(url);
    expect(
      decryptUrl(payload, [pairB.secretKey, pairA.secretKey])
    ).toBe(url);
  });

  it("returns null when no key in the array matches", () => {
    const shortyQ = new ShortyQ({ publicKey: pairA.publicKey });
    const { payload } = shortyQ.createShortUrl(url);
    expect(decryptUrl(payload, [pairB.secretKey])).toBeNull();
    expect(decryptUrl(payload, [])).toBeNull();
  });
});

describe("deterministic short codes", () => {
  const { publicKey, secretKey, codeKey } = generateKeyPair();
  const url = "https://example.com/dedupe-me";

  it("generateKeyPair returns a 32-byte codeKey", () => {
    expect(Buffer.from(codeKey, "base64")).toHaveLength(32);
  });

  it("yields the same code across instances for the same URL", () => {
    const a = new ShortyQ({ publicKey, codeKey });
    const b = new ShortyQ({ publicKey, codeKey });
    const codeA = a.createShortUrl(url, { deterministic: true }).shortCode;
    const codeB = b.createShortUrl(url, { deterministic: true }).shortCode;
    expect(codeA).toBe(codeB);
    expect(codeA).toHaveLength(8);
    expect(codeA).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("yields different codes for different URLs and different codeKeys", () => {
    const a = new ShortyQ({ publicKey, codeKey });
    const other = new ShortyQ({
      publicKey,
      codeKey: generateKeyPair().codeKey,
    });
    expect(
      a.createShortUrl(url, { deterministic: true }).shortCode
    ).not.toBe(
      a.createShortUrl("https://example.com/other", { deterministic: true })
        .shortCode
    );
    expect(
      a.createShortUrl(url, { deterministic: true }).shortCode
    ).not.toBe(other.createShortUrl(url, { deterministic: true }).shortCode);
  });

  it("still encrypts freshly even when the code is deterministic", () => {
    const a = new ShortyQ({ publicKey, codeKey });
    const r1 = a.createShortUrl(url, { deterministic: true });
    const r2 = a.createShortUrl(url, { deterministic: true });
    expect(r1.payload.kemCiphertext).not.toBe(r2.payload.kemCiphertext);
    expect(decryptUrl(r1.payload, secretKey)).toBe(url);
  });

  it("throws when deterministic is used without a codeKey", () => {
    const a = new ShortyQ({ publicKey });
    expect(() => a.createShortUrl(url, { deterministic: true })).toThrow(
      "Deterministic codes require a codeKey"
    );
  });

  it("throws for an invalid codeKey", () => {
    expect(
      () => new ShortyQ({ publicKey, codeKey: "dG9vLXNob3J0" })
    ).toThrow("Invalid code key");
  });
});
