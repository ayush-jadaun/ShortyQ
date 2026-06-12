import {
  ShortyQ,
  generateKeyPair,
  decryptUrl,
  EncryptedPayload,
} from "./index";

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
