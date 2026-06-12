import { ShortyQ, generateKeyPair } from "./index";

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
