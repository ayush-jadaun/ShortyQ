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
