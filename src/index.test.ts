import { ShortyQ, EncryptedData } from "./index";

describe("ShortyQ", () => {
  let shortyQ: ShortyQ;

  beforeEach(() => {
    // Create a new instance with fixed seed for reproducible tests
    shortyQ = new ShortyQ({
      urlLength: 6,
      saltRounds: 10,
      quantumSeed: 42,
    });
  });

  describe("URL Shortening", () => {
    it("should generate short codes of specified length", () => {
      const url = "https://example.com";
      const { shortCode } = shortyQ.createShortUrl(url);
      expect(shortCode).toHaveLength(6);
    });

    it("should generate different codes for same URL", () => {
      const url = "https://example.com";
      const result1 = shortyQ.createShortUrl(url);
      const result2 = shortyQ.createShortUrl(url);
      expect(result1.shortCode).not.toBe(result2.shortCode);
    });

    it("should handle URLs with query parameters", () => {
      const url = "https://example.com/api?param1=value1&param2=value2";
      const { encryptedData } = shortyQ.createShortUrl(url);
      const decrypted = shortyQ.decryptUrl(encryptedData);
      expect(decrypted).toBe(url);
    });

    it("should handle URLs with special characters", () => {
      const url = "https://example.com/path/with/special/chars/!@#$%^&*()";
      const { encryptedData } = shortyQ.createShortUrl(url);
      const decrypted = shortyQ.decryptUrl(encryptedData);
      expect(decrypted).toBe(url);
    });

    it("should handle URLs with Unicode characters", () => {
      const url = "https://example.com/unicode/path/🚀/测试/тест";
      const { encryptedData } = shortyQ.createShortUrl(url);
      const decrypted = shortyQ.decryptUrl(encryptedData);
      expect(decrypted).toBe(url);
    });

    it("should handle maximum length URLs", () => {
      const longPath = "a".repeat(2048);
      const url = `https://example.com/${longPath}`;
      const { encryptedData } = shortyQ.createShortUrl(url);
      const decrypted = shortyQ.decryptUrl(encryptedData);
      expect(decrypted).toBe(url);
    });

    it("should handle URLs with fragments", () => {
      const url = "https://example.com/page#section1";
      const { encryptedData } = shortyQ.createShortUrl(url);
      const decrypted = shortyQ.decryptUrl(encryptedData);
      expect(decrypted).toBe(url);
    });
  });

  describe("Encryption/Decryption", () => {
    it("should encrypt and decrypt URLs maintaining data integrity", () => {
      const urls = [
        "https://example.com/simple",
        "https://api.example.com/v1/users?id=123&format=json",
        "https://example.com/path/with/special/chars/!@#$%^&*()",
        "https://example.com/unicode/path/🚀/测试/тест",
      ];

      urls.forEach((url) => {
        const { encryptedData } = shortyQ.createShortUrl(url);
        const decrypted = shortyQ.decryptUrl(encryptedData);
        expect(decrypted).toBe(url);
      });
    });

    it("should generate different encrypted data for same URL", () => {
      const url = "https://example.com";
      const result1 = shortyQ.createShortUrl(url);
      const result2 = shortyQ.createShortUrl(url);

      expect(result1.encryptedData.data).not.toBe(result2.encryptedData.data);
      expect(result1.encryptedData.noise).not.toBe(result2.encryptedData.noise);
      expect(result1.encryptedData.iv).not.toBe(result2.encryptedData.iv);
    });

    it("should return null for invalid encrypted data", () => {
      const invalidData: EncryptedData = {
        data: "invalid",
        noise: "invalid",
        iv: "invalid",
      };
      const result = shortyQ.decryptUrl(invalidData);
      expect(result).toBeNull();
    });

    it("should handle encryption with different quantum seeds", () => {
      const url = "https://example.com";
      const shortyQ1 = new ShortyQ({ quantumSeed: 42 });
      const shortyQ2 = new ShortyQ({ quantumSeed: 43 });

      const result1 = shortyQ1.createShortUrl(url);
      const result2 = shortyQ2.createShortUrl(url);

      expect(result1.encryptedData.noise).not.toBe(result2.encryptedData.noise);
      expect(shortyQ1.decryptUrl(result1.encryptedData)).toBe(url);
      expect(shortyQ2.decryptUrl(result2.encryptedData)).toBe(url);
    });

    it("should handle partial encrypted data", () => {
      const partialData = {
        data: "somedata",
        noise: "somenoise",
      } as EncryptedData;
      const result = shortyQ.decryptUrl(partialData);
      expect(result).toBeNull();
    });

    it("should handle null encrypted data", () => {
      const result = shortyQ.decryptUrl(null as any);
      expect(result).toBeNull();
    });
  });

  describe("Error Handling", () => {
    it("should throw error for empty URL", () => {
      expect(() => shortyQ.createShortUrl("")).toThrow("URL cannot be empty");
    });

    it("should throw error for invalid URL format", () => {
      expect(() => shortyQ.createShortUrl("not-a-valid-url")).toThrow(
        "Invalid URL format"
      );
    });

    it("should handle undefined URL", () => {
      expect(() => shortyQ.createShortUrl(undefined as any)).toThrow(
        "URL cannot be empty"
      );
    });

    it("should handle null URL", () => {
      expect(() => shortyQ.createShortUrl(null as any)).toThrow(
        "URL cannot be empty"
      );
    });

    it("should throw error for URLs exceeding maximum length", () => {
      const longPath = "a".repeat(8192);
      const url = `https://example.com/${longPath}`;
      expect(() => shortyQ.createShortUrl(url)).toThrow();
    });
  });

  describe("Configuration", () => {
    it("should respect custom URL length", () => {
      const customShortyQ = new ShortyQ({ urlLength: 10 });
      const { shortCode } = customShortyQ.createShortUrl("https://example.com");
      expect(shortCode).toHaveLength(10);
    });

    it("should use default values when no options provided", () => {
      const defaultShortyQ = new ShortyQ();
      const { shortCode } = defaultShortyQ.createShortUrl(
        "https://example.com"
      );
      expect(shortCode).toHaveLength(8);
    });

    it("should handle custom salt rounds", () => {
      const customShortyQ = new ShortyQ({ saltRounds: 15 });
      const url = "https://example.com";
      const { encryptedData } = customShortyQ.createShortUrl(url);
      const decrypted = customShortyQ.decryptUrl(encryptedData);
      expect(decrypted).toBe(url);
    });

    it("should throw error for URL length below minimum", () => {
      expect(() => new ShortyQ({ urlLength: 3 })).toThrow(
        "URL length must be at least 4 characters"
      );
    });

    it("should throw error for URL length above maximum", () => {
      expect(() => new ShortyQ({ urlLength: 101 })).toThrow(
        "URL length cannot exceed 100 characters"
      );
    });
  });

  describe("Performance", () => {
    it("should handle rapid encryption/decryption cycles", () => {
      const url = "https://example.com";
      const cycles = 100;

      const start = performance.now();
      for (let i = 0; i < cycles; i++) {
        const { encryptedData } = shortyQ.createShortUrl(url);
        const decrypted = shortyQ.decryptUrl(encryptedData);
        expect(decrypted).toBe(url);
      }
      const end = performance.now();
      const avgTime = (end - start) / cycles;

      expect(avgTime).toBeLessThan(50); // Average time should be less than 50ms
    });

    it("should handle concurrent operations", async () => {
      const urls = Array.from(
        { length: 100 },
        (_, i) => `https://example.com/test/${i}`
      );

      const results = await Promise.all(
        urls.map((url) => {
          const { encryptedData } = shortyQ.createShortUrl(url);
          const decrypted = shortyQ.decryptUrl(encryptedData);
          return { url, decrypted };
        })
      );

      results.forEach(({ url, decrypted }) => {
        expect(decrypted).toBe(url);
      });
    });
  });
});
