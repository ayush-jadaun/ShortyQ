import { ShortyQ } from "./index";

describe("ShortyQ", () => {
  let shortyQ: ShortyQ;

  beforeEach(() => {
    shortyQ = new ShortyQ();
  });

  it("should create short URLs", () => {
    const originalUrl = "https://example.com/very/long/url/path";
    const shortCode = shortyQ.shortenUrl(originalUrl);

    expect(shortCode).toBeDefined();
    expect(typeof shortCode).toBe("string");
    expect(shortCode.length).toBe(8); // default length
  });

  it("should store and retrieve URLs", () => {
    const originalUrl = "https://example.com/test";
    const shortCode = shortyQ.shortenUrl(originalUrl);
    const storedUrl = shortyQ.getOriginalUrl(shortCode);

    expect(storedUrl).not.toBeNull();
  });

  it("should return null for non-existent short codes", () => {
    const result = shortyQ.getOriginalUrl("nonexistent");
    expect(result).toBeNull();
  });

  it("should throw error for invalid URLs", () => {
    expect(() => {
      shortyQ.shortenUrl("not-a-url");
    }).toThrow("Invalid URL format");
  });

  it("should throw error for empty URLs", () => {
    expect(() => {
      shortyQ.shortenUrl("");
    }).toThrow("URL cannot be empty");
  });

  it("should clear stored URLs", () => {
    const url = "https://example.com";
    const shortCode = shortyQ.shortenUrl(url);

    shortyQ.clearUrls();

    expect(shortyQ.getOriginalUrl(shortCode)).toBeNull();
  });

  it("should generate different codes for same URL", () => {
    const url = "https://example.com";
    const code1 = shortyQ.shortenUrl(url);
    const code2 = shortyQ.shortenUrl(url);

    expect(code1).not.toBe(code2);
  });
});
