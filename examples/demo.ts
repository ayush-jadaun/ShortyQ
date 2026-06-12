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
  console.log(
    "KEM ciphertext bytes:",
    Buffer.from(payload.kemCiphertext, "base64").length
  );
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
