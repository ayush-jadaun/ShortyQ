import { ShortyQ } from "shortyq";

// Example 1: Basic Usage
async function basicDemo() {
  console.log("\n🚀 Basic Usage Demo");
  console.log("==================");

  // Initialize with default options
  const shortyQ = new ShortyQ();

  // Create a short URL
  const url = "https://example.com/very/long/path/that/needs/shortening";
  const { shortCode, encryptedData } = shortyQ.createShortUrl(url);

  console.log("Original URL:", url);
  console.log("Short Code:", shortCode);
  console.log("Encrypted Data:", encryptedData);

  // Decrypt the URL
  const decryptedUrl = shortyQ.decryptUrl(encryptedData);
  console.log("Decrypted URL:", decryptedUrl);
  console.log("URLs match:", url === decryptedUrl);
}

// Example 2: Advanced Configuration
async function advancedConfigDemo() {
  console.log("\n⚙️ Advanced Configuration Demo");
  console.log("=============================");

  // Initialize with custom options
  const shortyQ = new ShortyQ({
    urlLength: 10, // Longer short codes
    saltRounds: 15, // More secure but slower
    quantumSeed: 42, // Fixed seed for reproducibility
  });

  const url = "https://api.example.com/v1/users?sort=desc&limit=100";
  const { shortCode, encryptedData } = shortyQ.createShortUrl(url);

  console.log("Original URL:", url);
  console.log("Short Code (10 chars):", shortCode);
  console.log("Encrypted Data:", encryptedData);
}

// Example 3: Error Handling
async function errorHandlingDemo() {
  console.log("\n🚨 Error Handling Demo");
  console.log("=====================");

  const shortyQ = new ShortyQ();

  // Test empty URL
  try {
    shortyQ.createShortUrl("");
  } catch (error: any) {
    console.log("Empty URL Error:", error.message);
  }

  // Test invalid URL
  try {
    shortyQ.createShortUrl("not-a-valid-url");
  } catch (error: any) {
    console.log("Invalid URL Error:", error.message);
  }

  // Test URL exceeding maximum length
  const longUrl = "https://example.com/" + "a".repeat(5000);
  try {
    shortyQ.createShortUrl(longUrl);
  } catch (error: any) {
    console.log("Long URL Error:", error.message);
  }
}

// Example 4: Different URL Types
async function urlTypesDemo() {
  console.log("\n🌐 Different URL Types Demo");
  console.log("==========================");

  const shortyQ = new ShortyQ();

  // Test URLs with different characteristics
  const urls = [
    "https://example.com", // Basic URL
    "https://api.example.com/search?q=test&sort=desc", // Query parameters
    "https://example.com/path/with/special/chars/!@#$%^&*()", // Special characters
    "https://example.com/unicode/path/🚀/测试/тест", // Unicode characters
    "https://example.com/page#section1", // URL fragment
  ];

  urls.forEach((url, index) => {
    const { shortCode, encryptedData } = shortyQ.createShortUrl(url);
    const decryptedUrl = shortyQ.decryptUrl(encryptedData);

    console.log(`\nURL ${index + 1}:`);
    console.log("Original:", url);
    console.log("Short Code:", shortCode);
    console.log("Decrypted:", decryptedUrl);
    console.log("Match:", url === decryptedUrl);
  });
}

// Example 5: Performance Demo
async function performanceDemo() {
  console.log("\n⚡ Performance Demo");
  console.log("==================");

  const shortyQ = new ShortyQ();
  const iterations = 100;
  const url = "https://example.com/test";

  // Measure encryption time
  const encryptStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    shortyQ.createShortUrl(url);
  }
  const encryptTime = (performance.now() - encryptStart) / iterations;

  // Measure decryption time
  const { encryptedData } = shortyQ.createShortUrl(url);
  const decryptStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    shortyQ.decryptUrl(encryptedData);
  }
  const decryptTime = (performance.now() - decryptStart) / iterations;

  console.log(`Average encryption time: ${encryptTime.toFixed(2)}ms`);
  console.log(`Average decryption time: ${decryptTime.toFixed(2)}ms`);
}

// Run all demos
async function runAllDemos() {
  console.log("🎬 Starting ShortyQ Demos\n");

  await basicDemo();
  await advancedConfigDemo();
  await errorHandlingDemo();
  await urlTypesDemo();
  await performanceDemo();

  console.log("\n✨ All demos completed!");
}

// Run the demos
runAllDemos().catch(console.error);
