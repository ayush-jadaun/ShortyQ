import { ShortyQ } from "./index";

// Create a new instance with custom options
const shortyQ = new ShortyQ({
  urlLength: 6,
  saltRounds: 12,
  quantumSeed: Math.random() * 1000,
});

// Test URLs
const urls = [
  "https://www.example.com/very/long/path/to/some/resource",
  "https://github.com/features/actions",
  "https://www.google.com/search?q=typescript+url+shortener",
  "https://www.npmjs.com/package/shortyq",
];

console.log("🚀 ShortyQ Demo\n");

// Test URL shortening
console.log("📋 URL Shortening Test:");
const shortCodes = urls.map((url) => {
  const shortCode = shortyQ.shortenUrl(url);
  console.log(`Original: ${url}`);
  console.log(`Shortened: ${shortCode}`);
  console.log(`Encrypted: ${shortyQ.getOriginalUrl(shortCode)}\n`);
  return shortCode;
});

// Test URL retrieval
console.log("🔍 URL Retrieval Test:");
shortCodes.forEach((code) => {
  const encrypted = shortyQ.getOriginalUrl(code);
  console.log(`Short Code: ${code}`);
  console.log(`Encrypted URL: ${encrypted}\n`);
});

// Test invalid URLs
console.log("❌ Invalid URL Test:");
try {
  shortyQ.shortenUrl("not-a-valid-url");
} catch (error: any) {
  console.log(
    `Error caught successfully: ${error?.message || "Invalid URL"}\n`
  );
}

// Test empty URL
try {
  shortyQ.shortenUrl("");
} catch (error: any) {
  console.log(`Error caught successfully: ${error?.message || "Empty URL"}\n`);
}

// Test non-existent short code
console.log("🔎 Non-existent Short Code Test:");
const result = shortyQ.getOriginalUrl("nonexistent");
console.log(`Result for non-existent code: ${result}\n`);

// Clear URLs and verify
console.log("🧹 Clear URLs Test:");
shortyQ.clearUrls();
const clearedResult = shortyQ.getOriginalUrl(shortCodes[0]);
console.log(`Result after clearing: ${clearedResult}`);
