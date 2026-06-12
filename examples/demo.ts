import {
  ShortyQ,
  generateKeyPair,
  decryptUrl,
  decryptPayload,
  getKeyId,
} from "shortyq";

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

// Example 5: v2.1 — Encrypted Expiry & Metadata
function expiryMetadataDemo() {
  console.log("\n⏳ Expiry & Metadata Demo (v2.1)");
  console.log("================================");

  const shortyQ = new ShortyQ({ publicKey });
  const url = "https://example.com/winter-sale";

  const { shortCode, payload } = shortyQ.createShortUrl(url, {
    expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
    metadata: { campaign: "winter", owner: "ayush" },
  });

  // decryptPayload returns everything that was encrypted
  const result = decryptPayload(payload, secretKey);
  console.log("Short Code:", shortCode);
  console.log("URL:", result?.url);
  console.log("Metadata:", result?.metadata);
  console.log("Expires:", result?.expiresAt?.toISOString());
  // Once expiresAt passes, decryptPayload/decryptUrl return null —
  // the deadline is inside the authenticated ciphertext, so nobody
  // with database access can read or extend it.
}

// Example 6: v2.1 — Password-Protected Links
function passwordDemo() {
  console.log("\n🔏 Password-Protected Links Demo (v2.1)");
  console.log("=======================================");

  const shortyQ = new ShortyQ({ publicKey });
  const url = "https://example.com/board-meeting-notes";

  const { payload } = shortyQ.createShortUrl(url, { password: "hunter2" });

  console.log("Without password:", decryptUrl(payload, secretKey)); // null
  console.log(
    "Wrong password:",
    decryptUrl(payload, secretKey, { password: "hunter3" }) // null
  );
  console.log(
    "Correct password:",
    decryptUrl(payload, secretKey, { password: "hunter2" }) // url
  );
}

// Example 7: v2.1 — Key Rotation
function rotationDemo() {
  console.log("\n🔁 Key Rotation Demo (v2.1)");
  console.log("===========================");

  const oldPair = generateKeyPair();
  const newPair = generateKeyPair();
  const url = "https://example.com/archived-link";

  // A link created under the OLD key...
  const oldShortyQ = new ShortyQ({ publicKey: oldPair.publicKey });
  const { payload } = oldShortyQ.createShortUrl(url);

  // ...still decrypts after rotating, by passing all known secret keys.
  // The payload's keyId tells you which key it needs.
  console.log("Payload keyId:", payload.keyId);
  console.log("Old key's id: ", getKeyId(oldPair.publicKey));
  console.log("New key's id: ", getKeyId(newPair.publicKey));
  console.log(
    "Decrypted with key array:",
    decryptUrl(payload, [newPair.secretKey, oldPair.secretKey])
  );
}

// Example 8: v2.1 — Deterministic & Vanity Short Codes
function shortCodeModesDemo() {
  console.log("\n🎯 Deterministic & Vanity Codes Demo (v2.1)");
  console.log("===========================================");

  const { publicKey: pk, codeKey } = generateKeyPair();
  const shortyQ = new ShortyQ({ publicKey: pk, codeKey });
  const url = "https://example.com/dedupe-me";

  // Deterministic: same URL -> same code, so your app can dedupe.
  // Opt-in because it reveals URL-equality in your database.
  const a = shortyQ.createShortUrl(url, { deterministic: true });
  const b = shortyQ.createShortUrl(url, { deterministic: true });
  console.log("Deterministic codes match:", a.shortCode === b.shortCode);

  // Vanity: bring your own code (4-100 chars of A-Za-z0-9_-).
  const vanity = shortyQ.createShortUrl(url, { shortCode: "summer-sale" });
  console.log("Vanity code:", vanity.shortCode);
}

// Example 9: v2.1 — Batch API
function batchDemo() {
  console.log("\n🧰 Batch Demo (v2.1)");
  console.log("====================");

  const shortyQ = new ShortyQ({ publicKey });
  const results = shortyQ.createShortUrls([
    "https://example.com/one",
    { url: "https://example.com/two", options: { metadata: { i: 2 } } },
    "https://example.com/three",
  ]);

  results.forEach(({ shortCode, payload }) => {
    console.log(`${shortCode} -> ${decryptUrl(payload, secretKey)}`);
  });
}

// Run all demos
console.log("🎬 Starting ShortyQ Demos\n");
basicDemo();
configDemo();
errorHandlingDemo();
urlTypesDemo();
expiryMetadataDemo();
passwordDemo();
rotationDemo();
shortCodeModesDemo();
batchDemo();
console.log("\n✨ All demos completed!");
