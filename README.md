# ShortyQ

A secure URL shortener package that uses quantum-inspired encryption techniques to generate and manage short URLs. This package provides a robust and secure way to create shortened URLs while maintaining privacy and security.

## Features

- Quantum-inspired encryption for enhanced security
- Configurable URL length and salt rounds
- Multiple rounds of encryption using different algorithms
- In-memory URL mapping with one-way encryption
- TypeScript support with full type definitions
- Comprehensive test coverage
- Error handling for invalid URLs

## Installation

```bash
npm install shortyq
```

## Usage

```typescript
import { ShortyQ } from "shortyq";

// Create a new instance with default options
const shortyQ = new ShortyQ();

// Or with custom options
const customShortyQ = new ShortyQ({
  saltRounds: 12,
  urlLength: 10,
  quantumSeed: 42,
});

// Shorten a URL
try {
  const shortCode = shortyQ.shortenUrl(
    "https://example.com/very/long/url/path"
  );
  console.log("Short Code:", shortCode); // e.g., "Km2n9q3p"

  // Retrieve the encrypted URL
  const encryptedUrl = shortyQ.getOriginalUrl(shortCode);
  console.log("Encrypted URL:", encryptedUrl);

  // Clear all stored URLs
  shortyQ.clearUrls();
} catch (error) {
  console.error("Error:", error.message);
}
```

## API

### `ShortyQ`

#### Constructor Options

- `saltRounds` (optional): Number of rounds for salt generation (default: 10)
- `urlLength` (optional): Length of generated short codes (default: 8)
- `quantumSeed` (optional): Seed for quantum noise generation (default: random)

#### Methods

- `shortenUrl(originalUrl: string): string`

  - Generates a short code for the given URL
  - Parameters:
    - `originalUrl`: A valid URL string
  - Returns:
    - A unique short code of specified length
  - Throws:
    - `Error("URL cannot be empty")` if URL is empty
    - `Error("Invalid URL format")` if URL is not properly formatted

- `getOriginalUrl(shortCode: string): string | null`

  - Returns the encrypted URL for a given short code
  - Parameters:
    - `shortCode`: Previously generated short code
  - Returns:
    - The encrypted URL hash if found
    - `null` if short code doesn't exist
  - Note: The returned encrypted URL is a one-way hash and cannot be converted back to the original URL

- `clearUrls(): void`
  - Clears all stored URL mappings
  - Useful for managing memory usage
  - All previous short codes will return null after clearing

## Security Features

ShortyQ implements several layers of security:

1. Quantum-inspired noise generation:

   - Uses seeded pseudo-random number generation
   - Generates 32 bytes of quantum-inspired noise
   - Applies trigonometric transformations for enhanced randomness

2. Multiple rounds of encryption:

   - First layer: AES encryption using quantum noise as key
   - Second layer: SHA3 hashing for additional security
   - Final layer: RIPEMD160 hashing for compact representation

3. URL Security:

   - One-way encryption (cannot retrieve original URL)
   - Unique short code generation
   - Collision detection and prevention
   - Input validation and sanitization

4. Storage Security:
   - In-memory storage only
   - No persistent storage of original URLs
   - Clearable URL mappings

## License

MIT
