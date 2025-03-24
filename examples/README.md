# ShortyQ Examples

This directory contains example code demonstrating how to use the ShortyQ URL shortener package.

## Running the Demo

1.First, install the dependencies:
```bash
npm install
```

2.Run the demo:
```bash
npm run demo
```

## Demo Contents

The demo showcases various features of ShortyQ:

1. **Basic Usage**
   - Simple URL shortening
   - Encryption and decryption
   - Default configuration

2. **Advanced Configuration**
   - Custom URL length
   - Custom salt rounds
   - Fixed quantum seed

3. **Error Handling**
   - Empty URL validation
   - Invalid URL format
   - Maximum length limits

4. **Different URL Types**
   - Basic URLs
   - URLs with query parameters
   - URLs with special characters
   - URLs with Unicode characters
   - URLs with fragments

5. **Performance**
   - Encryption speed
   - Decryption speed
   - Average operation times

## Database Integration Examples

### PostgreSQL with TypeORM

```typescript
import { PostgresURLService } from "shortyq/examples/databases/postgres";

const postgresService = new PostgresURLService({
  // Optional configuration
  urlLength: 8,
  saltRounds: 12,
  quantumSeed: 42,
});

// Create short URL with 24-hour expiration
const shortCode = await postgresService.shortenUrl(
  "https://example.com",
  24 * 60 * 60 * 1000
);
```

### MongoDB with Mongoose

```typescript
import { MongoURLService } from "shortyq/examples/databases/mongodb";

const mongoService = new MongoURLService({
  // Optional configuration
  urlLength: 8,
  saltRounds: 12,
  quantumSeed: 42,
});

// Create short URL with default expiration
await mongoService.shortenUrl("https://example.com");
```

### Redis

```typescript
import { RedisURLService } from "shortyq/examples/databases/redis";

const redisService = new RedisURLService({
  // Redis configuration
  host: "localhost",
  port: 6379,
  // Optional ShortyQ configuration
  urlLength: 8,
  saltRounds: 12,
  quantumSeed: 42,
});

// Create short URL with 1-hour expiration
await redisService.shortenUrl("https://example.com", 3600);
```

## Expected Output

The demo will show:
- Original URLs and their shortened versions
- Encrypted data structure
- Decryption results
- Error handling examples
- Performance metrics

## Customization

You can modify the demo file (`demo.ts`) to:
- Change the test URLs
- Adjust the number of iterations
- Modify configuration options
- Add your own examples