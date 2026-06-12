import Redis from "ioredis";
import { ShortyQ, decryptUrl, EncryptedPayload } from "../../src/index";

export class RedisURLService {
  private shortyQ: ShortyQ;
  private secretKey: string;
  private redis: Redis;
  private prefix: string;

  /**
   * @param publicKey base64 ML-KEM-768 public key (from generateKeyPair)
   * @param secretKey base64 secret key — load from an env var or KMS,
   *                  e.g. process.env.SHORTYQ_SECRET_KEY
   */
  constructor(
    publicKey: string,
    secretKey: string,
    redisOptions = {},
    urlLength?: number,
    prefix = "shortyq:"
  ) {
    this.shortyQ = new ShortyQ({ publicKey, urlLength });
    this.secretKey = secretKey;
    this.redis = new Redis(redisOptions);
    this.prefix = prefix;
  }

  private getKey(shortCode: string): string {
    return `${this.prefix}${shortCode}`;
  }

  async shortenUrl(url: string, expiresIn?: number): Promise<string> {
    const { shortCode, payload } = this.shortyQ.createShortUrl(url);
    const key = this.getKey(shortCode);

    // Store as hash to maintain data structure
    await this.redis
      .multi()
      .hmset(key, {
        kemCiphertext: payload.kemCiphertext,
        nonce: payload.nonce,
        ciphertext: payload.ciphertext,
      })
      .expire(key, Math.floor((expiresIn || 2592000000) / 1000)) // Default 30 days
      .exec();

    return shortCode;
  }

  async getOriginalUrl(shortCode: string): Promise<string | null> {
    const key = this.getKey(shortCode);
    const data = await this.redis.hgetall(key);

    if (!data || !data.kemCiphertext || !data.nonce || !data.ciphertext) {
      return null;
    }

    const payload: EncryptedPayload = {
      kemCiphertext: data.kemCiphertext,
      nonce: data.nonce,
      ciphertext: data.ciphertext,
    };

    return decryptUrl(payload, this.secretKey);
  }

  async deleteUrl(shortCode: string): Promise<void> {
    await this.redis.del(this.getKey(shortCode));
  }

  async cleanup(): Promise<void> {
    // Redis TTL handles cleanup automatically
    // This method is kept for API consistency
  }

  async disconnect(): Promise<void> {
    await this.redis.quit();
  }
}
