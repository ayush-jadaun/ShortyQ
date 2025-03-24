import Redis from "ioredis";
import { ShortyQ, EncryptedData } from "../../src/index";

export class RedisURLService {
  private shortyQ: ShortyQ;
  private redis: Redis;
  private prefix: string;

  constructor(redisOptions = {}, shortyQOptions = {}, prefix = "shortyq:") {
    this.shortyQ = new ShortyQ(shortyQOptions);
    this.redis = new Redis(redisOptions);
    this.prefix = prefix;
  }

  private getKey(shortCode: string): string {
    return `${this.prefix}${shortCode}`;
  }

  async shortenUrl(url: string, expiresIn?: number): Promise<string> {
    const { shortCode, encryptedData } = this.shortyQ.createShortUrl(url);
    const key = this.getKey(shortCode);

    // Store as hash to maintain data structure
    await this.redis
      .multi()
      .hmset(key, {
        data: encryptedData.data,
        noise: encryptedData.noise,
        iv: encryptedData.iv,
      })
      .expire(key, Math.floor((expiresIn || 2592000000) / 1000)) // Default 30 days
      .exec();

    return shortCode;
  }

  async getOriginalUrl(shortCode: string): Promise<string | null> {
    const key = this.getKey(shortCode);
    const data = await this.redis.hgetall(key);

    if (!data || !data.data || !data.noise || !data.iv) {
      return null;
    }

    const encryptedData: EncryptedData = {
      data: data.data,
      noise: data.noise,
      iv: data.iv,
    };

    return this.shortyQ.decryptUrl(encryptedData);
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
