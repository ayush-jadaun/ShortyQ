import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  BaseEntity,
} from "typeorm";
import { ShortyQ, decryptUrl, EncryptedPayload } from "../../src/index";

@Entity("shortened_urls")
export class ShortenedURL extends BaseEntity {
  @PrimaryColumn()
  shortCode!: string;

  // Safe to store: useless without the secret key
  @Column("jsonb")
  payload!: EncryptedPayload;

  @CreateDateColumn()
  createdAt!: Date;

  @Column({ type: "timestamp", nullable: true })
  expiresAt?: Date;
}

export class PostgresURLService {
  private shortyQ: ShortyQ;
  private secretKey: string;

  /**
   * @param publicKey base64 ML-KEM-768 public key (from generateKeyPair)
   * @param secretKey base64 secret key — load from an env var or KMS,
   *                  e.g. process.env.SHORTYQ_SECRET_KEY
   */
  constructor(publicKey: string, secretKey: string, urlLength?: number) {
    this.shortyQ = new ShortyQ({ publicKey, urlLength });
    this.secretKey = secretKey;
  }

  async shortenUrl(url: string, expiresIn?: number): Promise<string> {
    const { shortCode, payload } = this.shortyQ.createShortUrl(url);

    const shortenedURL = new ShortenedURL();
    shortenedURL.shortCode = shortCode;
    shortenedURL.payload = payload;
    if (expiresIn) {
      shortenedURL.expiresAt = new Date(Date.now() + expiresIn);
    }

    await shortenedURL.save();
    return shortCode;
  }

  async getOriginalUrl(shortCode: string): Promise<string | null> {
    const record = await ShortenedURL.findOne({
      where: {
        shortCode,
        expiresAt: {
          $gt: new Date(),
        },
      },
    });

    if (!record) return null;
    return decryptUrl(record.payload, this.secretKey);
  }

  async deleteUrl(shortCode: string): Promise<void> {
    await ShortenedURL.delete({ shortCode });
  }

  async cleanup(): Promise<void> {
    // Delete expired URLs
    await ShortenedURL.delete({
      expiresAt: {
        $lt: new Date(),
      },
    });
  }
}
