import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  BaseEntity,
} from "typeorm";
import { ShortyQ, EncryptedData } from "../../src/index";

@Entity("shortened_urls")
export class ShortenedURL extends BaseEntity {
  @PrimaryColumn()
  shortCode!: string;

  @Column("jsonb")
  encryptedData!: EncryptedData;

  @CreateDateColumn()
  createdAt!: Date;

  @Column({ type: "timestamp", nullable: true })
  expiresAt?: Date;
}

export class PostgresURLService {
  private shortyQ: ShortyQ;

  constructor(options = {}) {
    this.shortyQ = new ShortyQ(options);
  }

  async shortenUrl(url: string, expiresIn?: number): Promise<string> {
    const { shortCode, encryptedData } = this.shortyQ.createShortUrl(url);

    const shortenedURL = new ShortenedURL();
    shortenedURL.shortCode = shortCode;
    shortenedURL.encryptedData = encryptedData;
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
    return this.shortyQ.decryptUrl(record.encryptedData);
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
