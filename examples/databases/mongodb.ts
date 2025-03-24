import mongoose, { Schema, Document } from "mongoose";
import { ShortyQ, EncryptedData } from "../../src/index";

interface IShortenedURL extends Document {
  shortCode: string;
  encryptedData: EncryptedData;
  createdAt: Date;
  expiresAt?: Date;
}

const ShortenedURLSchema = new Schema({
  shortCode: { type: String, required: true, unique: true, index: true },
  encryptedData: {
    data: { type: String, required: true },
    noise: { type: String, required: true },
    iv: { type: String, required: true },
  },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date },
});

// Create TTL index for auto-expiration
ShortenedURLSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const ShortenedURL = mongoose.model<IShortenedURL>(
  "ShortenedURL",
  ShortenedURLSchema
);

export class MongoURLService {
  private shortyQ: ShortyQ;

  constructor(options = {}) {
    this.shortyQ = new ShortyQ(options);
  }

  async shortenUrl(url: string, expiresIn?: number): Promise<string> {
    const { shortCode, encryptedData } = this.shortyQ.createShortUrl(url);

    await ShortenedURL.create({
      shortCode,
      encryptedData,
      expiresAt: expiresIn ? new Date(Date.now() + expiresIn) : undefined,
    });

    return shortCode;
  }

  async getOriginalUrl(shortCode: string): Promise<string | null> {
    const record = await ShortenedURL.findOne({
      shortCode,
      $or: [
        { expiresAt: { $exists: false } },
        { expiresAt: { $gt: new Date() } },
      ],
    });

    if (!record) return null;
    return this.shortyQ.decryptUrl(record.encryptedData);
  }

  async deleteUrl(shortCode: string): Promise<void> {
    await ShortenedURL.deleteOne({ shortCode });
  }

  async cleanup(): Promise<void> {
    // MongoDB TTL index handles cleanup automatically
    // This method is kept for API consistency
  }
}
