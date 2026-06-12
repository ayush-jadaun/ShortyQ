import mongoose, { Schema, Document } from "mongoose";
import { ShortyQ, decryptUrl, EncryptedPayload } from "../../src/index";

interface IShortenedURL extends Document {
  shortCode: string;
  payload: EncryptedPayload;
  createdAt: Date;
  expiresAt?: Date;
}

const ShortenedURLSchema = new Schema({
  shortCode: { type: String, required: true, unique: true, index: true },
  // Safe to store: useless without the secret key
  payload: {
    kemCiphertext: { type: String, required: true },
    nonce: { type: String, required: true },
    ciphertext: { type: String, required: true },
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

    await ShortenedURL.create({
      shortCode,
      payload,
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
    return decryptUrl(record.payload, this.secretKey);
  }

  async deleteUrl(shortCode: string): Promise<void> {
    await ShortenedURL.deleteOne({ shortCode });
  }

  async cleanup(): Promise<void> {
    // MongoDB TTL index handles cleanup automatically
    // This method is kept for API consistency
  }
}
