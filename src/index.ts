import CryptoJS from "crypto-js";
import { nanoid } from "nanoid";

export interface ShortyQOptions {
  saltRounds?: number;
  urlLength?: number;
  quantumSeed?: number;
}

export class ShortyQ {
  private readonly saltRounds: number;
  private readonly urlLength: number;
  private readonly quantumSeed: number;
  private urlMap: Map<string, string>;

  constructor(options: ShortyQOptions = {}) {
    this.saltRounds = options.saltRounds || 10;
    this.urlLength = options.urlLength || 8;
    this.quantumSeed = options.quantumSeed || Math.floor(Math.random() * 1000);
    this.urlMap = new Map();
  }

  private generateQuantumNoise(): string {
    // Simulate quantum noise using pseudo-random numbers and the quantum seed
    const noise = new Uint8Array(32);
    for (let i = 0; i < noise.length; i++) {
      noise[i] = Math.floor((Math.sin(this.quantumSeed * i) * 10000) % 256);
    }
    return Buffer.from(noise).toString("hex");
  }

  private encryptUrl(url: string): string {
    const quantumNoise = this.generateQuantumNoise();
    const saltedUrl = url + quantumNoise;

    // Multiple rounds of encryption with different algorithms
    let encrypted = CryptoJS.AES.encrypt(saltedUrl, quantumNoise).toString();
    encrypted = CryptoJS.SHA3(encrypted).toString();
    encrypted = CryptoJS.RIPEMD160(encrypted).toString();

    return encrypted;
  }

  private generateShortCode(): string {
    return nanoid(this.urlLength);
  }

  public shortenUrl(originalUrl: string): string {
    if (!originalUrl) {
      throw new Error("URL cannot be empty");
    }

    // Validate URL format
    try {
      new URL(originalUrl);
    } catch (e) {
      throw new Error("Invalid URL format");
    }

    // Generate encrypted hash of the URL
    const encryptedUrl = this.encryptUrl(originalUrl);

    // Generate short code
    let shortCode = this.generateShortCode();

    // Ensure uniqueness
    while (this.urlMap.has(shortCode)) {
      shortCode = this.generateShortCode();
    }

    // Store the mapping
    this.urlMap.set(shortCode, encryptedUrl);

    return shortCode;
  }

  public getOriginalUrl(shortCode: string): string | null {
    const encryptedUrl = this.urlMap.get(shortCode);
    return encryptedUrl || null;
  }

  public clearUrls(): void {
    this.urlMap.clear();
  }
}
