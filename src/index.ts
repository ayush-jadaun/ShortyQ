import { nanoid } from "nanoid";
import CryptoJS from "crypto-js";

/**
 * Configuration options for the ShortyQ URL shortener
 */
export interface ShortyQOptions {
  /** Number of PBKDF2 iterations for key derivation (default: 10) */
  saltRounds?: number;
  /** Length of generated short codes (default: 8, range: 4-100) */
  urlLength?: number;
  /** Seed for quantum noise generation (default: random) */
  quantumSeed?: number;
}

/**
 * Structure for encrypted URL data
 */
export interface EncryptedData {
  /** The encrypted URL data */
  data: string;
  /** The quantum noise used in encryption */
  noise: string;
  /** The initialization vector */
  iv: string;
}

/**
 * ShortyQ - A secure URL shortener using quantum-inspired encryption
 *
 * This class provides functionality to:
 * 1. Generate short, unique codes for URLs
 * 2. Encrypt URLs using multiple layers of encryption
 * 3. Decrypt URLs using the corresponding keys
 *
 * Security features:
 * - Quantum-inspired noise generation
 * - Multiple rounds of AES encryption
 * - PBKDF2 key derivation
 * - SHA3 hashing
 */
export class ShortyQ {
  private readonly saltRounds: number;
  private readonly urlLength: number;
  private readonly quantumSeed: number;
  /** Maximum allowed length for input URLs */
  private readonly MAX_URL_LENGTH = 4096;
  /** Minimum allowed length for short codes */
  private readonly MIN_URL_LENGTH = 4;

  /**
   * Creates a new ShortyQ instance
   * @param options Configuration options for the URL shortener
   * @throws Error if URL length is out of bounds
   */
  constructor(options: ShortyQOptions = {}) {
    this.saltRounds = options.saltRounds || 10;

    // Validate and set URL length
    const urlLength = options.urlLength || 8;
    if (urlLength < this.MIN_URL_LENGTH) {
      throw new Error(
        `URL length must be at least ${this.MIN_URL_LENGTH} characters`
      );
    }
    if (urlLength > 100) {
      throw new Error("URL length cannot exceed 100 characters");
    }
    this.urlLength = urlLength;

    this.quantumSeed = options.quantumSeed || Math.floor(Math.random() * 1000);
  }

  /**
   * Generates quantum-inspired noise for encryption
   * Uses a combination of seed, timestamp, and trigonometric functions
   * to create unique noise even with the same seed
   * @returns A 32-byte noise string in hex format
   */
  private generateQuantumNoise(): string {
    // Simulate quantum noise using pseudo-random numbers and the quantum seed
    const noise = new Uint8Array(32);
    const timestamp = Date.now();
    for (let i = 0; i < noise.length; i++) {
      // Add timestamp to make noise unique even with same seed
      noise[i] = Math.floor(
        (Math.sin(this.quantumSeed * i + timestamp) * 10000) % 256
      );
    }
    return Buffer.from(noise).toString("hex");
  }

  /**
   * Encrypts a URL using multiple layers of encryption
   * Layer 1: AES with quantum noise
   * Layer 2: AES with PBKDF2-derived key
   * Layer 3: AES with SHA3-combined keys
   * @param url The URL to encrypt
   * @returns Encrypted data containing the URL
   */
  private encryptUrl(url: string): EncryptedData {
    // Generate different noise for each layer
    const layer1Noise = this.generateQuantumNoise();
    const layer2Noise = this.generateQuantumNoise();
    const layer3Noise = this.generateQuantumNoise();
    const iv = CryptoJS.lib.WordArray.random(16).toString();

    // First layer: AES encryption with quantum noise and IV
    let encrypted = CryptoJS.AES.encrypt(url, layer1Noise, {
      iv: CryptoJS.enc.Hex.parse(iv),
    }).toString();

    // Second layer: AES with PBKDF2-derived key
    const secondKey = CryptoJS.PBKDF2(layer2Noise, iv, {
      keySize: 256 / 32,
      iterations: this.saltRounds,
    });
    encrypted = CryptoJS.AES.encrypt(
      encrypted,
      secondKey.toString()
    ).toString();

    // Third layer: AES with SHA3-combined keys
    const finalKey = CryptoJS.SHA3(layer3Noise + secondKey.toString());
    encrypted = CryptoJS.AES.encrypt(encrypted, finalKey.toString()).toString();

    return {
      data: encrypted,
      noise: layer1Noise + layer2Noise + layer3Noise, // Combine all noise for decryption
      iv: iv,
    };
  }

  /**
   * Decrypts an encrypted URL data
   * @param encryptedData The encrypted URL data
   * @returns The decrypted URL or null if decryption fails
   */
  public decryptUrl(encryptedData: EncryptedData): string | null {
    try {
      if (
        !encryptedData ||
        !encryptedData.data ||
        !encryptedData.noise ||
        !encryptedData.iv
      ) {
        return null;
      }

      const { data, noise, iv } = encryptedData;
      let decrypted = data;

      // Split the combined noise into three parts
      const noiseLength = noise.length / 3;
      const layer1Noise = noise.slice(0, noiseLength);
      const layer2Noise = noise.slice(noiseLength, noiseLength * 2);
      const layer3Noise = noise.slice(noiseLength * 2);

      // Third layer: Decrypt with SHA3-combined keys
      const finalKey = CryptoJS.SHA3(
        layer3Noise +
          CryptoJS.PBKDF2(layer2Noise, iv, {
            keySize: 256 / 32,
            iterations: this.saltRounds,
          }).toString()
      );
      decrypted = CryptoJS.AES.decrypt(decrypted, finalKey.toString()).toString(
        CryptoJS.enc.Utf8
      );

      // Second layer: Decrypt with PBKDF2-derived key
      const secondKey = CryptoJS.PBKDF2(layer2Noise, iv, {
        keySize: 256 / 32,
        iterations: this.saltRounds,
      });
      decrypted = CryptoJS.AES.decrypt(
        decrypted,
        secondKey.toString()
      ).toString(CryptoJS.enc.Utf8);

      // First layer: Decrypt with quantum noise
      decrypted = CryptoJS.AES.decrypt(decrypted, layer1Noise, {
        iv: CryptoJS.enc.Hex.parse(iv),
      }).toString(CryptoJS.enc.Utf8);

      return decrypted || null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Creates a short code and encrypts the URL
   * @param originalUrl The URL to shorten
   * @returns An object containing the short code and encrypted data
   * @throws Error if URL is empty, invalid, or exceeds maximum length
   */
  public createShortUrl(originalUrl: string): {
    shortCode: string;
    encryptedData: EncryptedData;
  } {
    if (!originalUrl) {
      throw new Error("URL cannot be empty");
    }

    // Validate URL format
    try {
      new URL(originalUrl);
    } catch (e) {
      throw new Error("Invalid URL format");
    }

    // Check URL length
    if (originalUrl.length > this.MAX_URL_LENGTH) {
      throw new Error(
        `URL length cannot exceed ${this.MAX_URL_LENGTH} characters`
      );
    }

    // Generate encrypted version of the URL
    const encryptedData = this.encryptUrl(originalUrl);

    // Generate short code
    const shortCode = this.generateShortCode();

    return {
      shortCode,
      encryptedData,
    };
  }

  /**
   * Generates a unique short code using nanoid
   * @returns A unique short code of the specified length
   */
  private generateShortCode(): string {
    return nanoid(this.urlLength);
  }
}
