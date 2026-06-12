import { nanoid } from "nanoid";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { gcm } from "@noble/ciphers/aes";
import { randomBytes } from "crypto";

/** Byte sizes fixed by the ML-KEM-768 parameter set (FIPS 203) */
const PUBLIC_KEY_BYTES = 1184;
const SECRET_KEY_BYTES = 2400;
const KEM_CIPHERTEXT_BYTES = 1088;
/** AES-GCM standard nonce size */
const NONCE_BYTES = 12;

/**
 * An ML-KEM-768 key pair, base64-encoded for easy storage.
 * Store the secretKey in an env var or KMS — never in the database.
 */
export interface KeyPair {
  /** Base64-encoded ML-KEM-768 public key (safe to embed in app config) */
  publicKey: string;
  /** Base64-encoded ML-KEM-768 secret key (keep out of the database) */
  secretKey: string;
}

/**
 * Encrypted URL payload. Safe to store in a database —
 * useless without the secret key.
 */
export interface EncryptedPayload {
  /** Base64 ML-KEM-768 encapsulation ciphertext (1088 bytes) */
  kemCiphertext: string;
  /** Base64 AES-GCM nonce (12 bytes) */
  nonce: string;
  /** Base64 AES-256-GCM ciphertext including auth tag */
  ciphertext: string;
}

/**
 * Configuration options for the ShortyQ URL shortener
 */
export interface ShortyQOptions {
  /** Base64-encoded ML-KEM-768 public key from generateKeyPair() */
  publicKey: string;
  /** Length of generated short codes (default: 8, range: 4-100) */
  urlLength?: number;
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

/**
 * Generates an ML-KEM-768 key pair. Call once; reuse the public key
 * for shortening and keep the secret key for decryption.
 */
export function generateKeyPair(): KeyPair {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { publicKey: toBase64(publicKey), secretKey: toBase64(secretKey) };
}

/**
 * ShortyQ - a quantum-safe URL shortener.
 *
 * Encrypts URLs with ML-KEM-768 (NIST FIPS 203) + AES-256-GCM.
 * The instance only holds the public key; decryption requires the
 * secret key via the module-level decryptUrl().
 */
export class ShortyQ {
  private readonly publicKey: Uint8Array;
  private readonly urlLength: number;
  /** Maximum allowed length for input URLs */
  private readonly MAX_URL_LENGTH = 4096;
  /** Minimum allowed length for short codes */
  private readonly MIN_CODE_LENGTH = 4;
  /** Maximum allowed length for short codes */
  private readonly MAX_CODE_LENGTH = 100;

  /**
   * Creates a new ShortyQ instance
   * @param options Configuration; publicKey is required
   * @throws Error if the public key is missing/invalid or urlLength is out of bounds
   */
  constructor(options: ShortyQOptions) {
    if (!options || !options.publicKey) {
      throw new Error("Public key is required");
    }
    this.publicKey = fromBase64(options.publicKey);
    if (this.publicKey.length !== PUBLIC_KEY_BYTES) {
      throw new Error("Invalid ML-KEM-768 public key");
    }

    const urlLength = options.urlLength ?? 8;
    if (urlLength < this.MIN_CODE_LENGTH) {
      throw new Error(
        `URL length must be at least ${this.MIN_CODE_LENGTH} characters`
      );
    }
    if (urlLength > this.MAX_CODE_LENGTH) {
      throw new Error("URL length cannot exceed 100 characters");
    }
    this.urlLength = urlLength;
  }

  /**
   * Creates a short code and encrypts the URL against the public key.
   * Each call uses a fresh ML-KEM encapsulation (no key reuse across URLs).
   * @param originalUrl The URL to shorten
   * @returns The short code and an encrypted payload safe for DB storage
   * @throws Error if URL is empty, invalid, or exceeds maximum length
   */
  public createShortUrl(originalUrl: string): {
    shortCode: string;
    payload: EncryptedPayload;
  } {
    if (!originalUrl) {
      throw new Error("URL cannot be empty");
    }
    try {
      new URL(originalUrl);
    } catch (e) {
      throw new Error("Invalid URL format");
    }
    if (originalUrl.length > this.MAX_URL_LENGTH) {
      throw new Error(
        `URL length cannot exceed ${this.MAX_URL_LENGTH} characters`
      );
    }

    const { cipherText, sharedSecret } = ml_kem768.encapsulate(this.publicKey);
    const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
    const ciphertext = gcm(sharedSecret, nonce).encrypt(
      new Uint8Array(Buffer.from(originalUrl, "utf8"))
    );

    return {
      shortCode: nanoid(this.urlLength),
      payload: {
        kemCiphertext: toBase64(cipherText),
        nonce: toBase64(nonce),
        ciphertext: toBase64(ciphertext),
      },
    };
  }
}
