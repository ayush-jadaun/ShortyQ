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
  /** Base64 key identifier (8 bytes of sha256(publicKey)) — v2.1+ */
  keyId?: string;
  /** Base64 scrypt salt (16 bytes) — present only on password-protected links */
  kdfSalt?: string;
}

/**
 * Options for createShortUrl. All combinable except shortCode + deterministic.
 */
export interface CreateShortUrlOptions {
  /** Expiry as a Date or epoch milliseconds; must be in the future */
  expiresAt?: Date | number;
  /** Arbitrary JSON-serializable metadata, encrypted alongside the URL */
  metadata?: unknown;
  /** Password required (in addition to the secret key) to decrypt */
  password?: string;
  /** Custom (vanity) short code: 4-100 chars of [A-Za-z0-9_-] */
  shortCode?: string;
  /** Derive the short code deterministically from the URL (needs codeKey) */
  deterministic?: boolean;
}

/** Options for decryptUrl / decryptPayload */
export interface DecryptOptions {
  /** Password the link was created with, if any */
  password?: string;
}

/** Decrypted contents of a payload */
export interface DecryptedPayload {
  url: string;
  metadata?: unknown;
  expiresAt?: Date;
}

/** Wire format of the encrypted JSON envelope */
interface Envelope {
  u: string;
  e?: number;
  m?: unknown;
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

function buildPlaintext(url: string, options: CreateShortUrlOptions): string {
  const envelope: Envelope = { u: url };
  if (options.expiresAt !== undefined) {
    const at =
      options.expiresAt instanceof Date
        ? options.expiresAt.getTime()
        : options.expiresAt;
    if (!Number.isFinite(at) || at <= Date.now()) {
      throw new Error("expiresAt must be in the future");
    }
    envelope.e = at;
  }
  if (options.metadata !== undefined) {
    let serialized: string | undefined;
    try {
      serialized = JSON.stringify(options.metadata);
    } catch (e) {
      throw new Error("Metadata must be JSON-serializable");
    }
    if (serialized === undefined) {
      throw new Error("Metadata must be JSON-serializable");
    }
    envelope.m = options.metadata;
  }
  return JSON.stringify(envelope);
}

/**
 * Interprets decrypted plaintext: a v2.1 JSON envelope, or a v2.0 bare URL.
 * Returns null when the envelope says the link has expired.
 */
function parsePlaintext(plaintext: string): DecryptedPayload | null {
  let envelope: any;
  try {
    envelope = JSON.parse(plaintext);
  } catch (e) {
    return { url: plaintext };
  }
  if (
    typeof envelope !== "object" ||
    envelope === null ||
    typeof envelope.u !== "string"
  ) {
    return { url: plaintext };
  }
  const result: DecryptedPayload = { url: envelope.u };
  if (envelope.e !== undefined) {
    if (typeof envelope.e !== "number" || envelope.e <= Date.now()) {
      return null;
    }
    result.expiresAt = new Date(envelope.e);
  }
  if (envelope.m !== undefined) {
    result.metadata = envelope.m;
  }
  return result;
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
 * Decrypts a payload and returns its full contents.
 * @param payload The encrypted payload from createShortUrl
 * @param secretKey One base64 secret key, or several to try in order
 *                  (key rotation)
 * @param options Pass the password for password-protected links
 * @returns { url, metadata?, expiresAt? }, or null if the key is wrong, the
 *          password is wrong/missing, the link has expired, or the data was
 *          tampered with. Never throws.
 */
export function decryptPayload(
  payload: EncryptedPayload,
  secretKey: string | string[],
  options: DecryptOptions = {}
): DecryptedPayload | null {
  if (
    !payload ||
    !payload.kemCiphertext ||
    !payload.nonce ||
    !payload.ciphertext
  ) {
    return null;
  }
  const hasSalt = !!payload.kdfSalt;
  const hasPassword = options.password !== undefined;
  if (hasSalt !== hasPassword) {
    return null;
  }
  const keys = Array.isArray(secretKey) ? secretKey : [secretKey];
  for (const key of keys) {
    const result = tryDecrypt(payload, key, options.password);
    if (result !== null) {
      return result;
    }
  }
  return null;
}

/**
 * Decrypts an encrypted URL payload using the secret key.
 * Same contract as decryptPayload, returning only the URL.
 */
export function decryptUrl(
  payload: EncryptedPayload,
  secretKey: string | string[],
  options: DecryptOptions = {}
): string | null {
  const result = decryptPayload(payload, secretKey, options);
  return result ? result.url : null;
}

function tryDecrypt(
  payload: EncryptedPayload,
  secretKey: string,
  password?: string
): DecryptedPayload | null {
  try {
    if (!secretKey) {
      return null;
    }
    const secretKeyBytes = fromBase64(secretKey);
    if (secretKeyBytes.length !== SECRET_KEY_BYTES) {
      return null;
    }
    const kemCiphertext = fromBase64(payload.kemCiphertext);
    if (kemCiphertext.length !== KEM_CIPHERTEXT_BYTES) {
      return null;
    }
    const nonce = fromBase64(payload.nonce);
    if (nonce.length !== NONCE_BYTES) {
      return null;
    }
    // A wrong-but-valid secret key doesn't throw here (ML-KEM implicit
    // rejection); it yields a different shared secret and GCM auth fails below.
    const sharedSecret = ml_kem768.decapsulate(kemCiphertext, secretKeyBytes);
    const plaintext = gcm(sharedSecret, nonce).decrypt(
      fromBase64(payload.ciphertext)
    );
    return parsePlaintext(Buffer.from(plaintext).toString("utf8"));
  } catch (error) {
    return null;
  }
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
  public createShortUrl(
    originalUrl: string,
    options: CreateShortUrlOptions = {}
  ): {
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

    const plaintext = buildPlaintext(originalUrl, options);

    const { cipherText, sharedSecret } = ml_kem768.encapsulate(this.publicKey);
    const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
    const ciphertext = gcm(sharedSecret, nonce).encrypt(
      new Uint8Array(Buffer.from(plaintext, "utf8"))
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
