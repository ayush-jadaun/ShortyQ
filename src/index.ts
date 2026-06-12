import { nanoid } from "nanoid";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { gcm } from "@noble/ciphers/aes";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { scrypt } from "@noble/hashes/scrypt";
import { x25519 } from "@noble/curves/ed25519";
import { randomBytes } from "crypto";

/** Byte sizes fixed by the ML-KEM-768 parameter set (FIPS 203) */
const PUBLIC_KEY_BYTES = 1184;
const SECRET_KEY_BYTES = 2400;
const KEM_CIPHERTEXT_BYTES = 1088;
/** AES-GCM standard nonce size */
const NONCE_BYTES = 12;
/** scrypt salt size for password-protected links */
const KDF_SALT_BYTES = 16;
/** keyId length: leading bytes of sha256(publicKey) */
const KEY_ID_BYTES = 8;
/** HMAC key size for deterministic short codes */
const CODE_KEY_BYTES = 32;
/** X25519 key/ciphertext size */
const X25519_BYTES = 32;
/** Hybrid key sizes: ML-KEM part ‖ X25519 part */
const HYBRID_PUBLIC_KEY_BYTES = PUBLIC_KEY_BYTES + X25519_BYTES;
const HYBRID_SECRET_KEY_BYTES = SECRET_KEY_BYTES + X25519_BYTES;
/** Domain-separation label for the hybrid combiner */
const HYBRID_LABEL = new Uint8Array(
  Buffer.from("shortyq-hybrid-v1", "utf8")
);

/**
 * An ML-KEM-768 key pair, base64-encoded for easy storage.
 * Store the secretKey in an env var or KMS — never in the database.
 */
export interface KeyPair {
  /** Base64-encoded hybrid public key: ML-KEM-768 ‖ X25519 (safe to embed in app config) */
  publicKey: string;
  /** Base64-encoded hybrid secret key: ML-KEM-768 ‖ X25519 (keep out of the database) */
  secretKey: string;
  /** Base64-encoded 32-byte HMAC key for deterministic short codes */
  codeKey: string;
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
  /** Base64 X25519 ephemeral public key (32 bytes) — hybrid payloads only (v2.2+) */
  x25519Ciphertext?: string;
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
  /** Base64 codeKey from generateKeyPair(); enables deterministic codes */
  codeKey?: string;
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
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
 * Generates a hybrid ML-KEM-768 + X25519 key pair (v2.2+): confidentiality
 * holds if EITHER algorithm survives. Call once; reuse the public key for
 * shortening and keep the secret key for decryption. Legacy pure ML-KEM
 * keys (from v2.0/v2.1) remain fully supported everywhere.
 */
export function generateKeyPair(): KeyPair {
  const { publicKey, secretKey } = ml_kem768.keygen();
  const xSecret = x25519.utils.randomPrivateKey();
  const xPublic = x25519.getPublicKey(xSecret);
  return {
    publicKey: toBase64(concatBytes(publicKey, xPublic)),
    secretKey: toBase64(concatBytes(secretKey, xSecret)),
    codeKey: toBase64(new Uint8Array(randomBytes(CODE_KEY_BYTES))),
  };
}

/**
 * Advisory identifier for a public key: base64 of the first 8 bytes of
 * sha256(publicKeyBytes). Stamped on every v2.1 payload so apps can index
 * which keypair encrypted a record.
 */
export function getKeyId(publicKey: string): string {
  const bytes = fromBase64(publicKey);
  if (
    bytes.length !== PUBLIC_KEY_BYTES &&
    bytes.length !== HYBRID_PUBLIC_KEY_BYTES
  ) {
    throw new Error("Invalid ML-KEM-768 public key");
  }
  return toBase64(sha256(bytes).slice(0, KEY_ID_BYTES));
}

/**
 * AES key for a payload: the raw ML-KEM shared secret, or — for
 * password-protected links — sha256(sharedSecret || scrypt(password, salt)).
 */
function deriveAesKey(
  sharedSecret: Uint8Array,
  password: string | undefined,
  kdfSalt: Uint8Array | undefined
): Uint8Array {
  if (password === undefined || kdfSalt === undefined) {
    return sharedSecret;
  }
  const stretched = scrypt(password, kdfSalt, {
    N: 2 ** 15,
    r: 8,
    p: 1,
    dkLen: 32,
  });
  const combined = new Uint8Array(sharedSecret.length + stretched.length);
  combined.set(sharedSecret);
  combined.set(stretched, sharedSecret.length);
  return sha256(combined);
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
    if (
      secretKeyBytes.length !== SECRET_KEY_BYTES &&
      secretKeyBytes.length !== HYBRID_SECRET_KEY_BYTES
    ) {
      return null;
    }
    const isHybridPayload = payload.x25519Ciphertext !== undefined;
    if (isHybridPayload && secretKeyBytes.length !== HYBRID_SECRET_KEY_BYTES) {
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
    let kdfSalt: Uint8Array | undefined;
    if (payload.kdfSalt) {
      kdfSalt = fromBase64(payload.kdfSalt);
      if (kdfSalt.length !== KDF_SALT_BYTES) {
        return null;
      }
    }
    // A wrong-but-valid secret key doesn't throw here (ML-KEM implicit
    // rejection); it yields a different shared secret and GCM auth fails below.
    const mlkemSk = secretKeyBytes.subarray(0, SECRET_KEY_BYTES);
    const ssM = ml_kem768.decapsulate(kemCiphertext, mlkemSk);
    let baseKey: Uint8Array = ssM;
    if (isHybridPayload) {
      const ctX = fromBase64(payload.x25519Ciphertext!);
      if (ctX.length !== X25519_BYTES) {
        return null;
      }
      const xSk = secretKeyBytes.subarray(SECRET_KEY_BYTES);
      const xPk = x25519.getPublicKey(xSk);
      const ssX = x25519.getSharedSecret(xSk, ctX);
      baseKey = sha256(concatBytes(HYBRID_LABEL, ssM, ssX, ctX, xPk));
    }
    const aesKey = deriveAesKey(baseKey, password, kdfSalt);
    const plaintext = gcm(aesKey, nonce).decrypt(
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
  private readonly keyId: string;
  private readonly urlLength: number;
  private readonly codeKey?: Uint8Array;
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
    if (
      this.publicKey.length !== PUBLIC_KEY_BYTES &&
      this.publicKey.length !== HYBRID_PUBLIC_KEY_BYTES
    ) {
      throw new Error("Invalid ML-KEM-768 public key");
    }
    this.keyId = toBase64(sha256(this.publicKey).slice(0, KEY_ID_BYTES));

    if (options.codeKey !== undefined) {
      this.codeKey = fromBase64(options.codeKey);
      if (this.codeKey.length !== CODE_KEY_BYTES) {
        throw new Error("Invalid code key");
      }
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
    const shortCode = this.makeShortCode(originalUrl, options);

    const mlkemPk = this.publicKey.subarray(0, PUBLIC_KEY_BYTES);
    const { cipherText, sharedSecret: ssM } = ml_kem768.encapsulate(mlkemPk);
    let baseKey: Uint8Array = ssM;
    let x25519CtB64: string | undefined;
    if (this.publicKey.length === HYBRID_PUBLIC_KEY_BYTES) {
      const xPk = this.publicKey.subarray(PUBLIC_KEY_BYTES);
      const eSk = x25519.utils.randomPrivateKey();
      const ctX = x25519.getPublicKey(eSk);
      const ssX = x25519.getSharedSecret(eSk, xPk);
      baseKey = sha256(concatBytes(HYBRID_LABEL, ssM, ssX, ctX, xPk));
      x25519CtB64 = toBase64(ctX);
    }

    const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
    let aesKey: Uint8Array = baseKey;
    let kdfSaltB64: string | undefined;
    if (options.password !== undefined) {
      const kdfSalt = new Uint8Array(randomBytes(KDF_SALT_BYTES));
      aesKey = deriveAesKey(baseKey, options.password, kdfSalt);
      kdfSaltB64 = toBase64(kdfSalt);
    }
    const ciphertext = gcm(aesKey, nonce).encrypt(
      new Uint8Array(Buffer.from(plaintext, "utf8"))
    );

    const payload: EncryptedPayload = {
      kemCiphertext: toBase64(cipherText),
      nonce: toBase64(nonce),
      ciphertext: toBase64(ciphertext),
      keyId: this.keyId,
    };
    if (kdfSaltB64 !== undefined) {
      payload.kdfSalt = kdfSaltB64;
    }
    if (x25519CtB64 !== undefined) {
      payload.x25519Ciphertext = x25519CtB64;
    }
    return { shortCode, payload };
  }

  /**
   * Shortens several URLs in one call. All-or-nothing: throws on the first
   * invalid item without returning partial results.
   */
  public createShortUrls(
    items: Array<string | { url: string; options?: CreateShortUrlOptions }>
  ): Array<{ shortCode: string; payload: EncryptedPayload }> {
    return items.map((item) =>
      typeof item === "string"
        ? this.createShortUrl(item)
        : this.createShortUrl(item.url, item.options)
    );
  }

  /** Picks the short code: vanity > deterministic HMAC > nanoid */
  private makeShortCode(url: string, options: CreateShortUrlOptions): string {
    if (options.shortCode !== undefined && options.deterministic) {
      throw new Error(
        "Cannot combine a custom short code with deterministic mode"
      );
    }
    if (options.shortCode !== undefined) {
      if (!/^[A-Za-z0-9_-]{4,100}$/.test(options.shortCode)) {
        throw new Error("Invalid custom short code");
      }
      return options.shortCode;
    }
    if (options.deterministic) {
      if (!this.codeKey) {
        throw new Error("Deterministic codes require a codeKey");
      }
      const digest = hmac(sha256, this.codeKey, Buffer.from(url, "utf8"));
      // base64url of 32 bytes = 43 chars; codes cap there for urlLength > 43
      return Buffer.from(digest)
        .toString("base64url")
        .slice(0, this.urlLength);
    }
    return nanoid(this.urlLength);
  }
}
