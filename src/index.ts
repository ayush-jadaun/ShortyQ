import { ml_kem768 } from "@noble/post-quantum/ml-kem";

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
