import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;

/**
 * Gets the encryption key from environment variable
 * In production, ENCRYPTION_KEY must be set (validated in config.ts)
 * Falls back to derived key from JWT_SECRET for backwards compatibility in development
 */
function getEncryptionKey(): string {
  const encryptionKey = process.env.ENCRYPTION_KEY;
  if (encryptionKey) {
    return encryptionKey;
  }

  // Fallback for development - derive from JWT_SECRET (deprecated)
  if (process.env.NODE_ENV !== 'production') {
    console.warn('⚠️  ENCRYPTION_KEY not set. Using JWT_SECRET derivation (deprecated).');
    return process.env.JWT_SECRET || 'your-super-secret-jwt-key';
  }

  throw new Error('ENCRYPTION_KEY environment variable is required in production');
}

/**
 * Derives a 256-bit key using PBKDF2
 * Uses dedicated ENCRYPTION_KEY instead of JWT secret for proper key separation
 */
function deriveKey(salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(
    getEncryptionKey(),
    salt,
    100000, // iterations
    32, // key length
    'sha256'
  );
}

/**
 * Encrypts a plaintext string using AES-256-GCM
 * @param plaintext - The text to encrypt
 * @returns Base64 encoded string containing salt, iv, authTag, and ciphertext
 */
export function encrypt(plaintext: string): string {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = deriveKey(salt);
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Combine salt + iv + authTag + ciphertext
  const combined = Buffer.concat([salt, iv, authTag, encrypted]);
  return combined.toString('base64');
}

/**
 * Decrypts a ciphertext string encrypted with encrypt()
 * @param ciphertext - Base64 encoded encrypted data
 * @returns The decrypted plaintext
 */
export function decrypt(ciphertext: string): string {
  const combined = Buffer.from(ciphertext, 'base64');

  // Extract components
  const salt = combined.subarray(0, SALT_LENGTH);
  const iv = combined.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const authTag = combined.subarray(
    SALT_LENGTH + IV_LENGTH,
    SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH
  );
  const encrypted = combined.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);

  const key = deriveKey(salt);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

/**
 * Generates a cryptographically secure random state string for OAuth
 * @param length - Number of random bytes (default: 32)
 * @returns Hex encoded random string
 */
export function generateSecureState(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Generates a secure random string for tokens
 * @param length - Number of random bytes
 * @returns Base64 URL-safe encoded string
 */
export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('base64url');
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
export function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
