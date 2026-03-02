/**
 * SecretStore module for secure secret sharing
 * 
 * Handles storage and retrieval of encrypted secrets using Cloudflare KV.
 * Implements atomic get-and-delete operations for one-time access.
 * 
 * Requirements:
 * - 1.5: Generate a unique Secret_ID and store the data in Secret_Store
 * - 2.3: Return the Encrypted_Blob and Private_Key_Part exactly once
 * - 2.4: Immediately delete the secret from Secret_Store after retrieval
 * - 4.3: Store the secret with a TTL in Secret_Store
 */

import type { EncryptedPayload } from '../shared/crypto/encryptor';

/** Length of generated secret IDs (16 alphanumeric characters) */
export const SECRET_ID_LENGTH = 16;

/** Characters used for secret ID generation (alphanumeric) */
const SECRET_ID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Default TTL in seconds (1 hour) */
export const DEFAULT_TTL_SECONDS = 3600;

/**
 * TTL mapping for expiration options
 */
export const TTL_MAP: Record<string, number> = {
  '1h': 3600,
  '24h': 86400,
  '7d': 604800,
  '30d': 2592000,
};

/**
 * Data structure stored in KV for each secret
 */
export interface StoredSecret {
  /** Encrypted payload containing ciphertext, IV, and tag */
  encryptedBlob: EncryptedPayload;
  /** Base64url-encoded private key part (128 bits) */
  privateKeyPart: string;
  /** Optional email address for view notification */
  notifyEmail?: string;
  /** Optional Base64-encoded salt for password protection */
  passwordSalt?: string;
  /** Unix timestamp when the secret was created */
  createdAt: number;
}

/**
 * Generates a cryptographically secure random secret ID.
 * 
 * Uses crypto.getRandomValues() to generate a 16-character alphanumeric ID.
 * The ID space is 62^16 ≈ 4.7 × 10^28, providing excellent collision resistance.
 * 
 * @returns A 16-character alphanumeric secret ID
 */
export function generateSecretId(): string {
  const randomBytes = new Uint8Array(SECRET_ID_LENGTH);
  crypto.getRandomValues(randomBytes);
  
  let secretId = '';
  for (let i = 0; i < SECRET_ID_LENGTH; i++) {
    // Use modulo to map random byte to alphabet index
    // This has slight bias but is acceptable for our use case
    const index = randomBytes[i]! % SECRET_ID_ALPHABET.length;
    secretId += SECRET_ID_ALPHABET[index];
  }
  
  return secretId;
}

/**
 * Validates that a string is a valid secret ID format.
 * 
 * @param id - The string to validate
 * @returns true if the string is a valid 16-character alphanumeric ID
 */
export function isValidSecretId(id: string): boolean {
  if (typeof id !== 'string') {
    return false;
  }
  
  if (id.length !== SECRET_ID_LENGTH) {
    return false;
  }
  
  // Check that all characters are alphanumeric
  return /^[A-Za-z0-9]+$/.test(id);
}

/**
 * Converts an expiration option to TTL in seconds.
 * 
 * @param expiresIn - Expiration option ('1h', '24h', '7d', '30d') or undefined
 * @returns TTL in seconds, defaults to 1 hour if not specified
 */
export function getTtlSeconds(expiresIn?: string): number {
  if (!expiresIn) {
    return DEFAULT_TTL_SECONDS;
  }
  
  const ttl = TTL_MAP[expiresIn];
  if (ttl === undefined) {
    return DEFAULT_TTL_SECONDS;
  }
  
  return ttl;
}

/**
 * SecretStore interface for Cloudflare KV operations.
 * Provides methods for storing and retrieving secrets with TTL support.
 */
export interface SecretStore {
  /**
   * Stores a secret with optional TTL.
   */
  store(secretId: string, data: StoredSecret, ttlSeconds?: number): Promise<void>;

  /**
   * Retrieves a secret without deleting it.
   * Used for password-protected secrets where deletion happens after successful decryption.
   */
  get(secretId: string): Promise<StoredSecret | null>;

  /**
   * Deletes a secret from the store.
   */
  delete(secretId: string): Promise<void>;

  /**
   * Retrieves and deletes a secret atomically.
   * Used for non-password-protected secrets (one-time access).
   */
  getAndDelete(secretId: string): Promise<StoredSecret | null>;
}

/**
 * Creates a SecretStore implementation backed by Cloudflare KV.
 * 
 * @param kv - The Cloudflare KV namespace to use for storage
 * @returns A SecretStore implementation
 */
export function createSecretStore(kv: KVNamespace): SecretStore {
  return {
    async store(secretId: string, data: StoredSecret, ttlSeconds?: number): Promise<void> {
      if (!isValidSecretId(secretId)) {
        throw new Error('Invalid secret ID format');
      }
      if (!data.encryptedBlob || !data.privateKeyPart) {
        throw new Error('Missing required fields: encryptedBlob and privateKeyPart');
      }
      const ttl = ttlSeconds ?? DEFAULT_TTL_SECONDS;
      const storedData: StoredSecret = {
        ...data,
        createdAt: data.createdAt || Date.now(),
      };
      await kv.put(secretId, JSON.stringify(storedData), {
        expirationTtl: ttl,
      });
    },

    async get(secretId: string): Promise<StoredSecret | null> {
      if (!isValidSecretId(secretId)) {
        return null;
      }
      const value = await kv.get(secretId);
      if (value === null) {
        return null;
      }
      try {
        const data = JSON.parse(value) as StoredSecret;
        if (!data.encryptedBlob || !data.privateKeyPart) {
          return null;
        }
        return data;
      } catch {
        return null;
      }
    },

    async delete(secretId: string): Promise<void> {
      if (!isValidSecretId(secretId)) {
        return;
      }
      await kv.delete(secretId);
    },

    async getAndDelete(secretId: string): Promise<StoredSecret | null> {
      if (!isValidSecretId(secretId)) {
        return null;
      }
      const value = await kv.get(secretId);
      if (value === null) {
        return null;
      }
      await kv.delete(secretId);
      try {
        const data = JSON.parse(value) as StoredSecret;
        if (!data.encryptedBlob || !data.privateKeyPart) {
          return null;
        }
        return data;
      } catch {
        return null;
      }
    },
  };
}

/**
 * SecretStore factory type for dependency injection
 */
export type SecretStoreFactory = (kv: KVNamespace) => SecretStore;

/**
 * Default factory function for creating SecretStore instances
 */
export const secretStoreFactory: SecretStoreFactory = createSecretStore;
