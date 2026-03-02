/**
 * KeyGenerator module for secure secret sharing
 * 
 * Generates and manages cryptographic keys for secret encryption.
 * Uses Web Crypto API for cryptographically secure random generation.
 * 
 * Requirements:
 * - 1.1: Generate cryptographically secure random key using Web Crypto API
 * - 1.2: Split key into Public_Key_Part and Private_Key_Part
 * - 9.1: Generate a 256-bit random key for each secret
 * - 9.2: Split the key into two 128-bit parts
 * - 9.5: Combined_Key derived by concatenating Public_Key_Part and Private_Key_Part
 */

/** Size of the full key in bytes (256 bits) */
export const KEY_SIZE_BYTES = 32;

/** Size of each key part in bytes (128 bits) */
export const KEY_PART_SIZE_BYTES = 16;

/**
 * Result of splitting a key into two parts
 */
export interface SplitKeyResult {
  /** First 128 bits - stored in URL fragment (never sent to server) */
  publicPart: Uint8Array;
  /** Last 128 bits - stored on server alongside encrypted blob */
  privatePart: Uint8Array;
}

/**
 * Generates a 256-bit (32 bytes) cryptographically secure random key.
 * Uses crypto.getRandomValues() from the Web Crypto API.
 * 
 * @returns Promise resolving to a 256-bit random key as Uint8Array
 * @throws Error if crypto API is not available
 */
export async function generateKey(): Promise<Uint8Array> {
  const key = new Uint8Array(KEY_SIZE_BYTES);
  crypto.getRandomValues(key);
  return key;
}

/**
 * Splits a 256-bit key into two 128-bit parts.
 * 
 * The key is divided as follows:
 * - publicPart: bytes 0-15 (first 128 bits) - stored in URL fragment
 * - privatePart: bytes 16-31 (last 128 bits) - stored on server
 * 
 * @param key - The 256-bit key to split (must be exactly 32 bytes)
 * @returns Object containing publicPart and privatePart, each 128 bits
 * @throws Error if key is not exactly 32 bytes
 */
export function splitKey(key: Uint8Array): SplitKeyResult {
  if (key.length !== KEY_SIZE_BYTES) {
    throw new Error(`Key must be exactly ${KEY_SIZE_BYTES} bytes (256 bits), got ${key.length} bytes`);
  }

  // First 128 bits (16 bytes) - public part for URL fragment
  const publicPart = key.slice(0, KEY_PART_SIZE_BYTES);
  
  // Last 128 bits (16 bytes) - private part for server storage
  const privatePart = key.slice(KEY_PART_SIZE_BYTES, KEY_SIZE_BYTES);

  return { publicPart, privatePart };
}

/**
 * Combines two 128-bit key parts back into the original 256-bit key.
 * 
 * The parts are concatenated in order: publicPart + privatePart
 * This matches the split order to reconstruct the original key.
 * 
 * @param publicPart - The first 128 bits (from URL fragment)
 * @param privatePart - The last 128 bits (from server)
 * @returns The reconstructed 256-bit key
 * @throws Error if either part is not exactly 16 bytes
 */
export function combineKey(publicPart: Uint8Array, privatePart: Uint8Array): Uint8Array {
  if (publicPart.length !== KEY_PART_SIZE_BYTES) {
    throw new Error(`Public key part must be exactly ${KEY_PART_SIZE_BYTES} bytes (128 bits), got ${publicPart.length} bytes`);
  }
  
  if (privatePart.length !== KEY_PART_SIZE_BYTES) {
    throw new Error(`Private key part must be exactly ${KEY_PART_SIZE_BYTES} bytes (128 bits), got ${privatePart.length} bytes`);
  }

  // Concatenate: publicPart + privatePart
  const combinedKey = new Uint8Array(KEY_SIZE_BYTES);
  combinedKey.set(publicPart, 0);
  combinedKey.set(privatePart, KEY_PART_SIZE_BYTES);

  return combinedKey;
}

/**
 * KeyGenerator interface for dependency injection and testing
 */
export interface KeyGenerator {
  generateKey(): Promise<Uint8Array>;
  splitKey(key: Uint8Array): SplitKeyResult;
  combineKey(publicPart: Uint8Array, privatePart: Uint8Array): Uint8Array;
}

/**
 * Default KeyGenerator implementation using the module functions
 */
export const keyGenerator: KeyGenerator = {
  generateKey,
  splitKey,
  combineKey,
};
