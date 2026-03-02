/**
 * PasswordDeriver module for secure secret sharing
 * 
 * Derives encryption keys from user passwords using PBKDF2.
 * Uses Web Crypto API for all cryptographic operations.
 * 
 * Requirements:
 * - 3.2: The system SHALL use PBKDF2 with 100,000 iterations and SHA-256 to derive a key from the password
 * - 8.6: Clear sensitive data from memory after use
 */

import { clearBuffer } from './secure-memory.js';

/** Size of the salt in bytes (128 bits) */
export const SALT_SIZE_BYTES = 16;

/** Size of the derived key in bytes (256 bits) */
export const DERIVED_KEY_SIZE_BYTES = 32;

/** Number of PBKDF2 iterations */
export const PBKDF2_ITERATIONS = 100000;

/** Hash algorithm for PBKDF2 */
export const PBKDF2_HASH = 'SHA-256';

/**
 * Generates a random salt for password derivation.
 * 
 * Uses crypto.getRandomValues() to generate a cryptographically
 * secure random 16-byte (128-bit) salt.
 * 
 * @returns A 16-byte random salt as Uint8Array
 * 
 * @example
 * const salt = generateSalt();
 * // salt is a 16-byte Uint8Array
 */
export function generateSalt(): Uint8Array {
  const salt = new Uint8Array(SALT_SIZE_BYTES);
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * Derives a 256-bit key from a password using PBKDF2.
 * 
 * The derivation uses:
 * - 100,000 iterations (as per requirement 3.2)
 * - SHA-256 hash algorithm
 * - 256-bit (32 bytes) output key length
 * 
 * @param password - The password to derive the key from
 * @param salt - The salt to use for derivation (must be 16 bytes)
 * @returns Promise resolving to a 256-bit derived key as Uint8Array
 * @throws Error if salt is not exactly 16 bytes
 * 
 * @example
 * const salt = generateSalt();
 * const key = await deriveKey("myPassword", salt);
 * // key is a 32-byte Uint8Array
 */
export async function deriveKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  // Validate salt size
  if (salt.length !== SALT_SIZE_BYTES) {
    throw new Error(`Salt must be exactly ${SALT_SIZE_BYTES} bytes (128 bits), got ${salt.length} bytes`);
  }

  // Track sensitive buffers for cleanup (Requirement 8.6)
  let passwordBytes: Uint8Array | undefined;

  try {
    // Encode password to bytes
    const encoder = new TextEncoder();
    passwordBytes = encoder.encode(password);

    // Create a copy with explicit ArrayBuffer type for Web Crypto API compatibility
    const passwordBuffer = new ArrayBuffer(passwordBytes.length);
    new Uint8Array(passwordBuffer).set(passwordBytes);

    // Import password as a key for PBKDF2
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false, // not extractable
      ['deriveBits']
    );

    // Create a copy of salt with explicit ArrayBuffer type for Web Crypto API compatibility
    const saltBuffer = new ArrayBuffer(salt.length);
    new Uint8Array(saltBuffer).set(salt);

    // Derive key using PBKDF2
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: PBKDF2_ITERATIONS,
        hash: PBKDF2_HASH,
      },
      passwordKey,
      DERIVED_KEY_SIZE_BYTES * 8 // Length in bits
    );

    return new Uint8Array(derivedBits);
  } finally {
    // SECURITY: Clear sensitive buffers from memory (Requirement 8.6)
    clearBuffer(passwordBytes);
  }
}

/**
 * PasswordDeriver interface for dependency injection and testing
 */
export interface PasswordDeriver {
  generateSalt(): Uint8Array;
  deriveKey(password: string, salt: Uint8Array): Promise<Uint8Array>;
}

/**
 * Default PasswordDeriver implementation using the module functions
 */
export const passwordDeriver: PasswordDeriver = {
  generateSalt,
  deriveKey,
};
