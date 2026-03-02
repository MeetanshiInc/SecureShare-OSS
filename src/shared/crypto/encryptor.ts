/**
 * Encryptor module for secure secret sharing
 * 
 * Handles AES-256-GCM encryption and decryption operations.
 * Uses Web Crypto API for all cryptographic operations.
 * 
 * Requirements:
 * - 1.3: Encrypt the secret using AES-256-GCM with the Combined_Key
 * - 2.6: Decrypt the Encrypted_Blob using AES-256-GCM
 * - 6.5: Use AES-256-GCM for all encryption operations
 * - 8.6: Clear sensitive data from memory after use
 */

import { clearBuffer } from './secure-memory.js';

/** Size of the initialization vector in bytes (96 bits for GCM) */
export const IV_SIZE_BYTES = 12;

/** Size of the authentication tag in bytes (128 bits for GCM) */
export const TAG_SIZE_BYTES = 16;

/** Size of the encryption key in bytes (256 bits for AES-256) */
export const KEY_SIZE_BYTES = 32;

/**
 * Encrypted payload containing ciphertext, IV, and authentication tag.
 * All fields are Base64-encoded for transport.
 */
export interface EncryptedPayload {
  /** Base64-encoded ciphertext */
  ciphertext: string;
  /** Base64-encoded initialization vector (12 bytes) */
  iv: string;
  /** Base64-encoded authentication tag (16 bytes) */
  tag: string;
}

/**
 * Converts a Uint8Array to a Base64 string.
 * Uses standard Base64 encoding (not base64url).
 * 
 * @param bytes - The bytes to encode
 * @returns Base64-encoded string
 */
function toBase64(bytes: Uint8Array): string {
  // Convert Uint8Array to binary string
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

/**
 * Converts a Base64 string to a Uint8Array.
 * 
 * @param base64 - The Base64 string to decode
 * @returns Decoded bytes as Uint8Array
 * @throws Error if the string is not valid Base64
 */
function fromBase64(base64: string): Uint8Array {
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    throw new Error('Invalid Base64 encoding');
  }
}

/**
 * Imports a raw key for use with AES-GCM.
 * 
 * @param key - The raw key bytes (must be 32 bytes for AES-256)
 * @returns CryptoKey suitable for AES-GCM operations
 * @throws Error if key import fails
 */
async function importKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.length !== KEY_SIZE_BYTES) {
    throw new Error(`Key must be exactly ${KEY_SIZE_BYTES} bytes (256 bits), got ${key.length} bytes`);
  }

  // Create a copy with explicit ArrayBuffer type for Web Crypto API compatibility
  const keyBuffer = new ArrayBuffer(key.length);
  const keyView = new Uint8Array(keyBuffer);
  keyView.set(key);

  return crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-GCM' },
    false, // not extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts plaintext using AES-256-GCM with a random IV.
 * 
 * The function:
 * 1. Generates a random 12-byte IV
 * 2. Encrypts the plaintext using AES-256-GCM
 * 3. Extracts the authentication tag from the ciphertext
 * 4. Returns all components Base64-encoded
 * 
 * @param plaintext - The string to encrypt
 * @param key - The 256-bit encryption key (32 bytes)
 * @returns Promise resolving to EncryptedPayload with ciphertext, IV, and tag
 * @throws Error if encryption fails or key is invalid
 */
export async function encrypt(plaintext: string, key: Uint8Array): Promise<EncryptedPayload> {
  // Validate key size
  if (key.length !== KEY_SIZE_BYTES) {
    throw new Error(`Key must be exactly ${KEY_SIZE_BYTES} bytes (256 bits), got ${key.length} bytes`);
  }

  // Generate random IV (12 bytes for GCM)
  const iv = new Uint8Array(IV_SIZE_BYTES);
  crypto.getRandomValues(iv);

  // Track sensitive buffers for cleanup (Requirement 8.6)
  let plaintextBytes: Uint8Array | undefined;
  let encryptedBytes: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let tag: Uint8Array | undefined;

  try {
    // Import the key for AES-GCM
    const cryptoKey = await importKey(key);

    // Encode plaintext to bytes
    const encoder = new TextEncoder();
    plaintextBytes = encoder.encode(plaintext);

    // Create a copy with explicit ArrayBuffer type for Web Crypto API compatibility
    const plaintextBuffer = new ArrayBuffer(plaintextBytes.length);
    new Uint8Array(plaintextBuffer).set(plaintextBytes);

    // Encrypt with AES-256-GCM
    // The result includes the ciphertext with the authentication tag appended
    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: TAG_SIZE_BYTES * 8, // Tag length in bits (128)
      },
      cryptoKey,
      plaintextBuffer
    );

    encryptedBytes = new Uint8Array(encryptedBuffer);

    // AES-GCM appends the authentication tag to the ciphertext
    // Split them: ciphertext is everything except the last 16 bytes
    const ciphertextLength = encryptedBytes.length - TAG_SIZE_BYTES;
    ciphertext = encryptedBytes.slice(0, ciphertextLength);
    tag = encryptedBytes.slice(ciphertextLength);

    return {
      ciphertext: toBase64(ciphertext),
      iv: toBase64(iv),
      tag: toBase64(tag),
    };
  } finally {
    // SECURITY: Clear sensitive buffers from memory (Requirement 8.6)
    clearBuffer(iv);
    clearBuffer(plaintextBytes);
    clearBuffer(encryptedBytes);
    clearBuffer(ciphertext);
    clearBuffer(tag);
  }
}

/**
 * Decrypts an encrypted payload using AES-256-GCM.
 * 
 * The function:
 * 1. Decodes the Base64-encoded components
 * 2. Reconstructs the ciphertext with tag appended (as expected by Web Crypto)
 * 3. Decrypts and verifies the authentication tag
 * 4. Returns the original plaintext
 * 
 * @param payload - The encrypted payload containing ciphertext, IV, and tag
 * @param key - The 256-bit decryption key (32 bytes)
 * @returns Promise resolving to the decrypted plaintext string
 * @throws Error if decryption fails, authentication fails, or key is invalid
 */
export async function decrypt(payload: EncryptedPayload, key: Uint8Array): Promise<string> {
  // Validate key size
  if (key.length !== KEY_SIZE_BYTES) {
    throw new Error(`Key must be exactly ${KEY_SIZE_BYTES} bytes (256 bits), got ${key.length} bytes`);
  }

  // Validate payload structure
  // Note: ciphertext can be empty string for empty plaintext, so we check for undefined/null
  if (payload.ciphertext === undefined || payload.ciphertext === null ||
      !payload.iv || !payload.tag) {
    throw new Error('Invalid payload: missing ciphertext, iv, or tag');
  }

  // Track sensitive buffers for cleanup (Requirement 8.6)
  let ciphertext: Uint8Array | undefined;
  let iv: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  let encryptedData: Uint8Array | undefined;
  let decryptedBytes: Uint8Array | undefined;

  try {
    // Decode Base64 components
    try {
      ciphertext = fromBase64(payload.ciphertext);
      iv = fromBase64(payload.iv);
      tag = fromBase64(payload.tag);
    } catch {
      throw new Error('Invalid payload: failed to decode Base64 components');
    }

    // Validate IV size
    if (iv.length !== IV_SIZE_BYTES) {
      throw new Error(`Invalid IV: expected ${IV_SIZE_BYTES} bytes, got ${iv.length} bytes`);
    }

    // Validate tag size
    if (tag.length !== TAG_SIZE_BYTES) {
      throw new Error(`Invalid tag: expected ${TAG_SIZE_BYTES} bytes, got ${tag.length} bytes`);
    }

    // Import the key for AES-GCM
    const cryptoKey = await importKey(key);

    // Reconstruct the encrypted data (ciphertext + tag) as expected by Web Crypto
    encryptedData = new Uint8Array(ciphertext.length + tag.length);
    encryptedData.set(ciphertext, 0);
    encryptedData.set(tag, ciphertext.length);

    // Decrypt with AES-256-GCM
    // This will throw if authentication fails
    let decryptedBuffer: ArrayBuffer;
    try {
      // Create copies with explicit ArrayBuffer type for Web Crypto API compatibility
      const ivBuffer = new ArrayBuffer(iv.length);
      new Uint8Array(ivBuffer).set(iv);
      
      const dataBuffer = new ArrayBuffer(encryptedData.length);
      new Uint8Array(dataBuffer).set(encryptedData);

      decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ivBuffer,
          tagLength: TAG_SIZE_BYTES * 8, // Tag length in bits (128)
        },
        cryptoKey,
        dataBuffer
      );
    } catch {
      throw new Error('Decryption failed: authentication tag verification failed or data is corrupted');
    }

    // Decode bytes to string
    decryptedBytes = new Uint8Array(decryptedBuffer);
    const decoder = new TextDecoder();
    const result = decoder.decode(decryptedBytes);
    
    return result;
  } finally {
    // SECURITY: Clear sensitive buffers from memory (Requirement 8.6)
    clearBuffer(ciphertext);
    clearBuffer(iv);
    clearBuffer(tag);
    clearBuffer(encryptedData);
    clearBuffer(decryptedBytes);
  }
}

/**
 * Encryptor interface for dependency injection and testing
 */
export interface Encryptor {
  encrypt(plaintext: string, key: Uint8Array): Promise<EncryptedPayload>;
  decrypt(payload: EncryptedPayload, key: Uint8Array): Promise<string>;
}

/**
 * Default Encryptor implementation using the module functions
 */
export const encryptor: Encryptor = {
  encrypt,
  decrypt,
};
