/**
 * Property-Based Tests for End-to-End Encryption Round-Trip
 * 
 * **Validates: Requirements 1.1, 1.2, 1.3, 2.5, 2.6, 6.5, 9.1, 9.2, 9.5**
 * 
 * Property 1: End-to-End Encryption Round-Trip
 * For any secret string, generating a 256-bit key, splitting it into public and
 * private parts, encrypting the secret with AES-256-GCM, then combining the key
 * parts and decrypting should return the original secret unchanged.
 * 
 * Requirements context:
 * - 1.1: Generate cryptographically secure random key using Web Crypto API
 * - 1.2: Split key into Public_Key_Part and Private_Key_Part
 * - 1.3: Encrypt the secret using AES-256-GCM with the Combined_Key
 * - 2.5: Combine Public_Key_Part and Private_Key_Part to reconstruct the Combined_Key
 * - 2.6: Decrypt the Encrypted_Blob using AES-256-GCM
 * - 6.5: Use AES-256-GCM for all encryption operations
 * - 9.1: Generate a 256-bit random key for each secret
 * - 9.2: Split the key into two 128-bit parts
 * - 9.5: Combined_Key derived by concatenating Public_Key_Part and Private_Key_Part
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  generateKey,
  splitKey,
  combineKey,
  KEY_SIZE_BYTES,
} from '../../src/shared/crypto/key-generator';
import { encrypt, decrypt } from '../../src/shared/crypto/encryptor';

/**
 * Arbitrary generator for secret strings including:
 * - Empty strings
 * - ASCII strings
 * - Unicode strings (including emojis, CJK characters, etc.)
 * - Large strings
 */
const secretStringArbitrary = fc.oneof(
  // Empty string
  fc.constant(''),
  // ASCII strings of various lengths
  fc.string({ minLength: 1, maxLength: 100 }),
  // Unicode strings including special characters
  fc.unicodeString({ minLength: 1, maxLength: 100 }),
  // Large strings (up to 10KB)
  fc.string({ minLength: 1000, maxLength: 10000 }),
  // Strings with specific unicode categories
  fc.stringOf(
    fc.oneof(
      fc.char(), // Basic ASCII
      fc.unicode(), // Full unicode
      fc.constant('🔐'), // Emoji
      fc.constant('中文'), // CJK
      fc.constant('العربية'), // Arabic
      fc.constant('🎉🔒💻'), // Multiple emojis
    ),
    { minLength: 1, maxLength: 50 }
  )
);

/**
 * Arbitrary generator for 256-bit keys (32 bytes)
 */
const key256BitArbitrary = fc.uint8Array({
  minLength: KEY_SIZE_BYTES,
  maxLength: KEY_SIZE_BYTES,
});

describe('Property 1: End-to-End Encryption Round-Trip', () => {
  /**
   * **Validates: Requirements 1.1, 1.2, 1.3, 2.5, 2.6, 6.5, 9.1, 9.2, 9.5**
   * 
   * Property: For any secret string, the full encryption/decryption round-trip
   * using generated key, split, encrypt, combine, decrypt should return the
   * original secret unchanged.
   */
  it('encrypt then decrypt with split/combine key should return original secret', async () => {
    await fc.assert(
      fc.asyncProperty(secretStringArbitrary, async (originalSecret) => {
        // Step 1: Generate a 256-bit key (Req 1.1, 9.1)
        const fullKey = await generateKey();
        expect(fullKey.length).toBe(KEY_SIZE_BYTES);
        
        // Step 2: Split the key into public and private parts (Req 1.2, 9.2)
        const { publicPart, privatePart } = splitKey(fullKey);
        
        // Step 3: Encrypt the secret with the full key (Req 1.3, 6.5)
        const encryptedPayload = await encrypt(originalSecret, fullKey);
        
        // Verify encrypted payload structure
        expect(encryptedPayload).toHaveProperty('ciphertext');
        expect(encryptedPayload).toHaveProperty('iv');
        expect(encryptedPayload).toHaveProperty('tag');
        
        // Step 4: Combine the key parts to reconstruct the key (Req 2.5, 9.5)
        const reconstructedKey = combineKey(publicPart, privatePart);
        
        // Step 5: Decrypt with the reconstructed key (Req 2.6)
        const decryptedSecret = await decrypt(encryptedPayload, reconstructedKey);
        
        // The decrypted secret should match the original exactly
        expect(decryptedSecret).toBe(originalSecret);
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.3, 2.6, 6.5**
   * 
   * Property: Encryption with a randomly generated key and decryption with
   * the same key should always return the original secret.
   */
  it('encrypt then decrypt with same key should return original secret', async () => {
    await fc.assert(
      fc.asyncProperty(secretStringArbitrary, key256BitArbitrary, async (originalSecret, key) => {
        // Encrypt the secret
        const encryptedPayload = await encrypt(originalSecret, key);
        
        // Decrypt with the same key
        const decryptedSecret = await decrypt(encryptedPayload, key);
        
        // Should match original
        expect(decryptedSecret).toBe(originalSecret);
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.3, 6.5**
   * 
   * Property: Each encryption should produce a different ciphertext due to
   * random IV generation, even for the same plaintext and key.
   */
  it('encrypting same secret twice should produce different ciphertexts', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        key256BitArbitrary,
        async (secret, key) => {
          // Encrypt the same secret twice
          const encrypted1 = await encrypt(secret, key);
          const encrypted2 = await encrypt(secret, key);
          
          // IVs should be different (random)
          expect(encrypted1.iv).not.toBe(encrypted2.iv);
          
          // Ciphertexts should be different due to different IVs
          expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
          
          // But both should decrypt to the same original
          const decrypted1 = await decrypt(encrypted1, key);
          const decrypted2 = await decrypt(encrypted2, key);
          expect(decrypted1).toBe(secret);
          expect(decrypted2).toBe(secret);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 2.6, 6.5**
   * 
   * Property: Decryption with a wrong key should fail (authentication error).
   * This validates the integrity protection of AES-GCM.
   */
  it('decryption with wrong key should fail', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        key256BitArbitrary,
        key256BitArbitrary,
        async (secret, correctKey, wrongKey) => {
          // Skip if keys happen to be identical (extremely unlikely)
          if (arraysEqual(correctKey, wrongKey)) {
            return true;
          }
          
          // Encrypt with correct key
          const encryptedPayload = await encrypt(secret, correctKey);
          
          // Attempt to decrypt with wrong key should fail
          await expect(decrypt(encryptedPayload, wrongKey)).rejects.toThrow();
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.2, 2.5, 2.6, 9.5, 9.6**
   * 
   * Property: Decryption with key parts combined in wrong order should fail.
   * This validates that the key reconstruction order matters.
   */
  it('decryption with swapped key parts should fail', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        async (secret) => {
          // Generate key and split
          const fullKey = await generateKey();
          const { publicPart, privatePart } = splitKey(fullKey);
          
          // Skip if parts happen to be identical (extremely unlikely)
          if (arraysEqual(publicPart, privatePart)) {
            return true;
          }
          
          // Encrypt with full key
          const encryptedPayload = await encrypt(secret, fullKey);
          
          // Combine in wrong order
          const wrongOrderKey = combineKey(privatePart, publicPart);
          
          // Decryption with wrong order key should fail
          await expect(decrypt(encryptedPayload, wrongOrderKey)).rejects.toThrow();
          
          // But correct order should work
          const correctKey = combineKey(publicPart, privatePart);
          const decrypted = await decrypt(encryptedPayload, correctKey);
          expect(decrypted).toBe(secret);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});

/**
 * Helper function to compare two Uint8Arrays for equality
 */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
