/**
 * Property-Based Tests for Password Protection Round-Trip
 * 
 * **Validates: Requirements 3.2, 3.3**
 * 
 * Property 6: Password Protection Round-Trip
 * For any secret with password protection enabled, deriving a key from the password
 * and salt, performing double encryption, then deriving the same key and decrypting
 * should return the original secret. Using a different password should fail decryption.
 * 
 * Requirements context:
 * - 3.2: The system SHALL use PBKDF2 with 100,000 iterations and SHA-256 to derive a key from the password
 * - 3.3: When a password is provided, the system SHALL first encrypt the secret with the Combined_Key,
 *        then encrypt the result with the Password_Derived_Key
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  generateKey,
  splitKey,
  combineKey,
} from '../../src/shared/crypto/key-generator';
import { encrypt, decrypt, type EncryptedPayload } from '../../src/shared/crypto/encryptor';
import {
  generateSalt,
  deriveKey,
  PBKDF2_ITERATIONS,
  PBKDF2_HASH,
  SALT_SIZE_BYTES,
  DERIVED_KEY_SIZE_BYTES,
} from '../../src/shared/crypto/password-deriver';

/**
 * Arbitrary generator for secret content including:
 * - Empty strings
 * - ASCII strings
 * - Unicode strings (including emojis, CJK characters, etc.)
 * - Large strings
 */
const secretContentArbitrary = fc.oneof(
  // Empty string
  fc.constant(''),
  // ASCII strings of various lengths
  fc.string({ minLength: 1, maxLength: 100 }),
  // Unicode strings including special characters
  fc.unicodeString({ minLength: 1, maxLength: 100 }),
  // Large strings (up to 5KB for reasonable test performance)
  fc.string({ minLength: 500, maxLength: 5000 }),
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
 * Arbitrary generator for passwords including:
 * - Empty passwords
 * - ASCII passwords
 * - Unicode passwords
 * - Long passwords
 */
const passwordArbitrary = fc.oneof(
  // Empty password
  fc.constant(''),
  // Short ASCII passwords
  fc.string({ minLength: 1, maxLength: 20 }),
  // Unicode passwords
  fc.unicodeString({ minLength: 1, maxLength: 20 }),
  // Long passwords
  fc.string({ minLength: 50, maxLength: 200 }),
  // Passwords with special characters
  fc.stringOf(
    fc.oneof(
      fc.char(),
      fc.constant('!@#$%^&*()'),
      fc.constant('🔑'),
      fc.constant('密码'),
    ),
    { minLength: 1, maxLength: 30 }
  )
);

/**
 * Arbitrary generator for different passwords (guaranteed to be different)
 */
const differentPasswordsArbitrary = fc.tuple(
  fc.string({ minLength: 1, maxLength: 50 }),
  fc.string({ minLength: 1, maxLength: 50 })
).filter(([p1, p2]) => p1 !== p2);

/**
 * Performs double encryption as specified in Requirement 3.3:
 * 1. First encrypt the secret with the Combined_Key
 * 2. Then encrypt the result with the Password_Derived_Key
 * 
 * @param secret - The plaintext secret to encrypt
 * @param combinedKey - The 256-bit combined key (public + private parts)
 * @param passwordDerivedKey - The 256-bit key derived from password
 * @returns The double-encrypted payload
 */
async function doubleEncrypt(
  secret: string,
  combinedKey: Uint8Array,
  passwordDerivedKey: Uint8Array
): Promise<EncryptedPayload> {
  // Step 1: Encrypt with Combined_Key (inner layer)
  const innerEncrypted = await encrypt(secret, combinedKey);
  
  // Step 2: Serialize the inner encrypted payload
  const innerJson = JSON.stringify(innerEncrypted);
  
  // Step 3: Encrypt with Password_Derived_Key (outer layer)
  const outerEncrypted = await encrypt(innerJson, passwordDerivedKey);
  
  return outerEncrypted;
}

/**
 * Performs double decryption (reverse of doubleEncrypt):
 * 1. First decrypt the outer layer with the Password_Derived_Key
 * 2. Then decrypt the inner layer with the Combined_Key
 * 
 * @param encryptedPayload - The double-encrypted payload
 * @param combinedKey - The 256-bit combined key (public + private parts)
 * @param passwordDerivedKey - The 256-bit key derived from password
 * @returns The decrypted plaintext secret
 */
async function doubleDecrypt(
  encryptedPayload: EncryptedPayload,
  combinedKey: Uint8Array,
  passwordDerivedKey: Uint8Array
): Promise<string> {
  // Step 1: Decrypt outer layer with Password_Derived_Key
  const innerJson = await decrypt(encryptedPayload, passwordDerivedKey);
  
  // Step 2: Parse the inner encrypted payload
  const innerEncrypted = JSON.parse(innerJson) as EncryptedPayload;
  
  // Step 3: Decrypt inner layer with Combined_Key
  const secret = await decrypt(innerEncrypted, combinedKey);
  
  return secret;
}

describe('Property 6: Password Protection Round-Trip', () => {
  /**
   * **Validates: Requirements 3.2, 3.3**
   * 
   * Property: For any secret content and password, double encryption followed by
   * double decryption with the same password should return the original secret.
   */
  it('double encryption then decryption with correct password should return original secret', async () => {
    await fc.assert(
      fc.asyncProperty(secretContentArbitrary, passwordArbitrary, async (originalSecret, password) => {
        // Generate the combined key (simulating key generation and splitting)
        const fullKey = await generateKey();
        const { publicPart, privatePart } = splitKey(fullKey);
        const combinedKey = combineKey(publicPart, privatePart);
        
        // Generate salt and derive password key (Req 3.2)
        const salt = generateSalt();
        expect(salt.length).toBe(SALT_SIZE_BYTES);
        
        const passwordDerivedKey = await deriveKey(password, salt);
        expect(passwordDerivedKey.length).toBe(DERIVED_KEY_SIZE_BYTES);
        
        // Perform double encryption (Req 3.3)
        const encryptedPayload = await doubleEncrypt(originalSecret, combinedKey, passwordDerivedKey);
        
        // Verify encrypted payload structure
        expect(encryptedPayload).toHaveProperty('ciphertext');
        expect(encryptedPayload).toHaveProperty('iv');
        expect(encryptedPayload).toHaveProperty('tag');
        
        // Derive the same key from password and salt
        const samePasswordDerivedKey = await deriveKey(password, salt);
        
        // Perform double decryption
        const decryptedSecret = await doubleDecrypt(encryptedPayload, combinedKey, samePasswordDerivedKey);
        
        // The decrypted secret should match the original exactly
        expect(decryptedSecret).toBe(originalSecret);
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 3.2, 3.3**
   * 
   * Property: Decryption with a different password should fail.
   * This validates that password protection actually protects the secret.
   */
  it('decryption with wrong password should fail', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        differentPasswordsArbitrary,
        async (secret, [correctPassword, wrongPassword]) => {
          // Generate the combined key
          const fullKey = await generateKey();
          const { publicPart, privatePart } = splitKey(fullKey);
          const combinedKey = combineKey(publicPart, privatePart);
          
          // Generate salt and derive password key with correct password
          const salt = generateSalt();
          const correctPasswordKey = await deriveKey(correctPassword, salt);
          
          // Perform double encryption with correct password
          const encryptedPayload = await doubleEncrypt(secret, combinedKey, correctPasswordKey);
          
          // Derive key with wrong password
          const wrongPasswordKey = await deriveKey(wrongPassword, salt);
          
          // Attempt to decrypt with wrong password should fail
          await expect(
            doubleDecrypt(encryptedPayload, combinedKey, wrongPasswordKey)
          ).rejects.toThrow();
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirement 3.2**
   * 
   * Property: PBKDF2 key derivation should be deterministic - same password and salt
   * should always produce the same derived key.
   */
  it('same password and salt should produce same derived key', async () => {
    await fc.assert(
      fc.asyncProperty(passwordArbitrary, async (password) => {
        // Generate a salt
        const salt = generateSalt();
        
        // Derive key twice with same inputs
        const key1 = await deriveKey(password, salt);
        const key2 = await deriveKey(password, salt);
        
        // Keys should be identical
        expect(key1.length).toBe(DERIVED_KEY_SIZE_BYTES);
        expect(key2.length).toBe(DERIVED_KEY_SIZE_BYTES);
        expect(arraysEqual(key1, key2)).toBe(true);
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirement 3.2**
   * 
   * Property: Different salts should produce different derived keys for the same password.
   * This validates that the salt provides uniqueness.
   */
  it('different salts should produce different derived keys', async () => {
    await fc.assert(
      fc.asyncProperty(passwordArbitrary, async (password) => {
        // Generate two different salts
        const salt1 = generateSalt();
        const salt2 = generateSalt();
        
        // Skip if salts happen to be identical (extremely unlikely)
        if (arraysEqual(salt1, salt2)) {
          return true;
        }
        
        // Derive keys with different salts
        const key1 = await deriveKey(password, salt1);
        const key2 = await deriveKey(password, salt2);
        
        // Keys should be different
        expect(arraysEqual(key1, key2)).toBe(false);
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirement 3.3**
   * 
   * Property: The double encryption structure should be maintained - the outer layer
   * should be encrypted with the password key, and the inner layer with the combined key.
   * Decrypting only the outer layer should reveal a valid encrypted payload structure.
   */
  it('double encryption maintains layered structure', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        passwordArbitrary,
        async (secret, password) => {
          // Generate the combined key
          const fullKey = await generateKey();
          const { publicPart, privatePart } = splitKey(fullKey);
          const combinedKey = combineKey(publicPart, privatePart);
          
          // Generate salt and derive password key
          const salt = generateSalt();
          const passwordDerivedKey = await deriveKey(password, salt);
          
          // Perform double encryption
          const outerEncrypted = await doubleEncrypt(secret, combinedKey, passwordDerivedKey);
          
          // Decrypt only the outer layer with password key
          const innerJson = await decrypt(outerEncrypted, passwordDerivedKey);
          
          // The inner layer should be a valid EncryptedPayload JSON
          const innerEncrypted = JSON.parse(innerJson) as EncryptedPayload;
          expect(innerEncrypted).toHaveProperty('ciphertext');
          expect(innerEncrypted).toHaveProperty('iv');
          expect(innerEncrypted).toHaveProperty('tag');
          expect(typeof innerEncrypted.ciphertext).toBe('string');
          expect(typeof innerEncrypted.iv).toBe('string');
          expect(typeof innerEncrypted.tag).toBe('string');
          
          // Decrypt the inner layer with combined key
          const decryptedSecret = await decrypt(innerEncrypted, combinedKey);
          expect(decryptedSecret).toBe(secret);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 3.2, 3.3**
   * 
   * Property: Integration test simulating the full SecretCreator/SecretViewer flow
   * with password protection.
   */
  it('full password protection flow should work end-to-end', async () => {
    await fc.assert(
      fc.asyncProperty(secretContentArbitrary, passwordArbitrary, async (originalSecret, password) => {
        // === SecretCreator side ===
        
        // Step 1: Generate a 256-bit key
        const fullKey = await generateKey();
        
        // Step 2: Split the key into public and private parts
        const { publicPart, privatePart } = splitKey(fullKey);
        
        // Step 3: Encrypt the secret with the full key (inner layer)
        const innerEncrypted = await encrypt(originalSecret, fullKey);
        
        // Step 4: Generate salt and derive password key
        const salt = generateSalt();
        const passwordDerivedKey = await deriveKey(password, salt);
        
        // Step 5: Serialize inner encrypted payload and encrypt with password key (outer layer)
        const innerJson = JSON.stringify(innerEncrypted);
        const outerEncrypted = await encrypt(innerJson, passwordDerivedKey);
        
        // At this point, outerEncrypted and privatePart would be sent to server
        // publicPart would be in URL fragment
        // salt would be stored with the secret
        
        // === SecretViewer side ===
        
        // Step 1: Receive outerEncrypted, privatePart, salt from server
        // Step 2: Get publicPart from URL fragment
        
        // Step 3: Derive password key from user-provided password
        const viewerPasswordKey = await deriveKey(password, salt);
        
        // Step 4: Decrypt outer layer with password key
        const viewerInnerJson = await decrypt(outerEncrypted, viewerPasswordKey);
        const viewerInnerEncrypted = JSON.parse(viewerInnerJson) as EncryptedPayload;
        
        // Step 5: Combine key parts
        const viewerCombinedKey = combineKey(publicPart, privatePart);
        
        // Step 6: Decrypt inner layer with combined key
        const decryptedSecret = await decrypt(viewerInnerEncrypted, viewerCombinedKey);
        
        // The decrypted secret should match the original
        expect(decryptedSecret).toBe(originalSecret);
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirement 3.2**
   * 
   * Property: Verify PBKDF2 configuration constants are correct.
   */
  it('PBKDF2 configuration should match requirements', () => {
    // Requirement 3.2: 100,000 iterations
    expect(PBKDF2_ITERATIONS).toBe(100000);
    
    // Requirement 3.2: SHA-256
    expect(PBKDF2_HASH).toBe('SHA-256');
    
    // Salt should be 128 bits (16 bytes)
    expect(SALT_SIZE_BYTES).toBe(16);
    
    // Derived key should be 256 bits (32 bytes)
    expect(DERIVED_KEY_SIZE_BYTES).toBe(32);
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
