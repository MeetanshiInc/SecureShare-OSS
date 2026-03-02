/**
 * Property-Based Tests for Wrong Password Preserves Access
 * 
 * **Validates: Requirements 3.6**
 * 
 * Property 7: Wrong Password Preserves Access
 * For any password-protected secret, providing an incorrect password should fail
 * decryption but should not consume the one-time access. The secret should remain
 * retrievable with the correct password.
 * 
 * This tests the client-side behavior:
 * 1. Attempting decryption with wrong password fails
 * 2. The encrypted data remains unchanged after failed attempt
 * 3. Subsequent attempt with correct password succeeds
 * 4. Multiple wrong password attempts don't corrupt the data
 * 
 * Requirements context:
 * - 3.6: The system SHALL allow the user to retry with a different password if
 *        decryption fails, without consuming the one-time access
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
} from '../../src/shared/crypto/password-deriver';
import {
  decryptWithPassword,
  SecretViewError,
  type ViewSecretPasswordRequired,
} from '../../src/frontend/secret-viewer';
import { toBase64url } from '../../src/shared/encoding';

/**
 * Arbitrary generator for secret content including:
 * - Empty strings
 * - ASCII strings
 * - Unicode strings
 * - Large strings
 */
const secretContentArbitrary = fc.oneof(
  // Empty string
  fc.constant(''),
  // ASCII strings of various lengths
  fc.string({ minLength: 1, maxLength: 100 }),
  // Unicode strings including special characters
  fc.string({ minLength: 1, maxLength: 100, unit: 'grapheme' }),
  // Large strings (up to 5KB for reasonable test performance)
  fc.string({ minLength: 500, maxLength: 5000 }),
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
 * Performs double decryption (reverse of doubleEncrypt)
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

/**
 * Creates a simulated password-required result as would be returned by viewSecret
 */
async function createPasswordProtectedSecret(
  secret: string,
  password: string
): Promise<{
  passwordRequiredResult: ViewSecretPasswordRequired;
  combinedKey: Uint8Array;
  originalEncryptedBlob: EncryptedPayload;
}> {
  // Generate the combined key
  const fullKey = await generateKey();
  const { publicPart, privatePart } = splitKey(fullKey);
  const combinedKey = combineKey(publicPart, privatePart);
  
  // Generate salt and derive password key
  const salt = generateSalt();
  const passwordDerivedKey = await deriveKey(password, salt);
  
  // Perform double encryption
  const encryptedBlob = await doubleEncrypt(secret, combinedKey, passwordDerivedKey);
  
  // Create the password-required result as would be returned by viewSecret
  const passwordRequiredResult: ViewSecretPasswordRequired = {
    status: 'password_required',
    passwordSalt: toBase64url(salt),
    encryptedBlob: encryptedBlob,
    privateKeyPart: toBase64url(privatePart),
    publicKeyPart: toBase64url(publicPart),
  };
  
  return {
    passwordRequiredResult,
    combinedKey,
    originalEncryptedBlob: encryptedBlob,
  };
}

/**
 * Deep clone an EncryptedPayload to verify it hasn't been modified
 */
function cloneEncryptedPayload(payload: EncryptedPayload): EncryptedPayload {
  return {
    ciphertext: payload.ciphertext,
    iv: payload.iv,
    tag: payload.tag,
  };
}

/**
 * Compare two EncryptedPayloads for equality
 */
function encryptedPayloadsEqual(a: EncryptedPayload, b: EncryptedPayload): boolean {
  return a.ciphertext === b.ciphertext &&
         a.iv === b.iv &&
         a.tag === b.tag;
}

describe('Property 7: Wrong Password Preserves Access', () => {
  /**
   * **Validates: Requirements 3.6**
   * 
   * Property: Attempting decryption with wrong password should fail but not
   * modify the encrypted data.
   */
  it('wrong password fails decryption but encrypted data remains unchanged', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        differentPasswordsArbitrary,
        async (secret, [correctPassword, wrongPassword]) => {
          // Create a password-protected secret
          const { passwordRequiredResult, originalEncryptedBlob } = 
            await createPasswordProtectedSecret(secret, correctPassword);
          
          // Clone the encrypted blob before attempting wrong password
          const encryptedBlobBefore = cloneEncryptedPayload(passwordRequiredResult.encryptedBlob);
          
          // Attempt decryption with wrong password - should fail
          await expect(
            decryptWithPassword(passwordRequiredResult, wrongPassword)
          ).rejects.toThrow();
          
          // Verify the encrypted data is unchanged after failed attempt
          expect(encryptedPayloadsEqual(
            passwordRequiredResult.encryptedBlob,
            encryptedBlobBefore
          )).toBe(true);
          
          // Verify the original encrypted blob is also unchanged
          expect(encryptedPayloadsEqual(
            passwordRequiredResult.encryptedBlob,
            originalEncryptedBlob
          )).toBe(true);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 3.6**
   * 
   * Property: After a wrong password attempt, the correct password should
   * still successfully decrypt the secret.
   */
  it('correct password succeeds after wrong password attempt', async () => {
    await fc.assert(
      fc.asyncProperty(
        secretContentArbitrary,
        differentPasswordsArbitrary,
        async (secret, [correctPassword, wrongPassword]) => {
          // Create a password-protected secret
          const { passwordRequiredResult } = 
            await createPasswordProtectedSecret(secret, correctPassword);
          
          // Attempt decryption with wrong password - should fail
          try {
            await decryptWithPassword(passwordRequiredResult, wrongPassword);
            // If we get here, the wrong password somehow worked (shouldn't happen)
            return false;
          } catch (error) {
            // Expected - wrong password should fail
            expect(error).toBeInstanceOf(SecretViewError);
            expect((error as SecretViewError).type).toBe('WRONG_PASSWORD');
          }
          
          // Now attempt with correct password - should succeed
          const result = await decryptWithPassword(passwordRequiredResult, correctPassword);
          
          expect(result.status).toBe('success');
          expect(result.content).toBe(secret);
          expect(result.isPasswordProtected).toBe(true);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 3.6**
   * 
   * Property: Multiple wrong password attempts should not corrupt the data
   * or prevent eventual successful decryption with the correct password.
   */
  it('multiple wrong password attempts do not corrupt data', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.string({ minLength: 1, maxLength: 30 }),
        // Generate 3 wrong passwords as part of the property input
        fc.array(fc.string({ minLength: 1, maxLength: 50 }), { minLength: 3, maxLength: 3 }),
        async (secret, correctPassword, wrongPasswordCandidates) => {
          // Filter out any passwords that happen to match the correct one
          const wrongPasswords = wrongPasswordCandidates.filter(p => p !== correctPassword);
          
          // Skip if we don't have enough wrong passwords
          if (wrongPasswords.length < 2) {
            return true; // Skip this iteration
          }
          
          // Create a password-protected secret
          const { passwordRequiredResult, originalEncryptedBlob } = 
            await createPasswordProtectedSecret(secret, correctPassword);
          
          // Attempt decryption with each wrong password
          for (const wrongPassword of wrongPasswords) {
            try {
              await decryptWithPassword(passwordRequiredResult, wrongPassword);
              // Should not succeed
              return false;
            } catch (error) {
              // Expected - wrong password should fail
              expect(error).toBeInstanceOf(SecretViewError);
              expect((error as SecretViewError).type).toBe('WRONG_PASSWORD');
            }
          }
          
          // Verify encrypted data is still unchanged after multiple failed attempts
          expect(encryptedPayloadsEqual(
            passwordRequiredResult.encryptedBlob,
            originalEncryptedBlob
          )).toBe(true);
          
          // Correct password should still work
          const result = await decryptWithPassword(passwordRequiredResult, correctPassword);
          
          expect(result.status).toBe('success');
          expect(result.content).toBe(secret);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 3.6**
   * 
   * Property: The decryptWithPassword function should throw a WRONG_PASSWORD
   * error specifically when the password is incorrect.
   */
  it('wrong password throws WRONG_PASSWORD error type', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        differentPasswordsArbitrary,
        async (secret, [correctPassword, wrongPassword]) => {
          // Create a password-protected secret
          const { passwordRequiredResult } = 
            await createPasswordProtectedSecret(secret, correctPassword);
          
          // Attempt decryption with wrong password
          try {
            await decryptWithPassword(passwordRequiredResult, wrongPassword);
            // Should not reach here
            return false;
          } catch (error) {
            // Verify it's a SecretViewError with WRONG_PASSWORD type
            expect(error).toBeInstanceOf(SecretViewError);
            const secretViewError = error as SecretViewError;
            expect(secretViewError.type).toBe('WRONG_PASSWORD');
            expect(secretViewError.message).toContain('Incorrect password');
          }
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 3.6**
   * 
   * Property: The passwordRequiredResult object should remain completely
   * unchanged after any number of decryption attempts (successful or not).
   */
  it('passwordRequiredResult is immutable during decryption attempts', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        differentPasswordsArbitrary,
        async (secret, [correctPassword, wrongPassword]) => {
          // Create a password-protected secret
          const { passwordRequiredResult } = 
            await createPasswordProtectedSecret(secret, correctPassword);
          
          // Capture the original state
          const originalState = JSON.stringify(passwordRequiredResult);
          
          // Attempt wrong password
          try {
            await decryptWithPassword(passwordRequiredResult, wrongPassword);
          } catch {
            // Expected
          }
          
          // Verify state unchanged
          expect(JSON.stringify(passwordRequiredResult)).toBe(originalState);
          
          // Attempt correct password
          await decryptWithPassword(passwordRequiredResult, correctPassword);
          
          // Verify state still unchanged
          expect(JSON.stringify(passwordRequiredResult)).toBe(originalState);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 3.6**
   * 
   * Property: Direct double decryption with wrong password should fail
   * but not affect the encrypted payload.
   */
  it('direct double decryption with wrong password fails cleanly', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        differentPasswordsArbitrary,
        async (secret, [correctPassword, wrongPassword]) => {
          // Generate the combined key
          const fullKey = await generateKey();
          const { publicPart, privatePart } = splitKey(fullKey);
          const combinedKey = combineKey(publicPart, privatePart);
          
          // Generate salt and derive correct password key
          const salt = generateSalt();
          const correctPasswordKey = await deriveKey(correctPassword, salt);
          
          // Perform double encryption
          const encryptedPayload = await doubleEncrypt(secret, combinedKey, correctPasswordKey);
          
          // Clone the payload
          const payloadBefore = cloneEncryptedPayload(encryptedPayload);
          
          // Derive wrong password key
          const wrongPasswordKey = await deriveKey(wrongPassword, salt);
          
          // Attempt double decryption with wrong password - should fail
          await expect(
            doubleDecrypt(encryptedPayload, combinedKey, wrongPasswordKey)
          ).rejects.toThrow();
          
          // Verify payload unchanged
          expect(encryptedPayloadsEqual(encryptedPayload, payloadBefore)).toBe(true);
          
          // Correct password should still work
          const decrypted = await doubleDecrypt(encryptedPayload, combinedKey, correctPasswordKey);
          expect(decrypted).toBe(secret);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 3.6**
   * 
   * Property: Interleaved correct and wrong password attempts should all
   * behave correctly - wrong fails, correct succeeds.
   */
  it('interleaved correct and wrong password attempts work correctly', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        differentPasswordsArbitrary,
        async (secret, [correctPassword, wrongPassword]) => {
          // Create a password-protected secret
          const { passwordRequiredResult } = 
            await createPasswordProtectedSecret(secret, correctPassword);
          
          // Attempt sequence: wrong, correct, wrong, correct
          
          // 1. Wrong password - should fail
          await expect(
            decryptWithPassword(passwordRequiredResult, wrongPassword)
          ).rejects.toThrow(SecretViewError);
          
          // 2. Correct password - should succeed
          const result1 = await decryptWithPassword(passwordRequiredResult, correctPassword);
          expect(result1.content).toBe(secret);
          
          // 3. Wrong password again - should still fail
          await expect(
            decryptWithPassword(passwordRequiredResult, wrongPassword)
          ).rejects.toThrow(SecretViewError);
          
          // 4. Correct password again - should still succeed
          const result2 = await decryptWithPassword(passwordRequiredResult, correctPassword);
          expect(result2.content).toBe(secret);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});
