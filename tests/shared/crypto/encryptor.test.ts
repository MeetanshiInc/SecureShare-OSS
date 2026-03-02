/**
 * Unit tests for Encryptor module
 * 
 * Tests verify:
 * - Encryption produces valid EncryptedPayload structure
 * - Decryption reverses encryption correctly
 * - IV is random for each encryption
 * - Authentication tag is properly handled
 * - Error handling for invalid inputs
 * - Unicode and special character support
 */

import { describe, it, expect } from 'vitest';
import {
  encrypt,
  decrypt,
  encryptor,
  IV_SIZE_BYTES,
  TAG_SIZE_BYTES,
  KEY_SIZE_BYTES,
  type EncryptedPayload,
} from '../../../src/shared/crypto/encryptor';
import { generateKey } from '../../../src/shared/crypto/key-generator';

/**
 * Helper to decode Base64 and get byte length
 */
function base64ByteLength(base64: string): number {
  const binary = atob(base64);
  return binary.length;
}

describe('Encryptor', () => {
  describe('encrypt', () => {
    it('should return an EncryptedPayload with ciphertext, iv, and tag', async () => {
      const key = await generateKey();
      const plaintext = 'Hello, World!';
      
      const payload = await encrypt(plaintext, key);
      
      expect(payload).toHaveProperty('ciphertext');
      expect(payload).toHaveProperty('iv');
      expect(payload).toHaveProperty('tag');
      expect(typeof payload.ciphertext).toBe('string');
      expect(typeof payload.iv).toBe('string');
      expect(typeof payload.tag).toBe('string');
    });

    it('should produce a 12-byte IV', async () => {
      const key = await generateKey();
      const payload = await encrypt('test', key);
      
      expect(base64ByteLength(payload.iv)).toBe(IV_SIZE_BYTES);
    });

    it('should produce a 16-byte authentication tag', async () => {
      const key = await generateKey();
      const payload = await encrypt('test', key);
      
      expect(base64ByteLength(payload.tag)).toBe(TAG_SIZE_BYTES);
    });

    it('should generate different IVs for each encryption', async () => {
      const key = await generateKey();
      const plaintext = 'Same message';
      
      const payload1 = await encrypt(plaintext, key);
      const payload2 = await encrypt(plaintext, key);
      
      expect(payload1.iv).not.toBe(payload2.iv);
    });

    it('should produce different ciphertexts for same plaintext due to random IV', async () => {
      const key = await generateKey();
      const plaintext = 'Same message';
      
      const payload1 = await encrypt(plaintext, key);
      const payload2 = await encrypt(plaintext, key);
      
      expect(payload1.ciphertext).not.toBe(payload2.ciphertext);
    });

    it('should encrypt empty string', async () => {
      const key = await generateKey();
      const payload = await encrypt('', key);
      
      expect(payload.ciphertext).toBeDefined();
      expect(payload.iv).toBeDefined();
      expect(payload.tag).toBeDefined();
    });

    it('should encrypt unicode characters', async () => {
      const key = await generateKey();
      const plaintext = '你好世界 🌍 مرحبا';
      
      const payload = await encrypt(plaintext, key);
      
      expect(payload.ciphertext).toBeDefined();
      expect(payload.ciphertext.length).toBeGreaterThan(0);
    });

    it('should throw error for key that is too short', async () => {
      const shortKey = new Uint8Array(16);
      
      await expect(encrypt('test', shortKey)).rejects.toThrow('Key must be exactly 32 bytes');
    });

    it('should throw error for key that is too long', async () => {
      const longKey = new Uint8Array(64);
      
      await expect(encrypt('test', longKey)).rejects.toThrow('Key must be exactly 32 bytes');
    });

    it('should throw error for empty key', async () => {
      const emptyKey = new Uint8Array(0);
      
      await expect(encrypt('test', emptyKey)).rejects.toThrow('Key must be exactly 32 bytes');
    });
  });

  describe('decrypt', () => {
    it('should decrypt ciphertext back to original plaintext', async () => {
      const key = await generateKey();
      const plaintext = 'Hello, World!';
      
      const payload = await encrypt(plaintext, key);
      const decrypted = await decrypt(payload, key);
      
      expect(decrypted).toBe(plaintext);
    });

    it('should decrypt empty string', async () => {
      const key = await generateKey();
      const plaintext = '';
      
      const payload = await encrypt(plaintext, key);
      const decrypted = await decrypt(payload, key);
      
      expect(decrypted).toBe(plaintext);
    });

    it('should decrypt unicode characters', async () => {
      const key = await generateKey();
      const plaintext = '你好世界 🌍 مرحبا';
      
      const payload = await encrypt(plaintext, key);
      const decrypted = await decrypt(payload, key);
      
      expect(decrypted).toBe(plaintext);
    });

    it('should decrypt long strings', async () => {
      const key = await generateKey();
      const plaintext = 'A'.repeat(10000);
      
      const payload = await encrypt(plaintext, key);
      const decrypted = await decrypt(payload, key);
      
      expect(decrypted).toBe(plaintext);
    });

    it('should fail with wrong key', async () => {
      const key1 = await generateKey();
      const key2 = await generateKey();
      const plaintext = 'Secret message';
      
      const payload = await encrypt(plaintext, key1);
      
      await expect(decrypt(payload, key2)).rejects.toThrow('Decryption failed');
    });

    it('should fail with tampered ciphertext', async () => {
      const key = await generateKey();
      const payload = await encrypt('test', key);
      
      // Tamper with ciphertext
      const tamperedPayload: EncryptedPayload = {
        ...payload,
        ciphertext: payload.ciphertext.slice(0, -4) + 'XXXX',
      };
      
      await expect(decrypt(tamperedPayload, key)).rejects.toThrow();
    });

    it('should fail with tampered IV', async () => {
      const key = await generateKey();
      const payload = await encrypt('test', key);
      
      // Create a different IV (same length)
      const differentIv = new Uint8Array(IV_SIZE_BYTES);
      crypto.getRandomValues(differentIv);
      const tamperedPayload: EncryptedPayload = {
        ...payload,
        iv: btoa(String.fromCharCode(...differentIv)),
      };
      
      await expect(decrypt(tamperedPayload, key)).rejects.toThrow('Decryption failed');
    });

    it('should fail with tampered tag', async () => {
      const key = await generateKey();
      const payload = await encrypt('test', key);
      
      // Create a different tag (same length)
      const differentTag = new Uint8Array(TAG_SIZE_BYTES);
      crypto.getRandomValues(differentTag);
      const tamperedPayload: EncryptedPayload = {
        ...payload,
        tag: btoa(String.fromCharCode(...differentTag)),
      };
      
      await expect(decrypt(tamperedPayload, key)).rejects.toThrow('Decryption failed');
    });

    it('should throw error for key that is too short', async () => {
      const key = await generateKey();
      const payload = await encrypt('test', key);
      const shortKey = new Uint8Array(16);
      
      await expect(decrypt(payload, shortKey)).rejects.toThrow('Key must be exactly 32 bytes');
    });

    it('should throw error for key that is too long', async () => {
      const key = await generateKey();
      const payload = await encrypt('test', key);
      const longKey = new Uint8Array(64);
      
      await expect(decrypt(payload, longKey)).rejects.toThrow('Key must be exactly 32 bytes');
    });

    it('should throw error for missing ciphertext', async () => {
      const key = await generateKey();
      const invalidPayload = {
        iv: 'AAAAAAAAAAAAAAAA',
        tag: 'AAAAAAAAAAAAAAAAAAAAAA==',
      } as EncryptedPayload;
      
      await expect(decrypt(invalidPayload, key)).rejects.toThrow('Invalid payload');
    });

    it('should throw error for invalid Base64 in payload', async () => {
      const key = await generateKey();
      const invalidPayload: EncryptedPayload = {
        ciphertext: '!!!invalid-base64!!!',
        iv: 'AAAAAAAAAAAAAAAA',
        tag: 'AAAAAAAAAAAAAAAAAAAAAA==',
      };
      
      await expect(decrypt(invalidPayload, key)).rejects.toThrow('Invalid payload');
    });

    it('should throw error for wrong IV size', async () => {
      const key = await generateKey();
      const payload = await encrypt('test', key);
      
      // Create IV with wrong size
      const wrongSizeIv: EncryptedPayload = {
        ...payload,
        iv: btoa('short'), // Only 5 bytes
      };
      
      await expect(decrypt(wrongSizeIv, key)).rejects.toThrow('Invalid IV');
    });

    it('should throw error for wrong tag size', async () => {
      const key = await generateKey();
      const payload = await encrypt('test', key);
      
      // Create tag with wrong size
      const wrongSizeTag: EncryptedPayload = {
        ...payload,
        tag: btoa('short'), // Only 5 bytes
      };
      
      await expect(decrypt(wrongSizeTag, key)).rejects.toThrow('Invalid tag');
    });
  });

  describe('encryptor interface', () => {
    it('should expose encrypt and decrypt through the interface', () => {
      expect(encryptor.encrypt).toBe(encrypt);
      expect(encryptor.decrypt).toBe(decrypt);
    });

    it('should work correctly through the interface', async () => {
      const key = await generateKey();
      const plaintext = 'Test via interface';
      
      const payload = await encryptor.encrypt(plaintext, key);
      const decrypted = await encryptor.decrypt(payload, key);
      
      expect(decrypted).toBe(plaintext);
    });
  });

  describe('round-trip integrity', () => {
    it('should maintain data integrity through multiple encrypt/decrypt cycles', async () => {
      const key = await generateKey();
      const original = 'Original secret message';
      
      // First cycle
      const payload1 = await encrypt(original, key);
      const decrypted1 = await decrypt(payload1, key);
      expect(decrypted1).toBe(original);
      
      // Second cycle (re-encrypt the decrypted text)
      const payload2 = await encrypt(decrypted1, key);
      const decrypted2 = await decrypt(payload2, key);
      expect(decrypted2).toBe(original);
      
      // Third cycle
      const payload3 = await encrypt(decrypted2, key);
      const decrypted3 = await decrypt(payload3, key);
      expect(decrypted3).toBe(original);
    });

    it('should handle special characters correctly', async () => {
      const key = await generateKey();
      const specialChars = '!@#$%^&*()_+-=[]{}|;\':",./<>?\n\t\r';
      
      const payload = await encrypt(specialChars, key);
      const decrypted = await decrypt(payload, key);
      
      expect(decrypted).toBe(specialChars);
    });

    it('should handle newlines and whitespace correctly', async () => {
      const key = await generateKey();
      const multiline = `Line 1
Line 2
  Indented line
\tTabbed line`;
      
      const payload = await encrypt(multiline, key);
      const decrypted = await decrypt(payload, key);
      
      expect(decrypted).toBe(multiline);
    });
  });

  describe('constants', () => {
    it('should export correct IV size', () => {
      expect(IV_SIZE_BYTES).toBe(12);
    });

    it('should export correct tag size', () => {
      expect(TAG_SIZE_BYTES).toBe(16);
    });

    it('should export correct key size', () => {
      expect(KEY_SIZE_BYTES).toBe(32);
    });
  });
});
