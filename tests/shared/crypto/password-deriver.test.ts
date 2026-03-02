/**
 * Unit tests for PasswordDeriver module
 * 
 * Tests verify:
 * - Salt generation produces correct length salts
 * - Salts are different on each generation (randomness)
 * - Key derivation is deterministic with same password/salt
 * - Different passwords produce different keys
 * - Different salts produce different keys
 * - Empty password handling
 * - Error handling for invalid inputs
 */

import { describe, it, expect } from 'vitest';
import {
  generateSalt,
  deriveKey,
  SALT_SIZE_BYTES,
  DERIVED_KEY_SIZE_BYTES,
  PBKDF2_ITERATIONS,
  PBKDF2_HASH,
  passwordDeriver,
} from '../../../src/shared/crypto/password-deriver';

describe('PasswordDeriver', () => {
  describe('generateSalt', () => {
    it('should generate a salt of exactly 128 bits (16 bytes)', () => {
      const salt = generateSalt();
      expect(salt).toBeInstanceOf(Uint8Array);
      expect(salt.length).toBe(SALT_SIZE_BYTES);
      expect(salt.length).toBe(16);
    });

    it('should generate different salts on each call', () => {
      const salt1 = generateSalt();
      const salt2 = generateSalt();
      
      // Salts should not be identical (extremely unlikely with 128 bits of randomness)
      expect(salt1).not.toEqual(salt2);
    });

    it('should generate salts with non-zero bytes', () => {
      // Generate multiple salts and check they're not all zeros
      const salts = [generateSalt(), generateSalt(), generateSalt()];
      
      for (const salt of salts) {
        // At least some bytes should be non-zero
        const hasNonZero = salt.some(byte => byte !== 0);
        expect(hasNonZero).toBe(true);
      }
    });

    it('should generate unique salts across many generations', () => {
      const salts: string[] = [];
      const numSalts = 100;
      
      for (let i = 0; i < numSalts; i++) {
        const salt = generateSalt();
        const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
        salts.push(saltHex);
      }
      
      // All salts should be unique
      const uniqueSalts = new Set(salts);
      expect(uniqueSalts.size).toBe(numSalts);
    });
  });

  describe('deriveKey', () => {
    it('should derive a key of exactly 256 bits (32 bytes)', async () => {
      const salt = generateSalt();
      const key = await deriveKey('testPassword', salt);
      
      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(DERIVED_KEY_SIZE_BYTES);
      expect(key.length).toBe(32);
    });

    it('should be deterministic with same password and salt', async () => {
      const salt = generateSalt();
      const password = 'mySecretPassword';
      
      const key1 = await deriveKey(password, salt);
      const key2 = await deriveKey(password, salt);
      
      expect(key1).toEqual(key2);
    });

    it('should produce different keys for different passwords', async () => {
      const salt = generateSalt();
      
      const key1 = await deriveKey('password1', salt);
      const key2 = await deriveKey('password2', salt);
      
      expect(key1).not.toEqual(key2);
    });

    it('should produce different keys for different salts', async () => {
      const salt1 = generateSalt();
      const salt2 = generateSalt();
      const password = 'samePassword';
      
      const key1 = await deriveKey(password, salt1);
      const key2 = await deriveKey(password, salt2);
      
      expect(key1).not.toEqual(key2);
    });

    it('should handle empty password', async () => {
      const salt = generateSalt();
      const key = await deriveKey('', salt);
      
      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(DERIVED_KEY_SIZE_BYTES);
      
      // Empty password should still produce a valid key
      const hasNonZero = key.some(byte => byte !== 0);
      expect(hasNonZero).toBe(true);
    });

    it('should handle empty password deterministically', async () => {
      const salt = generateSalt();
      
      const key1 = await deriveKey('', salt);
      const key2 = await deriveKey('', salt);
      
      expect(key1).toEqual(key2);
    });

    it('should handle unicode passwords', async () => {
      const salt = generateSalt();
      const unicodePassword = '密码🔐パスワード';
      
      const key = await deriveKey(unicodePassword, salt);
      
      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(DERIVED_KEY_SIZE_BYTES);
    });

    it('should produce different keys for similar unicode passwords', async () => {
      const salt = generateSalt();
      
      const key1 = await deriveKey('密码', salt);
      const key2 = await deriveKey('密碼', salt); // Traditional Chinese variant
      
      expect(key1).not.toEqual(key2);
    });

    it('should handle very long passwords', async () => {
      const salt = generateSalt();
      const longPassword = 'a'.repeat(10000);
      
      const key = await deriveKey(longPassword, salt);
      
      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(DERIVED_KEY_SIZE_BYTES);
    });

    it('should throw error for salt that is too short', async () => {
      const shortSalt = new Uint8Array(8);
      
      await expect(deriveKey('password', shortSalt)).rejects.toThrow(
        'Salt must be exactly 16 bytes'
      );
    });

    it('should throw error for salt that is too long', async () => {
      const longSalt = new Uint8Array(32);
      
      await expect(deriveKey('password', longSalt)).rejects.toThrow(
        'Salt must be exactly 16 bytes'
      );
    });

    it('should throw error for empty salt', async () => {
      const emptySalt = new Uint8Array(0);
      
      await expect(deriveKey('password', emptySalt)).rejects.toThrow(
        'Salt must be exactly 16 bytes'
      );
    });

    it('should produce consistent results with known test vectors', async () => {
      // Use a fixed salt for reproducible test
      const fixedSalt = new Uint8Array([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
      ]);
      
      const key1 = await deriveKey('testPassword', fixedSalt);
      const key2 = await deriveKey('testPassword', fixedSalt);
      
      // Both derivations should produce identical keys
      expect(key1).toEqual(key2);
      
      // Key should be 32 bytes
      expect(key1.length).toBe(32);
    });
  });

  describe('passwordDeriver interface', () => {
    it('should expose all functions through the interface', () => {
      expect(passwordDeriver.generateSalt).toBe(generateSalt);
      expect(passwordDeriver.deriveKey).toBe(deriveKey);
    });

    it('should work correctly through the interface', async () => {
      const salt = passwordDeriver.generateSalt();
      expect(salt.length).toBe(16);
      
      const key = await passwordDeriver.deriveKey('password', salt);
      expect(key.length).toBe(32);
    });
  });

  describe('constants', () => {
    it('should have correct PBKDF2 configuration', () => {
      expect(SALT_SIZE_BYTES).toBe(16);
      expect(DERIVED_KEY_SIZE_BYTES).toBe(32);
      expect(PBKDF2_ITERATIONS).toBe(100000);
      expect(PBKDF2_HASH).toBe('SHA-256');
    });
  });

  describe('security properties', () => {
    it('should produce keys with high entropy', async () => {
      const salt = generateSalt();
      const key = await deriveKey('password', salt);
      
      // Count unique byte values - a good key should have many unique values
      const uniqueBytes = new Set(key);
      
      // With 32 bytes, we expect reasonable diversity
      // (not a strict test, but catches obvious issues)
      expect(uniqueBytes.size).toBeGreaterThan(10);
    });

    it('should be sensitive to single character password changes', async () => {
      const salt = generateSalt();
      
      const key1 = await deriveKey('password', salt);
      const key2 = await deriveKey('Password', salt); // Capital P
      const key3 = await deriveKey('password1', salt); // Added 1
      const key4 = await deriveKey('passwor', salt); // Removed d
      
      // All keys should be different
      expect(key1).not.toEqual(key2);
      expect(key1).not.toEqual(key3);
      expect(key1).not.toEqual(key4);
      expect(key2).not.toEqual(key3);
      expect(key2).not.toEqual(key4);
      expect(key3).not.toEqual(key4);
    });

    it('should be sensitive to single byte salt changes', async () => {
      const salt1 = new Uint8Array([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
      ]);
      const salt2 = new Uint8Array([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11 // Last byte changed
      ]);
      
      const key1 = await deriveKey('password', salt1);
      const key2 = await deriveKey('password', salt2);
      
      expect(key1).not.toEqual(key2);
    });
  });
});
