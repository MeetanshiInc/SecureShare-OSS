/**
 * Unit tests for KeyGenerator module
 * 
 * Tests verify:
 * - Key generation produces correct length keys
 * - Keys are different on each generation (randomness)
 * - Key splitting produces correct part sizes
 * - Key combining reconstructs the original key
 * - Error handling for invalid inputs
 */

import { describe, it, expect } from 'vitest';
import {
  generateKey,
  splitKey,
  combineKey,
  KEY_SIZE_BYTES,
  KEY_PART_SIZE_BYTES,
  keyGenerator,
} from '../../../src/shared/crypto/key-generator';

describe('KeyGenerator', () => {
  describe('generateKey', () => {
    it('should generate a key of exactly 256 bits (32 bytes)', async () => {
      const key = await generateKey();
      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(KEY_SIZE_BYTES);
      expect(key.length).toBe(32);
    });

    it('should generate different keys on each call', async () => {
      const key1 = await generateKey();
      const key2 = await generateKey();
      
      // Keys should not be identical (extremely unlikely with 256 bits of randomness)
      expect(key1).not.toEqual(key2);
    });

    it('should generate keys with non-zero bytes', async () => {
      // Generate multiple keys and check they're not all zeros
      const keys = await Promise.all([
        generateKey(),
        generateKey(),
        generateKey(),
      ]);
      
      for (const key of keys) {
        // At least some bytes should be non-zero
        const hasNonZero = key.some(byte => byte !== 0);
        expect(hasNonZero).toBe(true);
      }
    });
  });

  describe('splitKey', () => {
    it('should split a 256-bit key into two 128-bit parts', async () => {
      const key = await generateKey();
      const { publicPart, privatePart } = splitKey(key);
      
      expect(publicPart).toBeInstanceOf(Uint8Array);
      expect(privatePart).toBeInstanceOf(Uint8Array);
      expect(publicPart.length).toBe(KEY_PART_SIZE_BYTES);
      expect(privatePart.length).toBe(KEY_PART_SIZE_BYTES);
      expect(publicPart.length).toBe(16);
      expect(privatePart.length).toBe(16);
    });

    it('should split key into first and second halves', () => {
      // Create a known key for testing
      const key = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        key[i] = i;
      }
      
      const { publicPart, privatePart } = splitKey(key);
      
      // Public part should be bytes 0-15
      for (let i = 0; i < 16; i++) {
        expect(publicPart[i]).toBe(i);
      }
      
      // Private part should be bytes 16-31
      for (let i = 0; i < 16; i++) {
        expect(privatePart[i]).toBe(i + 16);
      }
    });

    it('should throw error for key that is too short', () => {
      const shortKey = new Uint8Array(16);
      expect(() => splitKey(shortKey)).toThrow('Key must be exactly 32 bytes');
    });

    it('should throw error for key that is too long', () => {
      const longKey = new Uint8Array(64);
      expect(() => splitKey(longKey)).toThrow('Key must be exactly 32 bytes');
    });

    it('should throw error for empty key', () => {
      const emptyKey = new Uint8Array(0);
      expect(() => splitKey(emptyKey)).toThrow('Key must be exactly 32 bytes');
    });
  });

  describe('combineKey', () => {
    it('should combine two 128-bit parts into a 256-bit key', async () => {
      const key = await generateKey();
      const { publicPart, privatePart } = splitKey(key);
      const combined = combineKey(publicPart, privatePart);
      
      expect(combined).toBeInstanceOf(Uint8Array);
      expect(combined.length).toBe(KEY_SIZE_BYTES);
      expect(combined.length).toBe(32);
    });

    it('should reconstruct the original key from split parts', async () => {
      const originalKey = await generateKey();
      const { publicPart, privatePart } = splitKey(originalKey);
      const reconstructedKey = combineKey(publicPart, privatePart);
      
      expect(reconstructedKey).toEqual(originalKey);
    });

    it('should combine parts in correct order', () => {
      // Create known parts
      const publicPart = new Uint8Array(16);
      const privatePart = new Uint8Array(16);
      
      for (let i = 0; i < 16; i++) {
        publicPart[i] = i;
        privatePart[i] = i + 16;
      }
      
      const combined = combineKey(publicPart, privatePart);
      
      // Combined should be 0-31 in order
      for (let i = 0; i < 32; i++) {
        expect(combined[i]).toBe(i);
      }
    });

    it('should produce different key when parts are swapped', async () => {
      const key = await generateKey();
      const { publicPart, privatePart } = splitKey(key);
      
      const correctCombined = combineKey(publicPart, privatePart);
      const swappedCombined = combineKey(privatePart, publicPart);
      
      // Swapped combination should be different (unless parts happen to be identical, which is extremely unlikely)
      expect(swappedCombined).not.toEqual(correctCombined);
    });

    it('should throw error for public part that is too short', () => {
      const shortPublic = new Uint8Array(8);
      const validPrivate = new Uint8Array(16);
      
      expect(() => combineKey(shortPublic, validPrivate)).toThrow('Public key part must be exactly 16 bytes');
    });

    it('should throw error for private part that is too short', () => {
      const validPublic = new Uint8Array(16);
      const shortPrivate = new Uint8Array(8);
      
      expect(() => combineKey(validPublic, shortPrivate)).toThrow('Private key part must be exactly 16 bytes');
    });

    it('should throw error for public part that is too long', () => {
      const longPublic = new Uint8Array(32);
      const validPrivate = new Uint8Array(16);
      
      expect(() => combineKey(longPublic, validPrivate)).toThrow('Public key part must be exactly 16 bytes');
    });

    it('should throw error for private part that is too long', () => {
      const validPublic = new Uint8Array(16);
      const longPrivate = new Uint8Array(32);
      
      expect(() => combineKey(validPublic, longPrivate)).toThrow('Private key part must be exactly 16 bytes');
    });
  });

  describe('keyGenerator interface', () => {
    it('should expose all functions through the interface', () => {
      expect(keyGenerator.generateKey).toBe(generateKey);
      expect(keyGenerator.splitKey).toBe(splitKey);
      expect(keyGenerator.combineKey).toBe(combineKey);
    });

    it('should work correctly through the interface', async () => {
      const key = await keyGenerator.generateKey();
      expect(key.length).toBe(32);
      
      const { publicPart, privatePart } = keyGenerator.splitKey(key);
      expect(publicPart.length).toBe(16);
      expect(privatePart.length).toBe(16);
      
      const combined = keyGenerator.combineKey(publicPart, privatePart);
      expect(combined).toEqual(key);
    });
  });

  describe('round-trip integrity', () => {
    it('should maintain key integrity through multiple split/combine cycles', async () => {
      const originalKey = await generateKey();
      
      // First cycle
      const split1 = splitKey(originalKey);
      const combined1 = combineKey(split1.publicPart, split1.privatePart);
      expect(combined1).toEqual(originalKey);
      
      // Second cycle
      const split2 = splitKey(combined1);
      const combined2 = combineKey(split2.publicPart, split2.privatePart);
      expect(combined2).toEqual(originalKey);
      
      // Third cycle
      const split3 = splitKey(combined2);
      const combined3 = combineKey(split3.publicPart, split3.privatePart);
      expect(combined3).toEqual(originalKey);
    });
  });
});
