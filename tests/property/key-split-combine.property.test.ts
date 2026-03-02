/**
 * Property-Based Tests for Key Split/Combine Integrity
 * 
 * **Validates: Requirements 1.2, 9.2, 9.5, 9.6**
 * 
 * Property 2: Key Split/Combine Integrity
 * For any 256-bit key, splitting into two 128-bit parts and then combining them
 * in the same order should produce the original key. Additionally, combining in
 * the wrong order should produce a different key that fails decryption.
 * 
 * Requirements context:
 * - 1.2: Split key into Public_Key_Part and Private_Key_Part
 * - 9.2: Split the key into two 128-bit parts
 * - 9.5: Combined_Key derived by concatenating Public_Key_Part and Private_Key_Part
 * - 9.6: When reconstructing the key, combine both parts in the correct order before decryption
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  splitKey,
  combineKey,
  KEY_SIZE_BYTES,
  KEY_PART_SIZE_BYTES,
} from '../../src/shared/crypto/key-generator';

/**
 * Arbitrary generator for 256-bit keys (32 bytes)
 * Generates random Uint8Array of exactly 32 bytes
 */
const key256BitArbitrary = fc.uint8Array({
  minLength: KEY_SIZE_BYTES,
  maxLength: KEY_SIZE_BYTES,
});

describe('Property 2: Key Split/Combine Integrity', () => {
  /**
   * **Validates: Requirements 1.2, 9.2, 9.5, 9.6**
   * 
   * Property: For any 256-bit key, splitting into two 128-bit parts and then
   * combining them in the same order should produce the original key.
   */
  it('split then combine should return the original key', () => {
    fc.assert(
      fc.property(key256BitArbitrary, (originalKey) => {
        // Split the key into public and private parts
        const { publicPart, privatePart } = splitKey(originalKey);
        
        // Verify each part is exactly 128 bits (16 bytes)
        expect(publicPart.length).toBe(KEY_PART_SIZE_BYTES);
        expect(privatePart.length).toBe(KEY_PART_SIZE_BYTES);
        
        // Combine the parts back together
        const reconstructedKey = combineKey(publicPart, privatePart);
        
        // The reconstructed key should be identical to the original
        expect(reconstructedKey).toEqual(originalKey);
        expect(reconstructedKey.length).toBe(KEY_SIZE_BYTES);
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.2, 9.2, 9.5, 9.6**
   * 
   * Property: Combining key parts in the wrong order (swapped) should produce
   * a different key than the original. This ensures order matters for security.
   */
  it('combining parts in wrong order should produce a different key', () => {
    fc.assert(
      fc.property(key256BitArbitrary, (originalKey) => {
        const { publicPart, privatePart } = splitKey(originalKey);
        
        // Combine in correct order
        const correctKey = combineKey(publicPart, privatePart);
        
        // Combine in wrong order (swapped)
        const swappedKey = combineKey(privatePart, publicPart);
        
        // Check if the parts are different (they could theoretically be identical
        // if the key happens to be symmetric, but this is extremely unlikely)
        const partsAreDifferent = !arraysEqual(publicPart, privatePart);
        
        if (partsAreDifferent) {
          // If parts are different, swapped key must be different from correct key
          expect(swappedKey).not.toEqual(correctKey);
          expect(swappedKey).not.toEqual(originalKey);
        }
        // If parts happen to be identical (extremely rare), swapped would equal correct
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 9.2**
   * 
   * Property: Split key parts should each be exactly 128 bits (16 bytes),
   * and together they should contain all the original key's bytes.
   */
  it('split parts should be exactly 128 bits each and preserve all bytes', () => {
    fc.assert(
      fc.property(key256BitArbitrary, (originalKey) => {
        const { publicPart, privatePart } = splitKey(originalKey);
        
        // Each part should be exactly 128 bits
        expect(publicPart.length).toBe(16);
        expect(privatePart.length).toBe(16);
        
        // Public part should be first half of original key
        for (let i = 0; i < 16; i++) {
          expect(publicPart[i]).toBe(originalKey[i]);
        }
        
        // Private part should be second half of original key
        for (let i = 0; i < 16; i++) {
          expect(privatePart[i]).toBe(originalKey[i + 16]);
        }
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 9.5, 9.6**
   * 
   * Property: Multiple split/combine cycles should always return the original key.
   * This ensures the operations are stable and idempotent.
   */
  it('multiple split/combine cycles should maintain key integrity', () => {
    fc.assert(
      fc.property(key256BitArbitrary, (originalKey) => {
        let currentKey = originalKey;
        
        // Perform multiple cycles
        for (let cycle = 0; cycle < 3; cycle++) {
          const { publicPart, privatePart } = splitKey(currentKey);
          currentKey = combineKey(publicPart, privatePart);
          
          // After each cycle, key should still equal original
          expect(currentKey).toEqual(originalKey);
        }
        
        return true;
      }),
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
