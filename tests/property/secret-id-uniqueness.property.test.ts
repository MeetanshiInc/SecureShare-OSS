/**
 * Property-Based Tests for Secret ID Uniqueness
 * 
 * **Validates: Requirements 1.5**
 * 
 * Property 4: Secret ID Uniqueness
 * For any set of generated secret IDs, all IDs should be unique. No two secrets
 * should ever receive the same identifier.
 * 
 * Requirements context:
 * - 1.5: Generate a unique Secret_ID and store the data in Secret_Store
 * 
 * The SecretStore module generates 16-character alphanumeric IDs using
 * crypto.getRandomValues(). The ID space is 62^16 ≈ 4.7 × 10^28, providing
 * excellent collision resistance.
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  generateSecretId,
  isValidSecretId,
  SECRET_ID_LENGTH,
} from '../../src/worker/secret-store';

/** Characters used for secret ID generation (alphanumeric) */
const SECRET_ID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

describe('Property 4: Secret ID Uniqueness', () => {
  /**
   * **Validates: Requirements 1.5**
   * 
   * Property: For any batch of generated secret IDs, all IDs should be unique.
   * No two secrets should ever receive the same identifier.
   */
  it('all generated secret IDs should be unique within a batch', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate a batch size between 10 and 500 IDs
        fc.integer({ min: 10, max: 500 }),
        async (batchSize) => {
          const ids = new Set<string>();
          
          // Generate batchSize number of secret IDs
          for (let i = 0; i < batchSize; i++) {
            const id = generateSecretId();
            ids.add(id);
          }
          
          // All IDs should be unique - set size should equal batch size
          expect(ids.size).toBe(batchSize);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.5**
   * 
   * Property: All generated secret IDs should be valid according to the
   * validation function (16-character alphanumeric format).
   */
  it('all generated secret IDs should be valid format', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate a batch size between 1 and 100 IDs
        fc.integer({ min: 1, max: 100 }),
        async (batchSize) => {
          for (let i = 0; i < batchSize; i++) {
            const id = generateSecretId();
            
            // Each ID should pass validation
            expect(isValidSecretId(id)).toBe(true);
            
            // Each ID should be exactly SECRET_ID_LENGTH characters
            expect(id.length).toBe(SECRET_ID_LENGTH);
            
            // Each ID should contain only alphanumeric characters
            expect(/^[A-Za-z0-9]+$/.test(id)).toBe(true);
          }
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.5**
   * 
   * Property: Generated secret IDs should have good distribution of characters.
   * This validates that the random generation uses the full alphabet and doesn't
   * favor certain characters excessively.
   */
  it('generated secret IDs should have good character distribution', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Use a fixed large sample size for statistical significance
        fc.constant(1000),
        async (sampleSize) => {
          const charCounts = new Map<string, number>();
          const totalChars = sampleSize * SECRET_ID_LENGTH;
          
          // Generate many IDs and count character occurrences
          for (let i = 0; i < sampleSize; i++) {
            const id = generateSecretId();
            for (const char of id) {
              charCounts.set(char, (charCounts.get(char) || 0) + 1);
            }
          }
          
          // Should use a variety of characters from the alphabet
          // With 62 possible characters and 16000 total chars, we expect
          // to see most characters represented
          const uniqueCharsUsed = charCounts.size;
          
          // Should use at least 50 different characters (out of 62)
          // This is a reasonable threshold that accounts for randomness
          expect(uniqueCharsUsed).toBeGreaterThanOrEqual(50);
          
          // Check that no single character dominates excessively
          // Expected frequency per char: totalChars / 62 ≈ 258
          // Allow up to 3x expected frequency as upper bound
          const expectedFrequency = totalChars / SECRET_ID_ALPHABET.length;
          const maxAllowedFrequency = expectedFrequency * 3;
          
          for (const [char, count] of charCounts) {
            expect(count).toBeLessThan(maxAllowedFrequency);
          }
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.5**
   * 
   * Property: Secret IDs generated across multiple batches should all be unique.
   * This tests that uniqueness holds even when IDs are generated in separate calls.
   */
  it('secret IDs should be unique across multiple generation batches', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Number of batches
        fc.integer({ min: 2, max: 10 }),
        // Size of each batch
        fc.integer({ min: 10, max: 50 }),
        async (numBatches, batchSize) => {
          const allIds = new Set<string>();
          const totalExpected = numBatches * batchSize;
          
          // Generate IDs in multiple batches
          for (let batch = 0; batch < numBatches; batch++) {
            for (let i = 0; i < batchSize; i++) {
              const id = generateSecretId();
              allIds.add(id);
            }
          }
          
          // All IDs across all batches should be unique
          expect(allIds.size).toBe(totalExpected);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.5**
   * 
   * Property: Each character position in generated IDs should have good
   * distribution. This validates that randomness is applied uniformly
   * across all positions in the ID.
   */
  it('each position in secret ID should have good character distribution', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constant(500), // Sample size for statistical significance
        async (sampleSize) => {
          // Track character counts per position
          const positionCounts: Map<string, number>[] = [];
          for (let pos = 0; pos < SECRET_ID_LENGTH; pos++) {
            positionCounts.push(new Map<string, number>());
          }
          
          // Generate IDs and count characters at each position
          for (let i = 0; i < sampleSize; i++) {
            const id = generateSecretId();
            for (let pos = 0; pos < SECRET_ID_LENGTH; pos++) {
              const char = id[pos]!;
              const counts = positionCounts[pos]!;
              counts.set(char, (counts.get(char) || 0) + 1);
            }
          }
          
          // Each position should use a variety of characters
          // With 500 samples and 62 possible chars, we expect good coverage
          for (let pos = 0; pos < SECRET_ID_LENGTH; pos++) {
            const uniqueCharsAtPosition = positionCounts[pos]!.size;
            
            // Each position should use at least 40 different characters
            expect(uniqueCharsAtPosition).toBeGreaterThanOrEqual(40);
          }
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});
