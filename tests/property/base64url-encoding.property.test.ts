/**
 * Property-Based Tests for Base64url Encoding Validity
 * 
 * **Validates: Requirements 9.3**
 * 
 * Property 12: Base64url Encoding Validity
 * For any public key part encoded for the URL fragment, the encoding should be
 * valid base64url (URL-safe base64 without padding). Decoding should return the
 * original bytes.
 * 
 * Requirements context:
 * - 9.3: The Public_Key_Part SHALL be encoded in the URL_Fragment using base64url encoding
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  toBase64url,
  fromBase64url,
  isValidBase64url,
} from '../../src/shared/encoding';

/**
 * Valid Base64url character set: A-Z, a-z, 0-9, -, _
 * No padding characters (=) allowed
 */
const BASE64URL_REGEX = /^[A-Za-z0-9_-]*$/;

/**
 * Arbitrary generator for random byte arrays of various sizes
 * Includes empty arrays, small arrays, and larger arrays
 */
const byteArrayArbitrary = fc.oneof(
  // Empty array
  fc.constant(new Uint8Array(0)),
  // Small arrays (1-10 bytes)
  fc.uint8Array({ minLength: 1, maxLength: 10 }),
  // Medium arrays (11-100 bytes)
  fc.uint8Array({ minLength: 11, maxLength: 100 }),
  // 128-bit key parts (16 bytes) - the specific use case for URL fragments
  fc.uint8Array({ minLength: 16, maxLength: 16 }),
  // Larger arrays (101-500 bytes)
  fc.uint8Array({ minLength: 101, maxLength: 500 })
);

/**
 * Arbitrary generator specifically for 128-bit key parts (16 bytes)
 * This is the primary use case for URL fragment encoding
 */
const keyPartArbitrary = fc.uint8Array({
  minLength: 16,
  maxLength: 16,
});

describe('Property 12: Base64url Encoding Validity', () => {
  /**
   * **Validates: Requirements 9.3**
   * 
   * Property: For any byte array, encoding to Base64url and then decoding
   * should return the original bytes unchanged.
   */
  it('encode then decode should return original bytes', () => {
    fc.assert(
      fc.property(byteArrayArbitrary, (originalBytes) => {
        // Encode the bytes to Base64url
        const encoded = toBase64url(originalBytes);
        
        // Decode back to bytes
        const decoded = fromBase64url(encoded);
        
        // The decoded bytes should match the original exactly
        expect(decoded).toEqual(originalBytes);
        expect(decoded.length).toBe(originalBytes.length);
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 9.3**
   * 
   * Property: For any byte array, the encoded output should contain only
   * valid Base64url characters (A-Z, a-z, 0-9, -, _).
   */
  it('encoded output should contain only valid Base64url characters', () => {
    fc.assert(
      fc.property(byteArrayArbitrary, (bytes) => {
        const encoded = toBase64url(bytes);
        
        // Should match the Base64url character set
        expect(encoded).toMatch(BASE64URL_REGEX);
        
        // Verify each character individually
        for (const char of encoded) {
          const isValidChar = 
            (char >= 'A' && char <= 'Z') ||
            (char >= 'a' && char <= 'z') ||
            (char >= '0' && char <= '9') ||
            char === '-' ||
            char === '_';
          expect(isValidChar).toBe(true);
        }
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 9.3**
   * 
   * Property: For any byte array, the encoded output should not contain
   * padding characters (=).
   */
  it('encoded output should not contain padding characters', () => {
    fc.assert(
      fc.property(byteArrayArbitrary, (bytes) => {
        const encoded = toBase64url(bytes);
        
        // Should not contain padding characters
        expect(encoded).not.toContain('=');
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 9.3**
   * 
   * Property: For any byte array, the encoded output should be URL-safe
   * (no encoding needed when used in URL fragments).
   */
  it('encoded output should be URL-safe (no encoding needed)', () => {
    fc.assert(
      fc.property(byteArrayArbitrary, (bytes) => {
        const encoded = toBase64url(bytes);
        
        // URL encoding should not change the string
        // (i.e., it's already URL-safe)
        expect(encodeURIComponent(encoded)).toBe(encoded);
        
        // Should not contain standard Base64 characters that need URL encoding
        expect(encoded).not.toContain('+');
        expect(encoded).not.toContain('/');
        expect(encoded).not.toContain('=');
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 9.3**
   * 
   * Property: For any byte array, the encoded string should pass the
   * isValidBase64url validation function.
   */
  it('encoded output should pass isValidBase64url validation', () => {
    fc.assert(
      fc.property(byteArrayArbitrary, (bytes) => {
        const encoded = toBase64url(bytes);
        
        // Should be recognized as valid Base64url
        expect(isValidBase64url(encoded)).toBe(true);
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 9.3**
   * 
   * Property: Specifically for 128-bit key parts (16 bytes), encoding should
   * produce exactly 22 characters and round-trip correctly.
   */
  it('128-bit key parts should encode to 22 characters and round-trip correctly', () => {
    fc.assert(
      fc.property(keyPartArbitrary, (keyPart) => {
        const encoded = toBase64url(keyPart);
        
        // 16 bytes should encode to exactly 22 Base64url characters
        // (16 * 8 bits / 6 bits per char = 21.33, rounded up = 22)
        expect(encoded.length).toBe(22);
        
        // Should be valid Base64url
        expect(encoded).toMatch(BASE64URL_REGEX);
        expect(encoded).not.toContain('=');
        
        // Should round-trip correctly
        const decoded = fromBase64url(encoded);
        expect(decoded).toEqual(keyPart);
        expect(decoded.length).toBe(16);
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 9.3**
   * 
   * Property: The encoded string should be usable directly in URL fragments
   * without any additional encoding or escaping.
   */
  it('encoded output should be usable directly in URL fragments', () => {
    fc.assert(
      fc.property(keyPartArbitrary, (keyPart) => {
        const encoded = toBase64url(keyPart);
        
        // Construct a URL with the encoded key in the fragment
        const url = `https://example.com/s/abc123#${encoded}`;
        
        // Parse the URL and extract the fragment
        const parsedUrl = new URL(url);
        const fragment = parsedUrl.hash.slice(1); // Remove the '#'
        
        // Fragment should match the encoded value exactly
        expect(fragment).toBe(encoded);
        
        // Should be able to decode it back to original bytes
        const decoded = fromBase64url(fragment);
        expect(decoded).toEqual(keyPart);
        
        return true;
      }),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 9.3**
   * 
   * Property: Multiple encode/decode cycles should maintain data integrity.
   */
  it('multiple encode/decode cycles should maintain data integrity', () => {
    fc.assert(
      fc.property(byteArrayArbitrary, (originalBytes) => {
        let currentBytes = originalBytes;
        let previousEncoded = '';
        
        // Perform multiple cycles
        for (let cycle = 0; cycle < 3; cycle++) {
          const encoded = toBase64url(currentBytes);
          currentBytes = fromBase64url(encoded);
          
          // After each cycle, bytes should still equal original
          expect(currentBytes).toEqual(originalBytes);
          
          // Encoding should be deterministic (same input = same output)
          if (cycle > 0) {
            expect(encoded).toBe(previousEncoded);
          }
          previousEncoded = encoded;
        }
        
        return true;
      }),
      { numRuns: 100 }
    );
  });
});
