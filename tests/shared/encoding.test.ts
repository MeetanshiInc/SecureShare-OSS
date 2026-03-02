/**
 * Unit tests for Base64url encoding utilities
 * 
 * Tests verify:
 * - Encoding produces valid Base64url strings (URL-safe, no padding)
 * - Decoding reverses encoding correctly
 * - Round-trip integrity for various inputs
 * - Error handling for invalid inputs
 * - Compatibility with standard Base64 inputs
 * 
 * Requirements:
 * - 9.3: The Public_Key_Part SHALL be encoded in the URL_Fragment using base64url encoding
 */

import { describe, it, expect } from 'vitest';
import {
  toBase64url,
  fromBase64url,
  isValidBase64url,
  encoding,
} from '../../src/shared/encoding';

describe('Base64url Encoding', () => {
  describe('toBase64url', () => {
    it('should encode a simple byte array', () => {
      // "Hello" in ASCII
      const bytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
      const encoded = toBase64url(bytes);
      
      expect(encoded).toBe('SGVsbG8');
    });

    it('should encode an empty byte array', () => {
      const bytes = new Uint8Array(0);
      const encoded = toBase64url(bytes);
      
      expect(encoded).toBe('');
    });

    it('should produce URL-safe output (no + or /)', () => {
      // Bytes that would produce '+' and '/' in standard Base64
      // 0xFB, 0xEF, 0xBE = standard Base64 "++--" contains + and /
      const bytes = new Uint8Array([0xfb, 0xef, 0xbe]);
      const encoded = toBase64url(bytes);
      
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
    });

    it('should not include padding characters', () => {
      // 1 byte would normally have 2 padding chars in Base64
      const bytes1 = new Uint8Array([0x41]);
      expect(toBase64url(bytes1)).not.toContain('=');
      
      // 2 bytes would normally have 1 padding char in Base64
      const bytes2 = new Uint8Array([0x41, 0x42]);
      expect(toBase64url(bytes2)).not.toContain('=');
      
      // 3 bytes would have no padding in Base64
      const bytes3 = new Uint8Array([0x41, 0x42, 0x43]);
      expect(toBase64url(bytes3)).not.toContain('=');
    });

    it('should encode 128-bit key part (16 bytes) to 22 characters', () => {
      // A 128-bit key part should encode to 22 Base64url characters
      // (16 bytes * 8 bits / 6 bits per char = 21.33, rounded up = 22)
      const keyPart = new Uint8Array(16);
      crypto.getRandomValues(keyPart);
      
      const encoded = toBase64url(keyPart);
      expect(encoded.length).toBe(22);
    });

    it('should encode all-zeros byte array', () => {
      const bytes = new Uint8Array([0, 0, 0, 0]);
      const encoded = toBase64url(bytes);
      
      expect(encoded).toBe('AAAAAA');
    });

    it('should encode all-ones byte array (0xFF)', () => {
      const bytes = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
      const encoded = toBase64url(bytes);
      
      expect(encoded).toBe('_____w');
    });

    it('should throw error for non-Uint8Array input', () => {
      expect(() => toBase64url('string' as unknown as Uint8Array)).toThrow('Input must be a Uint8Array');
      expect(() => toBase64url([1, 2, 3] as unknown as Uint8Array)).toThrow('Input must be a Uint8Array');
      expect(() => toBase64url(null as unknown as Uint8Array)).toThrow('Input must be a Uint8Array');
      expect(() => toBase64url(undefined as unknown as Uint8Array)).toThrow('Input must be a Uint8Array');
    });

    it('should handle large byte arrays', () => {
      const bytes = new Uint8Array(1000);
      crypto.getRandomValues(bytes);
      
      const encoded = toBase64url(bytes);
      
      // Should be URL-safe
      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
      // Should have expected length (1000 * 4/3 rounded up, no padding)
      expect(encoded.length).toBe(Math.ceil(1000 * 4 / 3));
    });
  });

  describe('fromBase64url', () => {
    it('should decode a simple Base64url string', () => {
      const decoded = fromBase64url('SGVsbG8');
      
      // "Hello" in ASCII
      expect(decoded).toEqual(new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]));
    });

    it('should decode an empty string', () => {
      const decoded = fromBase64url('');
      
      expect(decoded).toEqual(new Uint8Array(0));
    });

    it('should decode strings with URL-safe characters (- and _)', () => {
      // Decode string that uses - and _ (URL-safe replacements)
      const decoded = fromBase64url('--__');
      
      expect(decoded).toBeInstanceOf(Uint8Array);
      expect(decoded.length).toBe(3);
    });

    it('should handle missing padding', () => {
      // 1 byte encoded (would have 2 padding chars)
      const decoded1 = fromBase64url('QQ');
      expect(decoded1).toEqual(new Uint8Array([0x41]));
      
      // 2 bytes encoded (would have 1 padding char)
      const decoded2 = fromBase64url('QUI');
      expect(decoded2).toEqual(new Uint8Array([0x41, 0x42]));
    });

    it('should also accept standard Base64 with padding', () => {
      // Should work with padding included
      const decoded = fromBase64url('QQ==');
      expect(decoded).toEqual(new Uint8Array([0x41]));
    });

    it('should decode 22-character string to 16 bytes (128-bit key part)', () => {
      // A 22-character Base64url string decodes to 16 bytes
      const encoded = 'AAAAAAAAAAAAAAAAAAAAAA';
      const decoded = fromBase64url(encoded);
      
      expect(decoded.length).toBe(16);
    });

    it('should throw error for invalid Base64url characters', () => {
      expect(() => fromBase64url('Hello!')).toThrow('Invalid Base64url encoding');
      expect(() => fromBase64url('Hello World')).toThrow('Invalid Base64url encoding');
      expect(() => fromBase64url('Test@123')).toThrow('Invalid Base64url encoding');
    });

    it('should throw error for non-string input', () => {
      expect(() => fromBase64url(123 as unknown as string)).toThrow('Input must be a string');
      expect(() => fromBase64url(null as unknown as string)).toThrow('Input must be a string');
      expect(() => fromBase64url(undefined as unknown as string)).toThrow('Input must be a string');
    });

    it('should decode all-zeros encoding', () => {
      const decoded = fromBase64url('AAAAAA');
      expect(decoded).toEqual(new Uint8Array([0, 0, 0, 0]));
    });

    it('should decode all-ones encoding', () => {
      const decoded = fromBase64url('_____w');
      expect(decoded).toEqual(new Uint8Array([0xff, 0xff, 0xff, 0xff]));
    });
  });

  describe('isValidBase64url', () => {
    it('should return true for valid Base64url strings', () => {
      expect(isValidBase64url('SGVsbG8')).toBe(true);
      expect(isValidBase64url('AAAAAAAAAAAAAAAAAAAAAA')).toBe(true);
      expect(isValidBase64url('')).toBe(true);
      // Note: Not all strings with Base64url characters are valid encodings
      // The string must decode to valid bytes (proper length for Base64)
      expect(isValidBase64url('YWJj')).toBe(true); // "abc" encoded
      expect(isValidBase64url('dGVzdA')).toBe(true); // "test" encoded
    });

    it('should return false for strings with invalid characters', () => {
      expect(isValidBase64url('Hello!')).toBe(false);
      expect(isValidBase64url('Hello World')).toBe(false);
      expect(isValidBase64url('Test@123')).toBe(false);
      expect(isValidBase64url('abc+def')).toBe(false);
      expect(isValidBase64url('abc/def')).toBe(false);
      expect(isValidBase64url('abc=def')).toBe(false);
    });

    it('should return false for non-string inputs', () => {
      expect(isValidBase64url(123 as unknown as string)).toBe(false);
      expect(isValidBase64url(null as unknown as string)).toBe(false);
      expect(isValidBase64url(undefined as unknown as string)).toBe(false);
      expect(isValidBase64url({} as unknown as string)).toBe(false);
    });

    it('should return true for URL-safe characters', () => {
      expect(isValidBase64url('--__')).toBe(true);
      expect(isValidBase64url('_____w')).toBe(true);
    });
  });

  describe('round-trip integrity', () => {
    it('should maintain integrity for random byte arrays', () => {
      for (let i = 0; i < 10; i++) {
        const original = new Uint8Array(32);
        crypto.getRandomValues(original);
        
        const encoded = toBase64url(original);
        const decoded = fromBase64url(encoded);
        
        expect(decoded).toEqual(original);
      }
    });

    it('should maintain integrity for various sizes', () => {
      const sizes = [0, 1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 100, 256];
      
      for (const size of sizes) {
        const original = new Uint8Array(size);
        crypto.getRandomValues(original);
        
        const encoded = toBase64url(original);
        const decoded = fromBase64url(encoded);
        
        expect(decoded).toEqual(original);
      }
    });

    it('should maintain integrity for 128-bit key parts', () => {
      // This is the specific use case for URL fragments
      const keyPart = new Uint8Array(16);
      crypto.getRandomValues(keyPart);
      
      const encoded = toBase64url(keyPart);
      const decoded = fromBase64url(encoded);
      
      expect(decoded).toEqual(keyPart);
      expect(encoded.length).toBe(22); // 16 bytes = 22 Base64url chars
    });

    it('should maintain integrity through multiple encode/decode cycles', () => {
      const original = new Uint8Array(16);
      crypto.getRandomValues(original);
      
      // First cycle
      const encoded1 = toBase64url(original);
      const decoded1 = fromBase64url(encoded1);
      expect(decoded1).toEqual(original);
      
      // Second cycle
      const encoded2 = toBase64url(decoded1);
      const decoded2 = fromBase64url(encoded2);
      expect(decoded2).toEqual(original);
      
      // Encodings should be identical
      expect(encoded1).toBe(encoded2);
    });

    it('should handle edge case byte values', () => {
      // Test with bytes that produce special Base64 characters
      const edgeCases = [
        new Uint8Array([0x00]),
        new Uint8Array([0xff]),
        new Uint8Array([0xfb, 0xef, 0xbe]), // Would produce + and / in standard Base64
        new Uint8Array([0x3e, 0x3f]), // More edge cases
      ];
      
      for (const original of edgeCases) {
        const encoded = toBase64url(original);
        const decoded = fromBase64url(encoded);
        
        expect(decoded).toEqual(original);
        expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
      }
    });
  });

  describe('encoding interface', () => {
    it('should expose all functions through the interface', () => {
      expect(encoding.toBase64url).toBe(toBase64url);
      expect(encoding.fromBase64url).toBe(fromBase64url);
      expect(encoding.isValidBase64url).toBe(isValidBase64url);
    });

    it('should work correctly through the interface', () => {
      const original = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
      
      const encoded = encoding.toBase64url(original);
      expect(encoded).toBe('SGVsbG8');
      
      const decoded = encoding.fromBase64url(encoded);
      expect(decoded).toEqual(original);
      
      expect(encoding.isValidBase64url(encoded)).toBe(true);
    });
  });

  describe('URL safety', () => {
    it('should produce strings safe for URL fragments', () => {
      // Generate many random byte arrays and verify all produce URL-safe output
      for (let i = 0; i < 50; i++) {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        
        const encoded = toBase64url(bytes);
        
        // Should only contain URL-safe characters
        expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
        
        // Should not need URL encoding
        expect(encodeURIComponent(encoded)).toBe(encoded);
      }
    });

    it('should be usable directly in URL fragments', () => {
      const keyPart = new Uint8Array(16);
      crypto.getRandomValues(keyPart);
      
      const encoded = toBase64url(keyPart);
      
      // Construct a URL with the encoded key in the fragment
      const url = `https://example.com/s/abc123#${encoded}`;
      
      // Parse the URL and extract the fragment
      const parsedUrl = new URL(url);
      const fragment = parsedUrl.hash.slice(1); // Remove the '#'
      
      // Fragment should match the encoded value
      expect(fragment).toBe(encoded);
      
      // Should be able to decode it back
      const decoded = fromBase64url(fragment);
      expect(decoded).toEqual(keyPart);
    });
  });
});
