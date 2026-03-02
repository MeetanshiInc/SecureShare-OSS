/**
 * Unit tests for URL builder and parser utilities
 * 
 * Tests verify:
 * - URL construction places secretId in path and publicKeyPart in fragment
 * - URL parsing correctly extracts secretId and publicKeyPart
 * - Fragment is never in path or query string
 * - Validation of secretId (16 alphanumeric chars)
 * - Validation of publicKeyPart (22 Base64url chars)
 * - Error handling for invalid inputs
 * 
 * Requirements:
 * - 1.7: Construct a shareable URL with the Secret_ID in the path and Public_Key_Part in the URL_Fragment
 * - 2.1: Extract the Public_Key_Part from the URL_Fragment
 */

import { describe, it, expect } from 'vitest';
import {
  buildSecretUrl,
  parseSecretUrl,
  isValidSecretId,
  isValidPublicKeyPart,
  urlUtils,
  UrlValidationError,
  type BuildSecretUrlOptions,
} from '../../src/shared/url-utils';

describe('URL Utilities', () => {
  // Valid test data
  const validSecretId = 'abc123def456gh78'; // 16 alphanumeric chars
  const validPublicKeyPart = 'AAAAAAAAAAAAAAAAAAAAAA'; // 22 Base64url chars
  const validBaseUrl = 'https://example.com';

  describe('isValidSecretId', () => {
    it('should return true for valid 16-character alphanumeric IDs', () => {
      expect(isValidSecretId('abc123def456gh78')).toBe(true);
      expect(isValidSecretId('ABCDEFGHIJKLMNOP')).toBe(true);
      expect(isValidSecretId('1234567890123456')).toBe(true);
      expect(isValidSecretId('aB1cD2eF3gH4iJ5k')).toBe(true);
    });

    it('should return false for IDs that are too short', () => {
      expect(isValidSecretId('')).toBe(false);
      expect(isValidSecretId('abc')).toBe(false);
      expect(isValidSecretId('abc123def456gh7')).toBe(false); // 15 chars
    });

    it('should return false for IDs that are too long', () => {
      expect(isValidSecretId('abc123def456gh789')).toBe(false); // 17 chars
      expect(isValidSecretId('abc123def456gh78abc123def456gh78')).toBe(false);
    });

    it('should return false for IDs with special characters', () => {
      expect(isValidSecretId('abc123def456gh7!')).toBe(false);
      expect(isValidSecretId('abc-123-def-456g')).toBe(false);
      expect(isValidSecretId('abc_123_def_456g')).toBe(false);
      expect(isValidSecretId('abc 123 def 456g')).toBe(false);
    });

    it('should return false for non-string inputs', () => {
      expect(isValidSecretId(123 as unknown as string)).toBe(false);
      expect(isValidSecretId(null as unknown as string)).toBe(false);
      expect(isValidSecretId(undefined as unknown as string)).toBe(false);
      expect(isValidSecretId({} as unknown as string)).toBe(false);
    });
  });

  describe('isValidPublicKeyPart', () => {
    it('should return true for valid 22-character Base64url strings', () => {
      expect(isValidPublicKeyPart('AAAAAAAAAAAAAAAAAAAAAA')).toBe(true);
      expect(isValidPublicKeyPart('____________________-_')).toBe(true);
      expect(isValidPublicKeyPart('abcdefghijklmnopqrstuv')).toBe(true);
      expect(isValidPublicKeyPart('0123456789ABCDEFabcdef')).toBe(true);
    });

    it('should return false for strings that are too short', () => {
      expect(isValidPublicKeyPart('')).toBe(false);
      expect(isValidPublicKeyPart('AAAAAAAAAAAAAAAAAAAAA')).toBe(false); // 21 chars
    });

    it('should return false for strings that are too long', () => {
      expect(isValidPublicKeyPart('AAAAAAAAAAAAAAAAAAAAAAA')).toBe(false); // 23 chars
    });

    it('should return false for strings with invalid Base64url characters', () => {
      expect(isValidPublicKeyPart('AAAAAAAAAAAAAAAAAAAA!!')).toBe(false);
      expect(isValidPublicKeyPart('AAAAAAAAAAAAAAAAAAAA+/')).toBe(false);
      expect(isValidPublicKeyPart('AAAAAAAAAAAAAAAAAAAA==')).toBe(false);
    });

    it('should return false for non-string inputs', () => {
      expect(isValidPublicKeyPart(123 as unknown as string)).toBe(false);
      expect(isValidPublicKeyPart(null as unknown as string)).toBe(false);
      expect(isValidPublicKeyPart(undefined as unknown as string)).toBe(false);
    });
  });

  describe('buildSecretUrl', () => {
    it('should build a valid URL with secretId in path and publicKeyPart in fragment', () => {
      const url = buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      });

      expect(url).toBe(`https://example.com/s/${validSecretId}#${validPublicKeyPart}`);
    });

    it('should handle base URLs with trailing slashes', () => {
      const url = buildSecretUrl({
        baseUrl: 'https://example.com/',
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      });

      expect(url).toBe(`https://example.com/s/${validSecretId}#${validPublicKeyPart}`);
    });

    it('should handle base URLs with paths', () => {
      const url = buildSecretUrl({
        baseUrl: 'https://example.com/app',
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      });

      expect(url).toBe(`https://example.com/app/s/${validSecretId}#${validPublicKeyPart}`);
    });

    it('should handle base URLs with paths and trailing slashes', () => {
      const url = buildSecretUrl({
        baseUrl: 'https://example.com/app/',
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      });

      expect(url).toBe(`https://example.com/app/s/${validSecretId}#${validPublicKeyPart}`);
    });

    it('should place publicKeyPart ONLY in the fragment', () => {
      const url = buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      });

      const parsedUrl = new URL(url);
      
      // Public key part should be in fragment
      expect(parsedUrl.hash).toBe(`#${validPublicKeyPart}`);
      
      // Public key part should NOT be in path
      expect(parsedUrl.pathname).not.toContain(validPublicKeyPart);
      
      // Public key part should NOT be in query string
      expect(parsedUrl.search).toBe('');
    });

    it('should throw UrlValidationError for empty base URL', () => {
      expect(() => buildSecretUrl({
        baseUrl: '',
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      })).toThrow(UrlValidationError);
    });

    it('should throw UrlValidationError for invalid base URL format', () => {
      expect(() => buildSecretUrl({
        baseUrl: 'not-a-url',
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      })).toThrow(UrlValidationError);
    });

    it('should throw UrlValidationError for base URL with fragment', () => {
      expect(() => buildSecretUrl({
        baseUrl: 'https://example.com#existing',
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      })).toThrow(UrlValidationError);
    });

    it('should throw UrlValidationError for invalid secretId', () => {
      expect(() => buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: 'short',
        publicKeyPart: validPublicKeyPart,
      })).toThrow(UrlValidationError);

      expect(() => buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: 'has-special-chars!',
        publicKeyPart: validPublicKeyPart,
      })).toThrow(UrlValidationError);
    });

    it('should throw UrlValidationError for invalid publicKeyPart', () => {
      expect(() => buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: 'short',
      })).toThrow(UrlValidationError);

      expect(() => buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: 'invalid!characters!!!!!',
      })).toThrow(UrlValidationError);
    });

    it('should work with different valid Base64url characters in publicKeyPart', () => {
      const keyWithDash = 'AAAAAAAAAAAAAAAAAAAA--';
      const keyWithUnderscore = 'AAAAAAAAAAAAAAAAAAAA__';
      
      const url1 = buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: keyWithDash,
      });
      expect(url1).toContain(`#${keyWithDash}`);

      const url2 = buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: keyWithUnderscore,
      });
      expect(url2).toContain(`#${keyWithUnderscore}`);
    });
  });

  describe('parseSecretUrl', () => {
    it('should parse a valid secret URL', () => {
      const url = `https://example.com/s/${validSecretId}#${validPublicKeyPart}`;
      const result = parseSecretUrl(url);

      expect(result.secretId).toBe(validSecretId);
      expect(result.publicKeyPart).toBe(validPublicKeyPart);
    });

    it('should parse URLs with different base paths', () => {
      const url = `https://example.com/app/s/${validSecretId}#${validPublicKeyPart}`;
      const result = parseSecretUrl(url);

      expect(result.secretId).toBe(validSecretId);
      expect(result.publicKeyPart).toBe(validPublicKeyPart);
    });

    it('should parse URLs with trailing slashes', () => {
      const url = `https://example.com/s/${validSecretId}/#${validPublicKeyPart}`;
      const result = parseSecretUrl(url);

      expect(result.secretId).toBe(validSecretId);
      expect(result.publicKeyPart).toBe(validPublicKeyPart);
    });

    it('should extract publicKeyPart from fragment only', () => {
      const url = `https://example.com/s/${validSecretId}#${validPublicKeyPart}`;
      const result = parseSecretUrl(url);

      // Verify the public key part came from the fragment
      const parsedUrl = new URL(url);
      expect(result.publicKeyPart).toBe(parsedUrl.hash.slice(1));
    });

    it('should throw UrlValidationError for empty URL', () => {
      expect(() => parseSecretUrl('')).toThrow(UrlValidationError);
    });

    it('should throw UrlValidationError for invalid URL format', () => {
      expect(() => parseSecretUrl('not-a-url')).toThrow(UrlValidationError);
    });

    it('should throw UrlValidationError for URL without /s/ path pattern', () => {
      expect(() => parseSecretUrl(`https://example.com/${validSecretId}#${validPublicKeyPart}`))
        .toThrow(UrlValidationError);
      expect(() => parseSecretUrl(`https://example.com/secret/${validSecretId}#${validPublicKeyPart}`))
        .toThrow(UrlValidationError);
    });

    it('should throw UrlValidationError for invalid secretId in URL', () => {
      expect(() => parseSecretUrl(`https://example.com/s/short#${validPublicKeyPart}`))
        .toThrow(UrlValidationError);
      expect(() => parseSecretUrl(`https://example.com/s/has-special-chars!#${validPublicKeyPart}`))
        .toThrow(UrlValidationError);
    });

    it('should throw UrlValidationError for URL without fragment', () => {
      expect(() => parseSecretUrl(`https://example.com/s/${validSecretId}`))
        .toThrow(UrlValidationError);
    });

    it('should throw UrlValidationError for invalid publicKeyPart in fragment', () => {
      expect(() => parseSecretUrl(`https://example.com/s/${validSecretId}#short`))
        .toThrow(UrlValidationError);
      expect(() => parseSecretUrl(`https://example.com/s/${validSecretId}#invalid!characters!!!!!`))
        .toThrow(UrlValidationError);
    });

    it('should throw UrlValidationError if key appears in query string', () => {
      // Security check: key should never be in query string
      expect(() => parseSecretUrl(
        `https://example.com/s/${validSecretId}?key=${validPublicKeyPart}#${validPublicKeyPart}`
      )).toThrow(UrlValidationError);
      
      expect(() => parseSecretUrl(
        `https://example.com/s/${validSecretId}?publicKeyPart=${validPublicKeyPart}#${validPublicKeyPart}`
      )).toThrow(UrlValidationError);
    });

    it('should handle URLs with different valid Base64url characters', () => {
      const keyWithDash = 'AAAAAAAAAAAAAAAAAAAA--';
      const keyWithUnderscore = 'AAAAAAAAAAAAAAAAAAAA__';

      const result1 = parseSecretUrl(`https://example.com/s/${validSecretId}#${keyWithDash}`);
      expect(result1.publicKeyPart).toBe(keyWithDash);

      const result2 = parseSecretUrl(`https://example.com/s/${validSecretId}#${keyWithUnderscore}`);
      expect(result2.publicKeyPart).toBe(keyWithUnderscore);
    });
  });

  describe('round-trip integrity', () => {
    it('should maintain integrity through build and parse', () => {
      const originalOptions: BuildSecretUrlOptions = {
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      };

      const url = buildSecretUrl(originalOptions);
      const parsed = parseSecretUrl(url);

      expect(parsed.secretId).toBe(originalOptions.secretId);
      expect(parsed.publicKeyPart).toBe(originalOptions.publicKeyPart);
    });

    it('should maintain integrity with various valid inputs', () => {
      const testCases = [
        { secretId: 'ABCDEFGHIJKLMNOP', publicKeyPart: 'abcdefghijklmnopqrstuv' },
        { secretId: '1234567890123456', publicKeyPart: '0123456789ABCDEFabcdef' },
        { secretId: 'aB1cD2eF3gH4iJ5k', publicKeyPart: '____________________-_' },
      ];

      for (const testCase of testCases) {
        const url = buildSecretUrl({
          baseUrl: validBaseUrl,
          ...testCase,
        });
        const parsed = parseSecretUrl(url);

        expect(parsed.secretId).toBe(testCase.secretId);
        expect(parsed.publicKeyPart).toBe(testCase.publicKeyPart);
      }
    });

    it('should maintain integrity with different base URLs', () => {
      const baseUrls = [
        'https://example.com',
        'https://example.com/',
        'https://example.com/app',
        'https://example.com/app/',
        'https://sub.example.com/path/to/app',
      ];

      for (const baseUrl of baseUrls) {
        const url = buildSecretUrl({
          baseUrl,
          secretId: validSecretId,
          publicKeyPart: validPublicKeyPart,
        });
        const parsed = parseSecretUrl(url);

        expect(parsed.secretId).toBe(validSecretId);
        expect(parsed.publicKeyPart).toBe(validPublicKeyPart);
      }
    });
  });

  describe('security: fragment isolation', () => {
    it('should never place publicKeyPart in the path', () => {
      const url = buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      });

      const parsedUrl = new URL(url);
      expect(parsedUrl.pathname).not.toContain(validPublicKeyPart);
    });

    it('should never place publicKeyPart in the query string', () => {
      const url = buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      });

      const parsedUrl = new URL(url);
      expect(parsedUrl.search).toBe('');
      expect(parsedUrl.searchParams.toString()).toBe('');
    });

    it('should always place publicKeyPart in the fragment', () => {
      const url = buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      });

      const parsedUrl = new URL(url);
      expect(parsedUrl.hash).toBe(`#${validPublicKeyPart}`);
    });

    it('should reject URLs where key might be exposed to server', () => {
      // These URLs have the key in places that would be sent to the server
      const dangerousUrls = [
        `https://example.com/s/${validSecretId}?key=${validPublicKeyPart}#${validPublicKeyPart}`,
        `https://example.com/s/${validSecretId}?publicKeyPart=${validPublicKeyPart}#${validPublicKeyPart}`,
      ];

      for (const url of dangerousUrls) {
        expect(() => parseSecretUrl(url)).toThrow(UrlValidationError);
      }
    });
  });

  describe('urlUtils interface', () => {
    it('should expose all functions through the interface', () => {
      expect(urlUtils.buildSecretUrl).toBe(buildSecretUrl);
      expect(urlUtils.parseSecretUrl).toBe(parseSecretUrl);
      expect(urlUtils.isValidSecretId).toBe(isValidSecretId);
      expect(urlUtils.isValidPublicKeyPart).toBe(isValidPublicKeyPart);
    });

    it('should work correctly through the interface', () => {
      const url = urlUtils.buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      });

      const parsed = urlUtils.parseSecretUrl(url);

      expect(parsed.secretId).toBe(validSecretId);
      expect(parsed.publicKeyPart).toBe(validPublicKeyPart);
      expect(urlUtils.isValidSecretId(validSecretId)).toBe(true);
      expect(urlUtils.isValidPublicKeyPart(validPublicKeyPart)).toBe(true);
    });
  });

  describe('error messages', () => {
    it('should provide clear error messages for validation failures', () => {
      expect(() => buildSecretUrl({
        baseUrl: '',
        secretId: validSecretId,
        publicKeyPart: validPublicKeyPart,
      })).toThrow('Base URL must be a non-empty string');

      expect(() => buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: 'short',
        publicKeyPart: validPublicKeyPart,
      })).toThrow('Secret ID must be exactly 16 alphanumeric characters');

      expect(() => buildSecretUrl({
        baseUrl: validBaseUrl,
        secretId: validSecretId,
        publicKeyPart: 'short',
      })).toThrow('Public key part must be exactly 22 valid Base64url characters');
    });

    it('should throw UrlValidationError instances', () => {
      try {
        buildSecretUrl({
          baseUrl: '',
          secretId: validSecretId,
          publicKeyPart: validPublicKeyPart,
        });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(UrlValidationError);
        expect((error as UrlValidationError).name).toBe('UrlValidationError');
      }
    });
  });
});
