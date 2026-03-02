/**
 * Property-Based Tests for URL Fragment Isolation
 * 
 * **Validates: Requirements 1.7, 2.1, 9.3**
 * 
 * Property 3: URL Fragment Isolation
 * For any secret ID and public key part, the constructed URL should have the
 * secret ID in the path and the public key part only in the fragment (after #).
 * Parsing the URL should correctly extract both parts, and the fragment should
 * never appear in the path or query string.
 * 
 * Requirements context:
 * - 1.7: Construct a shareable URL with the Secret_ID in the path and Public_Key_Part in the URL_Fragment
 * - 2.1: Extract the Public_Key_Part from the URL_Fragment
 * - 9.3: The Public_Key_Part SHALL be encoded in the URL_Fragment using base64url encoding
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  buildSecretUrl,
  parseSecretUrl,
} from '../../src/shared/url-utils';

/**
 * Valid Base64url character set: A-Z, a-z, 0-9, -, _
 */
const BASE64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Alphanumeric character set for secret IDs: A-Z, a-z, 0-9
 */
const ALPHANUMERIC_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/**
 * Arbitrary generator for valid secret IDs (16 alphanumeric characters)
 * Secret IDs must be exactly 16 characters, containing only A-Z, a-z, 0-9
 */
const secretIdArbitrary = fc.stringOf(
  fc.constantFrom(...ALPHANUMERIC_CHARS.split('')),
  { minLength: 16, maxLength: 16 }
);

/**
 * Arbitrary generator for valid public key parts (22 Base64url characters)
 * Public key parts must be exactly 22 characters of valid Base64url encoding
 * (representing 128 bits / 16 bytes)
 */
const publicKeyPartArbitrary = fc.stringOf(
  fc.constantFrom(...BASE64URL_CHARS.split('')),
  { minLength: 22, maxLength: 22 }
);

/**
 * Arbitrary generator for valid base URLs
 */
const baseUrlArbitrary = fc.oneof(
  fc.constant('https://example.com'),
  fc.constant('https://example.com/'),
  fc.constant('https://example.com/app'),
  fc.constant('https://example.com/app/'),
  fc.constant('https://secrets.example.org'),
  fc.constant('https://sub.domain.example.com/path'),
  fc.constant('https://localhost:3000'),
  fc.constant('https://192.168.1.1:8080/app')
);

describe('Property 3: URL Fragment Isolation', () => {
  /**
   * **Validates: Requirements 1.7, 2.1, 9.3**
   * 
   * Property: For any valid secretId and publicKeyPart, building a URL and
   * then parsing it should return the original values unchanged.
   */
  it('build then parse should return original secretId and publicKeyPart', () => {
    fc.assert(
      fc.property(
        baseUrlArbitrary,
        secretIdArbitrary,
        publicKeyPartArbitrary,
        (baseUrl, secretId, publicKeyPart) => {
          // Build the URL
          const url = buildSecretUrl({ baseUrl, secretId, publicKeyPart });
          
          // Parse the URL
          const parsed = parseSecretUrl(url);
          
          // The parsed values should match the original inputs exactly
          expect(parsed.secretId).toBe(secretId);
          expect(parsed.publicKeyPart).toBe(publicKeyPart);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.7**
   * 
   * Property: For any valid inputs, the secretId should appear in the URL path
   * (specifically in the /s/{secretId} pattern).
   */
  it('secretId should be in the URL path', () => {
    fc.assert(
      fc.property(
        baseUrlArbitrary,
        secretIdArbitrary,
        publicKeyPartArbitrary,
        (baseUrl, secretId, publicKeyPart) => {
          const url = buildSecretUrl({ baseUrl, secretId, publicKeyPart });
          const parsedUrl = new URL(url);
          
          // The path should contain /s/{secretId}
          expect(parsedUrl.pathname).toContain(`/s/${secretId}`);
          
          // The secretId should be extractable from the path
          const pathMatch = parsedUrl.pathname.match(/\/s\/([^/]+)\/?$/);
          expect(pathMatch).not.toBeNull();
          expect(pathMatch![1]).toBe(secretId);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.7, 9.3**
   * 
   * Property: For any valid inputs, the publicKeyPart should appear ONLY in
   * the URL fragment (after #), never in the path or query string.
   */
  it('publicKeyPart should be ONLY in the URL fragment', () => {
    fc.assert(
      fc.property(
        baseUrlArbitrary,
        secretIdArbitrary,
        publicKeyPartArbitrary,
        (baseUrl, secretId, publicKeyPart) => {
          const url = buildSecretUrl({ baseUrl, secretId, publicKeyPart });
          const parsedUrl = new URL(url);
          
          // The fragment should contain the publicKeyPart
          expect(parsedUrl.hash).toBe(`#${publicKeyPart}`);
          
          // The publicKeyPart should NOT be in the path
          expect(parsedUrl.pathname).not.toContain(publicKeyPart);
          
          // The publicKeyPart should NOT be in the query string
          expect(parsedUrl.search).not.toContain(publicKeyPart);
          
          // The query string should be empty (no query params)
          expect(parsedUrl.search).toBe('');
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 2.1**
   * 
   * Property: For any valid URL, parsing should correctly extract the
   * publicKeyPart from the fragment.
   */
  it('parsing should extract publicKeyPart from fragment correctly', () => {
    fc.assert(
      fc.property(
        baseUrlArbitrary,
        secretIdArbitrary,
        publicKeyPartArbitrary,
        (baseUrl, secretId, publicKeyPart) => {
          const url = buildSecretUrl({ baseUrl, secretId, publicKeyPart });
          
          // Parse the URL
          const parsed = parseSecretUrl(url);
          
          // Verify the publicKeyPart was extracted from the fragment
          const parsedUrl = new URL(url);
          const fragmentContent = parsedUrl.hash.slice(1); // Remove leading '#'
          
          expect(parsed.publicKeyPart).toBe(fragmentContent);
          expect(parsed.publicKeyPart).toBe(publicKeyPart);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.7, 2.1, 9.3**
   * 
   * Property: The URL structure should maintain the security property that
   * the fragment (containing the publicKeyPart) is never sent to the server.
   * This is verified by ensuring the fragment is properly isolated.
   */
  it('URL structure should isolate fragment from server-visible parts', () => {
    fc.assert(
      fc.property(
        baseUrlArbitrary,
        secretIdArbitrary,
        publicKeyPartArbitrary,
        (baseUrl, secretId, publicKeyPart) => {
          const url = buildSecretUrl({ baseUrl, secretId, publicKeyPart });
          const parsedUrl = new URL(url);
          
          // Server-visible parts: origin + pathname + search
          const serverVisiblePart = parsedUrl.origin + parsedUrl.pathname + parsedUrl.search;
          
          // The publicKeyPart should NOT appear in server-visible parts
          expect(serverVisiblePart).not.toContain(publicKeyPart);
          
          // The secretId SHOULD appear in server-visible parts (it's in the path)
          expect(serverVisiblePart).toContain(secretId);
          
          // The fragment (client-only) should contain the publicKeyPart
          expect(parsedUrl.hash).toBe(`#${publicKeyPart}`);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 9.3**
   * 
   * Property: The publicKeyPart in the fragment should be valid Base64url
   * encoding (URL-safe, no padding).
   */
  it('publicKeyPart in fragment should be valid Base64url', () => {
    fc.assert(
      fc.property(
        baseUrlArbitrary,
        secretIdArbitrary,
        publicKeyPartArbitrary,
        (baseUrl, secretId, publicKeyPart) => {
          const url = buildSecretUrl({ baseUrl, secretId, publicKeyPart });
          const parsedUrl = new URL(url);
          
          // Extract the fragment content
          const fragmentContent = parsedUrl.hash.slice(1);
          
          // Should be exactly 22 characters (128 bits encoded)
          expect(fragmentContent.length).toBe(22);
          
          // Should contain only valid Base64url characters
          const base64urlRegex = /^[A-Za-z0-9_-]+$/;
          expect(fragmentContent).toMatch(base64urlRegex);
          
          // Should not contain standard Base64 characters that need URL encoding
          expect(fragmentContent).not.toContain('+');
          expect(fragmentContent).not.toContain('/');
          expect(fragmentContent).not.toContain('=');
          
          // URL encoding should not change the fragment (already URL-safe)
          expect(encodeURIComponent(fragmentContent)).toBe(fragmentContent);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.7, 2.1**
   * 
   * Property: Multiple round-trips (build -> parse -> build -> parse) should
   * maintain data integrity.
   */
  it('multiple round-trips should maintain data integrity', () => {
    fc.assert(
      fc.property(
        baseUrlArbitrary,
        secretIdArbitrary,
        publicKeyPartArbitrary,
        (baseUrl, secretId, publicKeyPart) => {
          // First round-trip
          const url1 = buildSecretUrl({ baseUrl, secretId, publicKeyPart });
          const parsed1 = parseSecretUrl(url1);
          
          // Second round-trip using parsed values
          const url2 = buildSecretUrl({
            baseUrl,
            secretId: parsed1.secretId,
            publicKeyPart: parsed1.publicKeyPart,
          });
          const parsed2 = parseSecretUrl(url2);
          
          // Third round-trip
          const url3 = buildSecretUrl({
            baseUrl,
            secretId: parsed2.secretId,
            publicKeyPart: parsed2.publicKeyPart,
          });
          const parsed3 = parseSecretUrl(url3);
          
          // All parsed values should match the original
          expect(parsed1.secretId).toBe(secretId);
          expect(parsed1.publicKeyPart).toBe(publicKeyPart);
          expect(parsed2.secretId).toBe(secretId);
          expect(parsed2.publicKeyPart).toBe(publicKeyPart);
          expect(parsed3.secretId).toBe(secretId);
          expect(parsed3.publicKeyPart).toBe(publicKeyPart);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 1.7**
   * 
   * Property: The URL should have a consistent structure with the secretId
   * in the /s/{secretId} path pattern.
   */
  it('URL should follow /s/{secretId}#{publicKeyPart} structure', () => {
    fc.assert(
      fc.property(
        baseUrlArbitrary,
        secretIdArbitrary,
        publicKeyPartArbitrary,
        (baseUrl, secretId, publicKeyPart) => {
          const url = buildSecretUrl({ baseUrl, secretId, publicKeyPart });
          
          // The URL should match the expected pattern
          const urlPattern = new RegExp(`/s/${secretId}#${publicKeyPart}$`);
          expect(url).toMatch(urlPattern);
          
          // Verify the structure by splitting on '#'
          const [beforeFragment, fragment] = url.split('#');
          expect(beforeFragment).toContain(`/s/${secretId}`);
          expect(fragment).toBe(publicKeyPart);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});
