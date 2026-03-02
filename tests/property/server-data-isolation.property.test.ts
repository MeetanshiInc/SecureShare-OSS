/**
 * Property-Based Tests for Server Data Isolation
 * 
 * **Validates: Requirements 6.3, 6.4**
 * 
 * Property 8: Server Data Isolation
 * For any API request to create a secret, the request payload should never contain
 * the public key part, the combined key, or the unencrypted secret content.
 * Only the encrypted blob and private key part should be transmitted.
 * 
 * Requirements context:
 * - 6.3: The Backend_API SHALL never receive the Public_Key_Part or the Combined_Key
 * - 6.4: The Backend_API SHALL never receive unencrypted secret content
 * 
 * Security model:
 * - The server only receives: encrypted blob and private key part (128 bits)
 * - The URL fragment contains: secretId and public key part (128 bits)
 * - Both key parts are needed to reconstruct the full 256-bit key for decryption
 * - The server alone cannot decrypt the secret content
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  createSecret,
  type CreateSecretApiRequest,
  type CreateSecretOptions,
  type SecretCreatorConfig,
  type ExpirationOption,
} from '../../src/frontend/secret-creator';
import { fromBase64url } from '../../src/shared/encoding';
import { combineKey, KEY_PART_SIZE_BYTES, KEY_SIZE_BYTES } from '../../src/shared/crypto/key-generator';
import { decrypt } from '../../src/shared/crypto/encryptor';

/**
 * Arbitrary generator for secret content strings including:
 * - ASCII strings
 * - Unicode strings (including emojis, CJK characters, etc.)
 * - Large strings
 * 
 * Note: We use fullUnicodeString to avoid invalid surrogate pairs
 * which would cause string comparison issues after encryption/decryption
 */
const secretContentArbitrary = fc.oneof(
  // ASCII strings of various lengths
  fc.string({ minLength: 1, maxLength: 100 }),
  // Full unicode strings (valid code points only)
  fc.fullUnicodeString({ minLength: 1, maxLength: 100 }),
  // Strings with specific unicode categories (all valid)
  fc.stringOf(
    fc.oneof(
      fc.char16bits().filter(c => {
        // Filter out lone surrogates (invalid Unicode)
        const code = c.charCodeAt(0);
        return code < 0xD800 || code > 0xDFFF;
      }),
      fc.constant('🔐'), // Emoji
      fc.constant('中文'), // CJK
      fc.constant('العربية'), // Arabic
      fc.constant('日本語'), // Japanese
      fc.constant('한국어'), // Korean
    ),
    { minLength: 1, maxLength: 50 }
  )
);

/**
 * Arbitrary generator for optional expiration values
 */
const expirationArbitrary: fc.Arbitrary<ExpirationOption | undefined> = fc.option(
  fc.constantFrom('1h' as const, '24h' as const, '7d' as const, '30d' as const),
  { nil: undefined }
);

/**
 * Arbitrary generator for optional email addresses
 */
const emailArbitrary: fc.Arbitrary<string | undefined> = fc.option(
  fc.emailAddress(),
  { nil: undefined }
);

/**
 * Test configuration
 */
const testConfig: SecretCreatorConfig = {
  baseUrl: 'https://test.example.com',
  apiEndpoint: '/api/secrets',
};

/**
 * Generates a valid 16-character alphanumeric secret ID for testing
 */
function generateValidSecretId(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * Creates a mock fetch function that captures the request and returns a valid response
 */
function createCapturingFetch(capturedRequests: CreateSecretApiRequest[]): typeof fetch {
  return async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    // Parse and capture the request body
    if (init?.body) {
      const requestBody = JSON.parse(init.body as string) as CreateSecretApiRequest;
      capturedRequests.push(requestBody);
    }

    // Return a successful response with a valid 16-character alphanumeric secretId
    return new Response(
      JSON.stringify({ secretId: generateValidSecretId() }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  };
}

describe('Property 8: Server Data Isolation', () => {
  /**
   * **Validates: Requirements 6.3, 6.4**
   * 
   * Property: The API request payload should never contain the public key part.
   * The public key part should only appear in the URL fragment (returned URL).
   */
  it('API request should never contain the public key part', async () => {
    await fc.assert(
      fc.asyncProperty(
        secretContentArbitrary,
        expirationArbitrary,
        emailArbitrary,
        async (content, expiresIn, notifyEmail) => {
          const capturedRequests: CreateSecretApiRequest[] = [];
          const mockFetch = createCapturingFetch(capturedRequests);

          const options: CreateSecretOptions = { content };
          if (expiresIn !== undefined) {
            options.expiresIn = expiresIn;
          }
          if (notifyEmail !== undefined) {
            options.notifyEmail = notifyEmail;
          }

          // Create the secret
          const shareableUrl = await createSecret(options, testConfig, mockFetch);

          // Verify we captured exactly one request
          expect(capturedRequests.length).toBe(1);
          const apiRequest = capturedRequests[0]!;

          // Extract the public key part from the URL fragment
          const url = new URL(shareableUrl);
          const publicKeyPartFromUrl = url.hash.slice(1); // Remove the '#'
          expect(publicKeyPartFromUrl.length).toBeGreaterThan(0);

          // Verify the public key part is NOT in the API request
          const requestJson = JSON.stringify(apiRequest);
          expect(requestJson).not.toContain(publicKeyPartFromUrl);

          // Verify the private key part IS in the request (it should be there)
          expect(apiRequest.privateKeyPart).toBeDefined();
          expect(typeof apiRequest.privateKeyPart).toBe('string');
          expect(apiRequest.privateKeyPart.length).toBeGreaterThan(0);

          // Verify the private key part is different from the public key part
          expect(apiRequest.privateKeyPart).not.toBe(publicKeyPartFromUrl);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 6.3**
   * 
   * Property: The API request should never contain the combined (full) key.
   * The combined key is 256 bits (32 bytes), while each part is 128 bits (16 bytes).
   */
  it('API request should never contain the combined key', async () => {
    await fc.assert(
      fc.asyncProperty(
        secretContentArbitrary,
        async (content) => {
          const capturedRequests: CreateSecretApiRequest[] = [];
          const mockFetch = createCapturingFetch(capturedRequests);

          // Create the secret
          const shareableUrl = await createSecret({ content }, testConfig, mockFetch);

          // Verify we captured exactly one request
          expect(capturedRequests.length).toBe(1);
          const apiRequest = capturedRequests[0]!;

          // Extract the public key part from the URL fragment
          const url = new URL(shareableUrl);
          const publicKeyPartEncoded = url.hash.slice(1);
          const publicKeyPart = fromBase64url(publicKeyPartEncoded);

          // Decode the private key part from the request
          const privateKeyPart = fromBase64url(apiRequest.privateKeyPart);

          // Verify each key part is 128 bits (16 bytes)
          expect(publicKeyPart.length).toBe(KEY_PART_SIZE_BYTES);
          expect(privateKeyPart.length).toBe(KEY_PART_SIZE_BYTES);

          // Reconstruct the combined key
          const combinedKey = combineKey(publicKeyPart, privateKeyPart);
          expect(combinedKey.length).toBe(KEY_SIZE_BYTES);

          // The combined key should NOT appear anywhere in the request
          // Check by encoding the combined key and searching for it
          const requestJson = JSON.stringify(apiRequest);
          
          // Convert combined key to various encodings to check
          let combinedKeyBase64 = '';
          let binary = '';
          for (let i = 0; i < combinedKey.length; i++) {
            binary += String.fromCharCode(combinedKey[i]!);
          }
          combinedKeyBase64 = btoa(binary);
          
          // Also check base64url encoding
          const combinedKeyBase64url = combinedKeyBase64
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

          // Neither encoding of the combined key should appear in the request
          expect(requestJson).not.toContain(combinedKeyBase64);
          expect(requestJson).not.toContain(combinedKeyBase64url);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 6.4**
   * 
   * Property: The API request should never contain the unencrypted secret content.
   * Only the encrypted blob should be transmitted.
   */
  it('API request should never contain unencrypted secret content', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Use non-empty strings to ensure we can detect them
        fc.string({ minLength: 5, maxLength: 100 }),
        async (content) => {
          const capturedRequests: CreateSecretApiRequest[] = [];
          const mockFetch = createCapturingFetch(capturedRequests);

          // Create the secret
          await createSecret({ content }, testConfig, mockFetch);

          // Verify we captured exactly one request
          expect(capturedRequests.length).toBe(1);
          const apiRequest = capturedRequests[0]!;

          // The request should contain an encrypted blob
          expect(apiRequest.encryptedBlob).toBeDefined();
          expect(apiRequest.encryptedBlob.ciphertext).toBeDefined();
          expect(apiRequest.encryptedBlob.iv).toBeDefined();
          expect(apiRequest.encryptedBlob.tag).toBeDefined();

          // The unencrypted content should NOT appear in the request
          const requestJson = JSON.stringify(apiRequest);
          
          // For content longer than a few characters, it should not appear verbatim
          // (Very short strings might coincidentally appear in base64 encoding)
          if (content.length >= 5) {
            expect(requestJson).not.toContain(content);
          }

          // Also verify the content is not in any of the encrypted blob fields
          // (The ciphertext is base64-encoded, so plaintext shouldn't appear there)
          expect(apiRequest.encryptedBlob.ciphertext).not.toContain(content);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 6.3, 6.4**
   * 
   * Property: The server data (encrypted blob + private key part) alone
   * cannot be used to decrypt the secret. The public key part is required.
   */
  it('server data alone cannot decrypt the secret', async () => {
    await fc.assert(
      fc.asyncProperty(
        secretContentArbitrary,
        async (content) => {
          const capturedRequests: CreateSecretApiRequest[] = [];
          const mockFetch = createCapturingFetch(capturedRequests);

          // Create the secret
          const shareableUrl = await createSecret({ content }, testConfig, mockFetch);

          // Get the server data
          expect(capturedRequests.length).toBe(1);
          const apiRequest = capturedRequests[0]!;
          const encryptedBlob = apiRequest.encryptedBlob;
          const privateKeyPart = fromBase64url(apiRequest.privateKeyPart);

          // Attempt to decrypt with only the private key part (padded to 256 bits)
          // This simulates what the server could attempt with only its data
          const paddedPrivateKey = new Uint8Array(KEY_SIZE_BYTES);
          paddedPrivateKey.set(privateKeyPart, 0);
          // Fill the rest with zeros (or any other value the server might try)
          
          // Decryption should fail because we don't have the correct full key
          await expect(decrypt(encryptedBlob, paddedPrivateKey)).rejects.toThrow();

          // Also try with private key duplicated
          const duplicatedPrivateKey = new Uint8Array(KEY_SIZE_BYTES);
          duplicatedPrivateKey.set(privateKeyPart, 0);
          duplicatedPrivateKey.set(privateKeyPart, KEY_PART_SIZE_BYTES);
          
          await expect(decrypt(encryptedBlob, duplicatedPrivateKey)).rejects.toThrow();

          // Now verify that with the public key part, decryption succeeds
          const url = new URL(shareableUrl);
          const publicKeyPartEncoded = url.hash.slice(1);
          const publicKeyPart = fromBase64url(publicKeyPartEncoded);
          
          const correctKey = combineKey(publicKeyPart, privateKeyPart);
          const decryptedContent = await decrypt(encryptedBlob, correctKey);
          
          expect(decryptedContent).toBe(content);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 6.3, 6.4**
   * 
   * Property: The key parts are properly sized (128 bits each) and
   * the server only receives the private part.
   */
  it('key parts are properly sized and isolated', async () => {
    await fc.assert(
      fc.asyncProperty(
        secretContentArbitrary,
        async (content) => {
          const capturedRequests: CreateSecretApiRequest[] = [];
          const mockFetch = createCapturingFetch(capturedRequests);

          // Create the secret
          const shareableUrl = await createSecret({ content }, testConfig, mockFetch);

          // Get the captured request
          expect(capturedRequests.length).toBe(1);
          const apiRequest = capturedRequests[0]!;

          // Decode the private key part from the request
          const privateKeyPart = fromBase64url(apiRequest.privateKeyPart);
          
          // Extract the public key part from the URL fragment
          const url = new URL(shareableUrl);
          const publicKeyPartEncoded = url.hash.slice(1);
          const publicKeyPart = fromBase64url(publicKeyPartEncoded);

          // Verify both parts are exactly 128 bits (16 bytes)
          expect(privateKeyPart.length).toBe(KEY_PART_SIZE_BYTES);
          expect(publicKeyPart.length).toBe(KEY_PART_SIZE_BYTES);

          // Verify the parts are different (extremely unlikely to be the same)
          let partsAreDifferent = false;
          for (let i = 0; i < KEY_PART_SIZE_BYTES; i++) {
            if (publicKeyPart[i] !== privateKeyPart[i]) {
              partsAreDifferent = true;
              break;
            }
          }
          // Note: There's a 1/2^128 chance they're the same, which is negligible
          // We check this to ensure the split is actually happening
          expect(partsAreDifferent).toBe(true);

          // Verify the combined key is 256 bits
          const combinedKey = combineKey(publicKeyPart, privateKeyPart);
          expect(combinedKey.length).toBe(KEY_SIZE_BYTES);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 6.3, 6.4**
   * 
   * Property: Attempting decryption with random key parts should fail,
   * demonstrating that both specific parts are required.
   */
  it('random key parts cannot decrypt the secret', async () => {
    await fc.assert(
      fc.asyncProperty(
        secretContentArbitrary,
        fc.uint8Array({ minLength: KEY_PART_SIZE_BYTES, maxLength: KEY_PART_SIZE_BYTES }),
        async (content, randomKeyPart) => {
          const capturedRequests: CreateSecretApiRequest[] = [];
          const mockFetch = createCapturingFetch(capturedRequests);

          // Create the secret
          const shareableUrl = await createSecret({ content }, testConfig, mockFetch);

          // Get the server data
          expect(capturedRequests.length).toBe(1);
          const apiRequest = capturedRequests[0]!;
          const encryptedBlob = apiRequest.encryptedBlob;
          const privateKeyPart = fromBase64url(apiRequest.privateKeyPart);

          // Get the actual public key part
          const url = new URL(shareableUrl);
          const publicKeyPartEncoded = url.hash.slice(1);
          const publicKeyPart = fromBase64url(publicKeyPartEncoded);

          // Skip if random part happens to match the actual public part (extremely unlikely)
          let randomMatchesPublic = true;
          for (let i = 0; i < KEY_PART_SIZE_BYTES; i++) {
            if (randomKeyPart[i] !== publicKeyPart[i]) {
              randomMatchesPublic = false;
              break;
            }
          }
          if (randomMatchesPublic) {
            return true; // Skip this iteration
          }

          // Try to decrypt with random public key part + correct private key part
          const wrongKey = combineKey(randomKeyPart, privateKeyPart);
          await expect(decrypt(encryptedBlob, wrongKey)).rejects.toThrow();

          // Verify correct key still works
          const correctKey = combineKey(publicKeyPart, privateKeyPart);
          const decryptedContent = await decrypt(encryptedBlob, correctKey);
          expect(decryptedContent).toBe(content);

          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});
