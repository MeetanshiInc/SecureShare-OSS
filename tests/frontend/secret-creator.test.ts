/**
 * Unit tests for SecretCreator module
 * 
 * Tests verify:
 * - Secret creation orchestrates key generation, splitting, and encryption
 * - API requests contain ONLY encrypted blob and private key part
 * - Public key part is NEVER sent to the server
 * - Plaintext content is NEVER sent to the server
 * - Shareable URL is correctly constructed with public key in fragment
 * - Error handling for various failure scenarios
 * 
 * Requirements:
 * - 1.1: Generate cryptographically secure random key using Web Crypto API
 * - 1.2: Split key into Public_Key_Part and Private_Key_Part
 * - 1.3: Encrypt the secret using AES-256-GCM with the Combined_Key
 * - 1.4: Send only the Encrypted_Blob and Private_Key_Part to the Backend_API
 * - 1.7: Construct a shareable URL with the Secret_ID in the path and Public_Key_Part in the URL_Fragment
 * - 6.3: The Backend_API SHALL never receive the Public_Key_Part or the Combined_Key
 * - 6.4: The Backend_API SHALL never receive unencrypted secret content
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  createSecret,
  createSecretCreator,
  SecretCreationError,
  DEFAULT_CONFIG,
  type CreateSecretOptions,
  type CreateSecretApiRequest,
  type SecretCreatorConfig,
} from '../../src/frontend/secret-creator';
import { fromBase64url } from '../../src/shared/encoding';
import { combineKey } from '../../src/shared/crypto/key-generator';
import { decrypt, type EncryptedPayload } from '../../src/shared/crypto/encryptor';
import { deriveKey } from '../../src/shared/crypto/password-deriver';
import { parseSecretUrl } from '../../src/shared/url-utils';

describe('SecretCreator', () => {
  // Mock fetch function
  let mockFetch: typeof fetch;
  let capturedRequest: CreateSecretApiRequest | null;
  
  const testConfig: SecretCreatorConfig = {
    baseUrl: 'https://example.com',
    apiEndpoint: '/api/secrets',
  };

  beforeEach(() => {
    capturedRequest = null;
    mockFetch = vi.fn(async (_url: RequestInfo | URL, options?: RequestInit) => {
      // Capture the request body for verification
      if (options?.body) {
        capturedRequest = JSON.parse(options.body as string);
      }
      
      // Return a successful response with a valid 16-character secret ID
      return new Response(JSON.stringify({ secretId: 'abc123def456gh78' }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
  });

  describe('createSecret', () => {
    it('should create a secret and return a shareable URL', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
      };

      const url = await createSecret(options, testConfig, mockFetch);

      // Verify URL structure
      expect(url).toMatch(/^https:\/\/example\.com\/s\/[A-Za-z0-9]{16}#[A-Za-z0-9_-]{22}$/);
      
      // Verify API was called
      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/api/secrets',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        })
      );
    });

    it('should include expiration option in API request', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
        expiresIn: '24h',
      };

      await createSecret(options, testConfig, mockFetch);

      expect(capturedRequest).not.toBeNull();
      expect(capturedRequest!.expiresIn).toBe('24h');
    });

    it('should include notification email in API request', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
        notifyEmail: 'test@example.com',
      };

      await createSecret(options, testConfig, mockFetch);

      expect(capturedRequest).not.toBeNull();
      expect(capturedRequest!.notifyEmail).toBe('test@example.com');
    });

    it('should handle empty string content', async () => {
      const options: CreateSecretOptions = {
        content: '',
      };

      const url = await createSecret(options, testConfig, mockFetch);

      expect(url).toMatch(/^https:\/\/example\.com\/s\/[A-Za-z0-9]{16}#[A-Za-z0-9_-]{22}$/);
      expect(capturedRequest).not.toBeNull();
      expect(capturedRequest!.encryptedBlob).toBeDefined();
    });

    it('should handle unicode content', async () => {
      const options: CreateSecretOptions = {
        content: '你好世界 🌍 مرحبا',
      };

      const url = await createSecret(options, testConfig, mockFetch);

      expect(url).toMatch(/^https:\/\/example\.com\/s\/[A-Za-z0-9]{16}#[A-Za-z0-9_-]{22}$/);
      expect(capturedRequest).not.toBeNull();
    });

    it('should handle large content', async () => {
      const options: CreateSecretOptions = {
        content: 'x'.repeat(100000), // 100KB of content
      };

      const url = await createSecret(options, testConfig, mockFetch);

      expect(url).toMatch(/^https:\/\/example\.com\/s\/[A-Za-z0-9]{16}#[A-Za-z0-9_-]{22}$/);
      expect(capturedRequest).not.toBeNull();
    });
  });

  describe('Security: Server Data Isolation (Requirements 6.3, 6.4)', () => {
    it('should NEVER send the public key part to the server', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
      };

      const url = await createSecret(options, testConfig, mockFetch);

      // Extract the public key part from the URL
      const { publicKeyPart } = parseSecretUrl(url);

      // Verify the request was captured
      expect(capturedRequest).not.toBeNull();

      // Convert request to string to search for the public key part
      const requestString = JSON.stringify(capturedRequest);

      // The public key part should NOT appear anywhere in the request
      expect(requestString).not.toContain(publicKeyPart);

      // Verify the request structure only contains expected fields
      expect(capturedRequest).toHaveProperty('encryptedBlob');
      expect(capturedRequest).toHaveProperty('privateKeyPart');
      expect(capturedRequest).not.toHaveProperty('publicKeyPart');
      expect(capturedRequest).not.toHaveProperty('key');
      expect(capturedRequest).not.toHaveProperty('combinedKey');
    });

    it('should NEVER send the plaintext content to the server', async () => {
      const secretContent = 'This is my super secret message that should never be sent to the server!';
      const options: CreateSecretOptions = {
        content: secretContent,
      };

      await createSecret(options, testConfig, mockFetch);

      // Verify the request was captured
      expect(capturedRequest).not.toBeNull();

      // Convert request to string to search for the plaintext
      const requestString = JSON.stringify(capturedRequest);

      // The plaintext content should NOT appear anywhere in the request
      expect(requestString).not.toContain(secretContent);

      // Verify the request structure only contains encrypted data
      expect(capturedRequest).toHaveProperty('encryptedBlob');
      expect(capturedRequest!.encryptedBlob).toHaveProperty('ciphertext');
      expect(capturedRequest!.encryptedBlob).toHaveProperty('iv');
      expect(capturedRequest!.encryptedBlob).toHaveProperty('tag');
      expect(capturedRequest).not.toHaveProperty('content');
      expect(capturedRequest).not.toHaveProperty('plaintext');
      expect(capturedRequest).not.toHaveProperty('secret');
    });

    it('should NEVER send the combined key to the server', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
      };

      const url = await createSecret(options, testConfig, mockFetch);

      // Extract the public key part from the URL
      const { publicKeyPart } = parseSecretUrl(url);
      const publicKeyBytes = fromBase64url(publicKeyPart);

      // Get the private key part from the request
      expect(capturedRequest).not.toBeNull();
      const privateKeyBytes = fromBase64url(capturedRequest!.privateKeyPart);

      // Reconstruct the combined key
      const combinedKey = combineKey(publicKeyBytes, privateKeyBytes);

      // Convert request to string
      const requestString = JSON.stringify(capturedRequest);

      // The combined key (in any encoding) should NOT appear in the request
      // Check for base64url encoding of the combined key
      const combinedKeyBase64 = btoa(String.fromCharCode(...combinedKey));
      expect(requestString).not.toContain(combinedKeyBase64);
    });

    it('should only send encryptedBlob and privateKeyPart (plus optional fields)', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
        expiresIn: '7d',
        notifyEmail: 'test@example.com',
      };

      await createSecret(options, testConfig, mockFetch);

      expect(capturedRequest).not.toBeNull();

      // Get all keys in the request
      const requestKeys = Object.keys(capturedRequest!);

      // Should only contain these allowed fields
      const allowedFields = ['encryptedBlob', 'privateKeyPart', 'expiresIn', 'notifyEmail', 'passwordSalt'];
      for (const key of requestKeys) {
        expect(allowedFields).toContain(key);
      }

      // Must have required fields
      expect(requestKeys).toContain('encryptedBlob');
      expect(requestKeys).toContain('privateKeyPart');
    });
  });

  describe('Encryption Verification', () => {
    it('should produce encrypted data that can be decrypted with the combined key', async () => {
      const secretContent = 'My secret message for decryption test';
      const options: CreateSecretOptions = {
        content: secretContent,
      };

      const url = await createSecret(options, testConfig, mockFetch);

      // Extract the public key part from the URL
      const { publicKeyPart } = parseSecretUrl(url);
      const publicKeyBytes = fromBase64url(publicKeyPart);

      // Get the private key part and encrypted blob from the request
      expect(capturedRequest).not.toBeNull();
      const privateKeyBytes = fromBase64url(capturedRequest!.privateKeyPart);
      const encryptedBlob = capturedRequest!.encryptedBlob;

      // Reconstruct the combined key
      const combinedKey = combineKey(publicKeyBytes, privateKeyBytes);

      // Decrypt the blob
      const decrypted = await decrypt(encryptedBlob, combinedKey);

      // Verify the decrypted content matches the original
      expect(decrypted).toBe(secretContent);
    });

    it('should produce different encrypted data for the same content (due to random IV)', async () => {
      const options: CreateSecretOptions = {
        content: 'Same content',
      };

      // Create two secrets with the same content
      const capturedRequests: CreateSecretApiRequest[] = [];
      const mockFetchCapture = vi.fn(async (_url: RequestInfo | URL, requestOptions?: RequestInit) => {
        if (requestOptions?.body) {
          capturedRequests.push(JSON.parse(requestOptions.body as string));
        }
        return new Response(JSON.stringify({ secretId: 'abc123def456gh78' }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      await createSecret(options, testConfig, mockFetchCapture);
      await createSecret(options, testConfig, mockFetchCapture);

      // The encrypted blobs should be different (different IVs)
      expect(capturedRequests.length).toBe(2);
      expect(capturedRequests[0]!.encryptedBlob.iv).not.toBe(capturedRequests[1]!.encryptedBlob.iv);
      expect(capturedRequests[0]!.encryptedBlob.ciphertext).not.toBe(capturedRequests[1]!.encryptedBlob.ciphertext);
    });
  });

  describe('URL Construction', () => {
    it('should place the public key part only in the URL fragment', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
      };

      const url = await createSecret(options, testConfig, mockFetch);

      // Parse the URL
      const parsedUrl = new URL(url);

      // The fragment should contain the public key part
      expect(parsedUrl.hash).toMatch(/^#[A-Za-z0-9_-]{22}$/);

      // The path should contain the secret ID
      expect(parsedUrl.pathname).toMatch(/^\/s\/[A-Za-z0-9]{16}$/);

      // The query string should be empty
      expect(parsedUrl.search).toBe('');
    });

    it('should produce a URL that can be parsed back correctly', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
      };

      const url = await createSecret(options, testConfig, mockFetch);

      // Parse the URL using our utility
      const { secretId, publicKeyPart } = parseSecretUrl(url);

      // Verify the parsed values
      expect(secretId).toBe('abc123def456gh78'); // From mock response
      expect(publicKeyPart).toMatch(/^[A-Za-z0-9_-]{22}$/);
    });
  });

  describe('Error Handling', () => {
    it('should throw SecretCreationError for non-string content', async () => {
      const options = {
        content: 123 as unknown as string,
      };

      await expect(createSecret(options, testConfig, mockFetch)).rejects.toThrow(SecretCreationError);
      await expect(createSecret(options, testConfig, mockFetch)).rejects.toThrow('Secret content must be a string');
    });

    it('should throw SecretCreationError for API errors', async () => {
      const errorFetch = vi.fn(async () => {
        return new Response(JSON.stringify({ error: 'Server error', code: 'INTERNAL_ERROR' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const options: CreateSecretOptions = {
        content: 'My secret message',
      };

      await expect(createSecret(options, testConfig, errorFetch)).rejects.toThrow(SecretCreationError);
      await expect(createSecret(options, testConfig, errorFetch)).rejects.toThrow('API error');
    });

    it('should throw SecretCreationError for network errors', async () => {
      const networkErrorFetch = vi.fn(async () => {
        throw new Error('Network error');
      }) as typeof fetch;

      const options: CreateSecretOptions = {
        content: 'My secret message',
      };

      await expect(createSecret(options, testConfig, networkErrorFetch)).rejects.toThrow(SecretCreationError);
      await expect(createSecret(options, testConfig, networkErrorFetch)).rejects.toThrow('Network error');
    });

    it('should throw SecretCreationError for invalid API response', async () => {
      const invalidResponseFetch = vi.fn(async () => {
        return new Response('not json', {
          status: 201,
          headers: { 'Content-Type': 'text/plain' },
        });
      }) as typeof fetch;

      const options: CreateSecretOptions = {
        content: 'My secret message',
      };

      await expect(createSecret(options, testConfig, invalidResponseFetch)).rejects.toThrow(SecretCreationError);
      await expect(createSecret(options, testConfig, invalidResponseFetch)).rejects.toThrow('Invalid API response format');
    });

    it('should throw SecretCreationError for missing secretId in response', async () => {
      const missingIdFetch = vi.fn(async () => {
        return new Response(JSON.stringify({}), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const options: CreateSecretOptions = {
        content: 'My secret message',
      };

      await expect(createSecret(options, testConfig, missingIdFetch)).rejects.toThrow(SecretCreationError);
      await expect(createSecret(options, testConfig, missingIdFetch)).rejects.toThrow('API response missing secretId');
    });

    it('should include cause in SecretCreationError when wrapping other errors', async () => {
      const originalError = new Error('Original error');
      const networkErrorFetch = vi.fn(async () => {
        throw originalError;
      }) as typeof fetch;

      const options: CreateSecretOptions = {
        content: 'My secret message',
      };

      try {
        await createSecret(options, testConfig, networkErrorFetch);
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(SecretCreationError);
        expect((error as SecretCreationError).cause).toBe(originalError);
      }
    });
  });

  describe('createSecretCreator factory', () => {
    it('should create a SecretCreator instance with default config', async () => {
      const creator = createSecretCreator(testConfig, mockFetch);

      const url = await creator.createSecret({ content: 'Test' });

      expect(url).toMatch(/^https:\/\/example\.com\/s\/[A-Za-z0-9]{16}#[A-Za-z0-9_-]{22}$/);
    });

    it('should create a SecretCreator instance with custom config', async () => {
      const customConfig: SecretCreatorConfig = {
        baseUrl: 'https://custom.example.com',
        apiEndpoint: '/custom/api/secrets',
      };

      const customFetch = vi.fn(async () => {
        return new Response(JSON.stringify({ secretId: 'custom12345678ab' }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const creator = createSecretCreator(customConfig, customFetch);

      const url = await creator.createSecret({ content: 'Test' });

      expect(url).toMatch(/^https:\/\/custom\.example\.com\/s\/custom12345678ab#[A-Za-z0-9_-]{22}$/);
      expect(customFetch).toHaveBeenCalledWith(
        'https://custom.example.com/custom/api/secrets',
        expect.any(Object)
      );
    });
  });

  describe('DEFAULT_CONFIG', () => {
    it('should have sensible default values', () => {
      expect(DEFAULT_CONFIG.apiEndpoint).toBe('/api/secrets');
      // baseUrl depends on window.location.origin which may not be available in tests
      expect(typeof DEFAULT_CONFIG.baseUrl).toBe('string');
    });
  });

  describe('Key Generation and Splitting', () => {
    it('should generate different keys for each secret', async () => {
      const options: CreateSecretOptions = {
        content: 'Same content',
      };

      const urls: string[] = [];
      const privateKeys: string[] = [];

      for (let i = 0; i < 5; i++) {
        capturedRequest = null;
        const url = await createSecret(options, testConfig, mockFetch);
        urls.push(url);
        if (capturedRequest !== null) {
          privateKeys.push((capturedRequest as CreateSecretApiRequest).privateKeyPart);
        }
      }

      // All URLs should have different public key parts
      const publicKeyParts = urls.map(url => parseSecretUrl(url).publicKeyPart);
      const uniquePublicKeys = new Set(publicKeyParts);
      expect(uniquePublicKeys.size).toBe(5);

      // All private key parts should be different
      const uniquePrivateKeys = new Set(privateKeys);
      expect(uniquePrivateKeys.size).toBe(5);
    });

    it('should produce 128-bit (16 byte) key parts', async () => {
      const options: CreateSecretOptions = {
        content: 'Test content',
      };

      const url = await createSecret(options, testConfig, mockFetch);

      // Extract and decode the public key part
      const { publicKeyPart } = parseSecretUrl(url);
      const publicKeyBytes = fromBase64url(publicKeyPart);
      expect(publicKeyBytes.length).toBe(16); // 128 bits

      // Decode the private key part
      expect(capturedRequest).not.toBeNull();
      const privateKeyBytes = fromBase64url(capturedRequest!.privateKeyPart);
      expect(privateKeyBytes.length).toBe(16); // 128 bits
    });
  });

  describe('Password Protection (Requirements 3.3, 3.4)', () => {
    it('should include passwordSalt in API request when password is provided', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
        password: 'mySecretPassword123',
      };

      await createSecret(options, testConfig, mockFetch);

      expect(capturedRequest).not.toBeNull();
      expect(capturedRequest!.passwordSalt).toBeDefined();
      expect(typeof capturedRequest!.passwordSalt).toBe('string');
      
      // Salt should be 16 bytes (128 bits) encoded as base64url (22 characters)
      const saltBytes = fromBase64url(capturedRequest!.passwordSalt!);
      expect(saltBytes.length).toBe(16);
    });

    it('should NOT include passwordSalt when no password is provided', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
      };

      await createSecret(options, testConfig, mockFetch);

      expect(capturedRequest).not.toBeNull();
      expect(capturedRequest!.passwordSalt).toBeUndefined();
    });

    it('should apply double encryption when password is provided (Requirement 3.3)', async () => {
      const secretContent = 'My secret message for double encryption test';
      const password = 'testPassword123';
      const options: CreateSecretOptions = {
        content: secretContent,
        password,
      };

      const url = await createSecret(options, testConfig, mockFetch);

      // Extract the public key part from the URL
      const { publicKeyPart } = parseSecretUrl(url);
      const publicKeyBytes = fromBase64url(publicKeyPart);

      // Get the private key part, encrypted blob, and salt from the request
      expect(capturedRequest).not.toBeNull();
      const privateKeyBytes = fromBase64url(capturedRequest!.privateKeyPart);
      const encryptedBlob = capturedRequest!.encryptedBlob;
      const salt = fromBase64url(capturedRequest!.passwordSalt!);

      // Reconstruct the combined key
      const combinedKey = combineKey(publicKeyBytes, privateKeyBytes);

      // Derive the password key
      const passwordDerivedKey = await deriveKey(password, salt);

      // First, decrypt with password-derived key (outer layer)
      const firstDecryption = await decrypt(encryptedBlob, passwordDerivedKey);
      
      // The first decryption should give us a JSON string of the inner encrypted payload
      const innerPayload: EncryptedPayload = JSON.parse(firstDecryption);
      expect(innerPayload).toHaveProperty('ciphertext');
      expect(innerPayload).toHaveProperty('iv');
      expect(innerPayload).toHaveProperty('tag');

      // Second, decrypt with combined key (inner layer)
      const finalDecryption = await decrypt(innerPayload, combinedKey);

      // Verify the decrypted content matches the original
      expect(finalDecryption).toBe(secretContent);
    });

    it('should fail decryption with wrong password', async () => {
      const secretContent = 'My secret message';
      const correctPassword = 'correctPassword123';
      const wrongPassword = 'wrongPassword456';
      
      const options: CreateSecretOptions = {
        content: secretContent,
        password: correctPassword,
      };

      await createSecret(options, testConfig, mockFetch);

      expect(capturedRequest).not.toBeNull();
      const encryptedBlob = capturedRequest!.encryptedBlob;
      const salt = fromBase64url(capturedRequest!.passwordSalt!);

      // Try to decrypt with wrong password
      const wrongPasswordKey = await deriveKey(wrongPassword, salt);

      // Decryption should fail with wrong password
      await expect(decrypt(encryptedBlob, wrongPasswordKey)).rejects.toThrow();
    });

    it('should generate different salts for each password-protected secret', async () => {
      const options: CreateSecretOptions = {
        content: 'Same content',
        password: 'samePassword',
      };

      const salts: string[] = [];
      for (let i = 0; i < 5; i++) {
        capturedRequest = null;
        await createSecret(options, testConfig, mockFetch);
        if (capturedRequest !== null) {
          salts.push((capturedRequest as CreateSecretApiRequest).passwordSalt!);
        }
      }

      // All salts should be different
      const uniqueSalts = new Set(salts);
      expect(uniqueSalts.size).toBe(5);
    });

    it('should handle empty password as no password protection', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
        password: '',
      };

      await createSecret(options, testConfig, mockFetch);

      expect(capturedRequest).not.toBeNull();
      // Empty password should not trigger password protection
      expect(capturedRequest!.passwordSalt).toBeUndefined();
    });

    it('should handle unicode passwords', async () => {
      const secretContent = 'My secret message';
      const unicodePassword = '密码🔐مرور';
      
      const options: CreateSecretOptions = {
        content: secretContent,
        password: unicodePassword,
      };

      const url = await createSecret(options, testConfig, mockFetch);

      // Extract keys and decrypt to verify it works
      const { publicKeyPart } = parseSecretUrl(url);
      const publicKeyBytes = fromBase64url(publicKeyPart);
      const privateKeyBytes = fromBase64url(capturedRequest!.privateKeyPart);
      const combinedKey = combineKey(publicKeyBytes, privateKeyBytes);
      const salt = fromBase64url(capturedRequest!.passwordSalt!);
      const passwordDerivedKey = await deriveKey(unicodePassword, salt);

      // Decrypt outer layer
      const firstDecryption = await decrypt(capturedRequest!.encryptedBlob, passwordDerivedKey);
      const innerPayload: EncryptedPayload = JSON.parse(firstDecryption);

      // Decrypt inner layer
      const finalDecryption = await decrypt(innerPayload, combinedKey);
      expect(finalDecryption).toBe(secretContent);
    });

    it('should handle long passwords', async () => {
      const secretContent = 'My secret message';
      const longPassword = 'a'.repeat(1000);
      
      const options: CreateSecretOptions = {
        content: secretContent,
        password: longPassword,
      };

      const url = await createSecret(options, testConfig, mockFetch);

      // Verify it works by decrypting
      const { publicKeyPart } = parseSecretUrl(url);
      const publicKeyBytes = fromBase64url(publicKeyPart);
      const privateKeyBytes = fromBase64url(capturedRequest!.privateKeyPart);
      const combinedKey = combineKey(publicKeyBytes, privateKeyBytes);
      const salt = fromBase64url(capturedRequest!.passwordSalt!);
      const passwordDerivedKey = await deriveKey(longPassword, salt);

      const firstDecryption = await decrypt(capturedRequest!.encryptedBlob, passwordDerivedKey);
      const innerPayload: EncryptedPayload = JSON.parse(firstDecryption);
      const finalDecryption = await decrypt(innerPayload, combinedKey);
      
      expect(finalDecryption).toBe(secretContent);
    });

    it('should include all optional fields with password protection', async () => {
      const options: CreateSecretOptions = {
        content: 'My secret message',
        password: 'myPassword',
        expiresIn: '24h',
        notifyEmail: 'test@example.com',
      };

      await createSecret(options, testConfig, mockFetch);

      expect(capturedRequest).not.toBeNull();
      expect(capturedRequest!.passwordSalt).toBeDefined();
      expect(capturedRequest!.expiresIn).toBe('24h');
      expect(capturedRequest!.notifyEmail).toBe('test@example.com');
    });
  });

});
