/**
 * Unit tests for SecretViewer module
 * 
 * Tests verify:
 * - Secret ID and public key part extraction from URL
 * - API request to fetch encrypted data
 * - Key combination and decryption
 * - Password-protected secret handling
 * - Error handling for various failure scenarios
 * 
 * Requirements:
 * - 2.1: Extract the Secret_ID from the URL path and the Public_Key_Part from the URL_Fragment
 * - 2.2: Request the Encrypted_Blob and Private_Key_Part from the Backend_API using the Secret_ID
 * - 2.5: Combine the Public_Key_Part and Private_Key_Part to reconstruct the Combined_Key
 * - 2.6: Decrypt the Encrypted_Blob using AES-256-GCM with the Combined_Key
 * - 2.7: Display the decrypted secret content to the user
 * - 2.9: Display an appropriate error message if the secret has already been viewed or does not exist
 * - 3.5: When viewing a password-protected secret, prompt for the password and derive the key using the stored salt
 * - 3.6: Allow the user to retry with a different password if decryption fails, without consuming the one-time access
 */

import { describe, it, expect, vi } from 'vitest';
import {
  viewSecret,
  viewSecretById,
  extractSecretInfoFromUrl,
  fetchSecretFromApi,
  decryptSecret,
  decryptWithPassword,
  createSecretViewer,
  getErrorMessage,
  SecretViewError,
  DEFAULT_CONFIG,
  type SecretViewerConfig,
  type ViewSecretPasswordRequired,
} from '../../src/frontend/secret-viewer';
import { generateKey, splitKey } from '../../src/shared/crypto/key-generator';
import { encrypt, type EncryptedPayload } from '../../src/shared/crypto/encryptor';
import { generateSalt, deriveKey } from '../../src/shared/crypto/password-deriver';
import { toBase64url } from '../../src/shared/encoding';
import { buildSecretUrl } from '../../src/shared/url-utils';

describe('SecretViewer', () => {
  const testConfig: SecretViewerConfig = {
    baseUrl: 'https://example.com',
    apiEndpoint: '/api/secrets',
  };

  // Helper to create a valid secret for testing
  async function createTestSecret(content: string): Promise<{
    url: string;
    secretId: string;
    publicKeyPart: string;
    privateKeyPart: string;
    encryptedBlob: EncryptedPayload;
  }> {
    const key = await generateKey();
    const { publicPart, privatePart } = splitKey(key);
    const encryptedBlob = await encrypt(content, key);
    const secretId = 'abc123def456gh78';
    const publicKeyPart = toBase64url(publicPart);
    const privateKeyPart = toBase64url(privatePart);
    const url = buildSecretUrl({
      baseUrl: testConfig.baseUrl,
      secretId,
      publicKeyPart,
    });

    return {
      url,
      secretId,
      publicKeyPart,
      privateKeyPart,
      encryptedBlob,
    };
  }

  // Helper to create a password-protected secret for testing
  async function createPasswordProtectedTestSecret(content: string, password: string): Promise<{
    url: string;
    secretId: string;
    publicKeyPart: string;
    privateKeyPart: string;
    encryptedBlob: EncryptedPayload;
    passwordSalt: string;
  }> {
    // Step 1: Generate key and encrypt with combined key (inner layer)
    const key = await generateKey();
    const { publicPart, privatePart } = splitKey(key);
    const innerEncryptedBlob = await encrypt(content, key);

    // Step 2: Generate salt and derive password key
    const salt = generateSalt();
    const passwordDerivedKey = await deriveKey(password, salt);

    // Step 3: Encrypt the inner blob with password-derived key (outer layer)
    const innerJson = JSON.stringify(innerEncryptedBlob);
    const outerEncryptedBlob = await encrypt(innerJson, passwordDerivedKey);

    const secretId = 'abc123def456gh78';
    const publicKeyPart = toBase64url(publicPart);
    const privateKeyPart = toBase64url(privatePart);
    const passwordSalt = toBase64url(salt);
    const url = buildSecretUrl({
      baseUrl: testConfig.baseUrl,
      secretId,
      publicKeyPart,
    });

    return {
      url,
      secretId,
      publicKeyPart,
      privateKeyPart,
      encryptedBlob: outerEncryptedBlob,
      passwordSalt,
    };
  }

  describe('extractSecretInfoFromUrl', () => {
    it('should extract secret ID and public key part from valid URL', async () => {
      const testSecret = await createTestSecret('test content');
      
      const result = extractSecretInfoFromUrl(testSecret.url);
      
      expect(result.secretId).toBe(testSecret.secretId);
      expect(result.publicKeyPart).toBe(testSecret.publicKeyPart);
    });

    it('should throw SecretViewError for invalid URL format', () => {
      expect(() => extractSecretInfoFromUrl('not-a-url')).toThrow(SecretViewError);
      expect(() => extractSecretInfoFromUrl('not-a-url')).toThrow('Invalid secret link format.');
    });

    it('should throw SecretViewError for URL without fragment', () => {
      expect(() => extractSecretInfoFromUrl('https://example.com/s/abc123def456gh78')).toThrow(SecretViewError);
    });

    it('should throw SecretViewError for URL with invalid secret ID', () => {
      expect(() => extractSecretInfoFromUrl('https://example.com/s/short#AAAAAAAAAAAAAAAAAAAAAA')).toThrow(SecretViewError);
    });

    it('should throw SecretViewError for URL with invalid public key part', () => {
      expect(() => extractSecretInfoFromUrl('https://example.com/s/abc123def456gh78#short')).toThrow(SecretViewError);
    });
  });

  describe('fetchSecretFromApi', () => {
    it('should fetch secret data from API successfully', async () => {
      const testSecret = await createTestSecret('test content');
      
      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob: testSecret.encryptedBlob,
          privateKeyPart: testSecret.privateKeyPart,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const result = await fetchSecretFromApi(testSecret.secretId, testConfig, mockFetch);

      expect(result.encryptedBlob).toEqual(testSecret.encryptedBlob);
      expect(result.privateKeyPart).toBe(testSecret.privateKeyPart);
      expect(mockFetch).toHaveBeenCalledWith(
        `${testConfig.baseUrl}${testConfig.apiEndpoint}/${testSecret.secretId}`,
        expect.objectContaining({
          method: 'GET',
          headers: { 'Accept': 'application/json' },
        })
      );
    });

    it('should throw SECRET_NOT_FOUND error for 404 response', async () => {
      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({ error: 'Not found', code: 'NOT_FOUND' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      await expect(fetchSecretFromApi('abc123def456gh78', testConfig, mockFetch))
        .rejects.toThrow(SecretViewError);
      
      try {
        await fetchSecretFromApi('abc123def456gh78', testConfig, mockFetch);
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('SECRET_NOT_FOUND');
        expect((error as SecretViewError).message).toContain('already been viewed or has expired');
      }
    });

    it('should throw SECRET_ALREADY_VIEWED error for 410 response', async () => {
      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({ error: 'Gone', code: 'GONE' }), {
          status: 410,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      try {
        await fetchSecretFromApi('abc123def456gh78', testConfig, mockFetch);
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('SECRET_ALREADY_VIEWED');
      }
    });

    it('should throw NETWORK_ERROR for network failures', async () => {
      const mockFetch = vi.fn(async () => {
        throw new Error('Network error');
      }) as typeof fetch;

      try {
        await fetchSecretFromApi('abc123def456gh78', testConfig, mockFetch);
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('NETWORK_ERROR');
      }
    });

    it('should throw INVALID_RESPONSE for invalid JSON response', async () => {
      const mockFetch = vi.fn(async () => {
        return new Response('not json', {
          status: 200,
          headers: { 'Content-Type': 'text/plain' },
        });
      }) as typeof fetch;

      try {
        await fetchSecretFromApi('abc123def456gh78', testConfig, mockFetch);
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('INVALID_RESPONSE');
      }
    });

    it('should throw INVALID_RESPONSE for missing required fields', async () => {
      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({ encryptedBlob: {} }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      try {
        await fetchSecretFromApi('abc123def456gh78', testConfig, mockFetch);
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('INVALID_RESPONSE');
      }
    });

    it('should include passwordSalt in response when present', async () => {
      const testSecret = await createTestSecret('test content');
      const passwordSalt = 'somesaltvalue123';
      
      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob: testSecret.encryptedBlob,
          privateKeyPart: testSecret.privateKeyPart,
          passwordSalt,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const result = await fetchSecretFromApi(testSecret.secretId, testConfig, mockFetch);

      expect(result.passwordSalt).toBe(passwordSalt);
    });
  });

  describe('decryptSecret', () => {
    it('should decrypt secret content successfully', async () => {
      const originalContent = 'My secret message';
      const testSecret = await createTestSecret(originalContent);

      const decrypted = await decryptSecret(
        testSecret.encryptedBlob,
        testSecret.publicKeyPart,
        testSecret.privateKeyPart
      );

      expect(decrypted).toBe(originalContent);
    });

    it('should decrypt empty string content', async () => {
      const testSecret = await createTestSecret('');

      const decrypted = await decryptSecret(
        testSecret.encryptedBlob,
        testSecret.publicKeyPart,
        testSecret.privateKeyPart
      );

      expect(decrypted).toBe('');
    });

    it('should decrypt unicode content', async () => {
      const originalContent = '你好世界 🌍 مرحبا';
      const testSecret = await createTestSecret(originalContent);

      const decrypted = await decryptSecret(
        testSecret.encryptedBlob,
        testSecret.publicKeyPart,
        testSecret.privateKeyPart
      );

      expect(decrypted).toBe(originalContent);
    });

    it('should decrypt large content', async () => {
      const originalContent = 'x'.repeat(100000);
      const testSecret = await createTestSecret(originalContent);

      const decrypted = await decryptSecret(
        testSecret.encryptedBlob,
        testSecret.publicKeyPart,
        testSecret.privateKeyPart
      );

      expect(decrypted).toBe(originalContent);
    });

    it('should throw INVALID_URL error for invalid public key part', async () => {
      const testSecret = await createTestSecret('test');

      try {
        await decryptSecret(
          testSecret.encryptedBlob,
          'invalid!!!key',
          testSecret.privateKeyPart
        );
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('INVALID_URL');
      }
    });

    it('should throw INVALID_RESPONSE error for invalid private key part', async () => {
      const testSecret = await createTestSecret('test');

      try {
        await decryptSecret(
          testSecret.encryptedBlob,
          testSecret.publicKeyPart,
          'invalid!!!key'
        );
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('INVALID_RESPONSE');
      }
    });

    it('should throw DECRYPTION_FAILED error for wrong key', async () => {
      const testSecret = await createTestSecret('test');
      
      // Generate a different key
      const wrongKey = await generateKey();
      const { publicPart: wrongPublicPart } = splitKey(wrongKey);
      const wrongPublicKeyPart = toBase64url(wrongPublicPart);

      try {
        await decryptSecret(
          testSecret.encryptedBlob,
          wrongPublicKeyPart,
          testSecret.privateKeyPart
        );
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('DECRYPTION_FAILED');
      }
    });

    it('should throw DECRYPTION_FAILED error for swapped key parts', async () => {
      const testSecret = await createTestSecret('test');

      // Swap public and private key parts
      try {
        await decryptSecret(
          testSecret.encryptedBlob,
          testSecret.privateKeyPart,
          testSecret.publicKeyPart
        );
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('DECRYPTION_FAILED');
      }
    });
  });

  describe('viewSecret', () => {
    it('should view and decrypt a secret successfully', async () => {
      const originalContent = 'My secret message';
      const testSecret = await createTestSecret(originalContent);

      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob: testSecret.encryptedBlob,
          privateKeyPart: testSecret.privateKeyPart,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const result = await viewSecret(testSecret.url, testConfig, mockFetch);

      expect(result.status).toBe('success');
      if (result.status === 'success') {
        expect(result.content).toBe(originalContent);
        expect(result.isPasswordProtected).toBe(false);
      }
    });

    it('should return password_required for password-protected secrets', async () => {
      const testSecret = await createPasswordProtectedTestSecret('test', 'mypassword');

      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob: testSecret.encryptedBlob,
          privateKeyPart: testSecret.privateKeyPart,
          passwordSalt: testSecret.passwordSalt,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const result = await viewSecret(testSecret.url, testConfig, mockFetch);

      expect(result.status).toBe('password_required');
      if (result.status === 'password_required') {
        expect(result.passwordSalt).toBe(testSecret.passwordSalt);
        expect(result.encryptedBlob).toEqual(testSecret.encryptedBlob);
        expect(result.privateKeyPart).toBe(testSecret.privateKeyPart);
        expect(result.publicKeyPart).toBe(testSecret.publicKeyPart);
      }
    });

    it('should propagate URL parsing errors', async () => {
      const mockFetch = vi.fn() as typeof fetch;

      await expect(viewSecret('invalid-url', testConfig, mockFetch))
        .rejects.toThrow(SecretViewError);
    });

    it('should propagate API errors', async () => {
      const testSecret = await createTestSecret('test');

      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({ error: 'Not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      try {
        await viewSecret(testSecret.url, testConfig, mockFetch);
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('SECRET_NOT_FOUND');
      }
    });
  });

  describe('viewSecretById', () => {
    it('should view and decrypt a secret by ID successfully', async () => {
      const originalContent = 'My secret message';
      const testSecret = await createTestSecret(originalContent);

      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob: testSecret.encryptedBlob,
          privateKeyPart: testSecret.privateKeyPart,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const result = await viewSecretById(
        testSecret.secretId,
        testSecret.publicKeyPart,
        testConfig,
        mockFetch
      );

      expect(result.status).toBe('success');
      if (result.status === 'success') {
        expect(result.content).toBe(originalContent);
        expect(result.isPasswordProtected).toBe(false);
      }
    });

    it('should return password_required for password-protected secrets', async () => {
      const testSecret = await createPasswordProtectedTestSecret('test', 'mypassword');

      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob: testSecret.encryptedBlob,
          privateKeyPart: testSecret.privateKeyPart,
          passwordSalt: testSecret.passwordSalt,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const result = await viewSecretById(testSecret.secretId, testSecret.publicKeyPart, testConfig, mockFetch);

      expect(result.status).toBe('password_required');
      if (result.status === 'password_required') {
        expect(result.passwordSalt).toBe(testSecret.passwordSalt);
      }
    });
  });

  describe('decryptWithPassword', () => {
    it('should decrypt a password-protected secret with correct password', async () => {
      const originalContent = 'My secret password-protected message';
      const password = 'correctPassword123';
      const testSecret = await createPasswordProtectedTestSecret(originalContent, password);

      const passwordRequiredResult: ViewSecretPasswordRequired = {
        status: 'password_required',
        passwordSalt: testSecret.passwordSalt,
        encryptedBlob: testSecret.encryptedBlob,
        privateKeyPart: testSecret.privateKeyPart,
        publicKeyPart: testSecret.publicKeyPart,
      };

      const result = await decryptWithPassword(passwordRequiredResult, password);

      expect(result.status).toBe('success');
      expect(result.content).toBe(originalContent);
      expect(result.isPasswordProtected).toBe(true);
    });

    it('should throw WRONG_PASSWORD error for incorrect password', async () => {
      const originalContent = 'My secret message';
      const correctPassword = 'correctPassword123';
      const wrongPassword = 'wrongPassword456';
      const testSecret = await createPasswordProtectedTestSecret(originalContent, correctPassword);

      const passwordRequiredResult: ViewSecretPasswordRequired = {
        status: 'password_required',
        passwordSalt: testSecret.passwordSalt,
        encryptedBlob: testSecret.encryptedBlob,
        privateKeyPart: testSecret.privateKeyPart,
        publicKeyPart: testSecret.publicKeyPart,
      };

      try {
        await decryptWithPassword(passwordRequiredResult, wrongPassword);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('WRONG_PASSWORD');
        expect((error as SecretViewError).message).toContain('Incorrect password');
      }
    });

    it('should decrypt unicode content with password protection', async () => {
      const originalContent = '你好世界 🌍 مرحبا - Password Protected!';
      const password = 'unicodePassword🔐';
      const testSecret = await createPasswordProtectedTestSecret(originalContent, password);

      const passwordRequiredResult: ViewSecretPasswordRequired = {
        status: 'password_required',
        passwordSalt: testSecret.passwordSalt,
        encryptedBlob: testSecret.encryptedBlob,
        privateKeyPart: testSecret.privateKeyPart,
        publicKeyPart: testSecret.publicKeyPart,
      };

      const result = await decryptWithPassword(passwordRequiredResult, password);

      expect(result.status).toBe('success');
      expect(result.content).toBe(originalContent);
    });

    it('should decrypt empty string content with password protection', async () => {
      const originalContent = '';
      const password = 'emptyContentPassword';
      const testSecret = await createPasswordProtectedTestSecret(originalContent, password);

      const passwordRequiredResult: ViewSecretPasswordRequired = {
        status: 'password_required',
        passwordSalt: testSecret.passwordSalt,
        encryptedBlob: testSecret.encryptedBlob,
        privateKeyPart: testSecret.privateKeyPart,
        publicKeyPart: testSecret.publicKeyPart,
      };

      const result = await decryptWithPassword(passwordRequiredResult, password);

      expect(result.status).toBe('success');
      expect(result.content).toBe('');
    });

    it('should allow retry with correct password after wrong password attempt', async () => {
      const originalContent = 'Retry test content';
      const correctPassword = 'correctPassword';
      const wrongPassword = 'wrongPassword';
      const testSecret = await createPasswordProtectedTestSecret(originalContent, correctPassword);

      const passwordRequiredResult: ViewSecretPasswordRequired = {
        status: 'password_required',
        passwordSalt: testSecret.passwordSalt,
        encryptedBlob: testSecret.encryptedBlob,
        privateKeyPart: testSecret.privateKeyPart,
        publicKeyPart: testSecret.publicKeyPart,
      };

      // First attempt with wrong password should fail
      try {
        await decryptWithPassword(passwordRequiredResult, wrongPassword);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect((error as SecretViewError).type).toBe('WRONG_PASSWORD');
      }

      // Second attempt with correct password should succeed (Requirement 3.6)
      const result = await decryptWithPassword(passwordRequiredResult, correctPassword);
      expect(result.status).toBe('success');
      expect(result.content).toBe(originalContent);
    });

    it('should throw INVALID_RESPONSE for invalid password salt', async () => {
      const passwordRequiredResult: ViewSecretPasswordRequired = {
        status: 'password_required',
        passwordSalt: 'invalid!!!salt',
        encryptedBlob: { ciphertext: 'test', iv: 'test', tag: 'test' },
        privateKeyPart: 'AAAAAAAAAAAAAAAAAAAAAA',
        publicKeyPart: 'AAAAAAAAAAAAAAAAAAAAAA',
      };

      try {
        await decryptWithPassword(passwordRequiredResult, 'anypassword');
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(SecretViewError);
        expect((error as SecretViewError).type).toBe('INVALID_RESPONSE');
      }
    });
  });

  describe('getErrorMessage', () => {
    it('should return message from SecretViewError', () => {
      const error = new SecretViewError('Custom error message', 'NETWORK_ERROR');
      expect(getErrorMessage(error)).toBe('Custom error message');
    });

    it('should return message from generic Error', () => {
      const error = new Error('Generic error');
      expect(getErrorMessage(error)).toBe('An unexpected error occurred: Generic error');
    });

    it('should return default message for non-Error values', () => {
      expect(getErrorMessage('string error')).toBe('An unexpected error occurred. Please try again.');
      expect(getErrorMessage(null)).toBe('An unexpected error occurred. Please try again.');
      expect(getErrorMessage(undefined)).toBe('An unexpected error occurred. Please try again.');
    });
  });

  describe('createSecretViewer factory', () => {
    it('should create a SecretViewer instance', async () => {
      const originalContent = 'Test content';
      const testSecret = await createTestSecret(originalContent);

      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob: testSecret.encryptedBlob,
          privateKeyPart: testSecret.privateKeyPart,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const viewer = createSecretViewer(testConfig, mockFetch);

      const result = await viewer.viewSecret(testSecret.url);
      expect(result.status).toBe('success');
      if (result.status === 'success') {
        expect(result.content).toBe(originalContent);
      }
    });

    it('should support viewSecretById method', async () => {
      const originalContent = 'Test content';
      const testSecret = await createTestSecret(originalContent);

      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob: testSecret.encryptedBlob,
          privateKeyPart: testSecret.privateKeyPart,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const viewer = createSecretViewer(testConfig, mockFetch);

      const result = await viewer.viewSecretById(testSecret.secretId, testSecret.publicKeyPart);
      expect(result.status).toBe('success');
      if (result.status === 'success') {
        expect(result.content).toBe(originalContent);
      }
    });

    it('should support decryptWithPassword method', async () => {
      const originalContent = 'Password protected content';
      const password = 'testPassword';
      const testSecret = await createPasswordProtectedTestSecret(originalContent, password);

      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob: testSecret.encryptedBlob,
          privateKeyPart: testSecret.privateKeyPart,
          passwordSalt: testSecret.passwordSalt,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const viewer = createSecretViewer(testConfig, mockFetch);

      // First get the password-required result
      const viewResult = await viewer.viewSecret(testSecret.url);
      expect(viewResult.status).toBe('password_required');

      if (viewResult.status === 'password_required') {
        // Then decrypt with password
        const decryptResult = await viewer.decryptWithPassword(viewResult, password);
        expect(decryptResult.status).toBe('success');
        expect(decryptResult.content).toBe(originalContent);
        expect(decryptResult.isPasswordProtected).toBe(true);
      }
    });
  });

  describe('DEFAULT_CONFIG', () => {
    it('should have sensible default values', () => {
      expect(DEFAULT_CONFIG.apiEndpoint).toBe('/api/secrets');
      expect(typeof DEFAULT_CONFIG.baseUrl).toBe('string');
    });
  });

  describe('SecretViewError', () => {
    it('should have correct name and properties', () => {
      const cause = new Error('Original error');
      const error = new SecretViewError('Test message', 'NETWORK_ERROR', cause);

      expect(error.name).toBe('SecretViewError');
      expect(error.message).toBe('Test message');
      expect(error.type).toBe('NETWORK_ERROR');
      expect(error.cause).toBe(cause);
    });

    it('should work without cause', () => {
      const error = new SecretViewError('Test message', 'INVALID_URL');

      expect(error.name).toBe('SecretViewError');
      expect(error.message).toBe('Test message');
      expect(error.type).toBe('INVALID_URL');
      expect(error.cause).toBeUndefined();
    });
  });

  describe('End-to-End Integration', () => {
    it('should successfully decrypt a secret created with SecretCreator flow', async () => {
      // Simulate the full flow: create -> store -> retrieve -> decrypt
      const originalContent = 'This is a secret message for end-to-end test';
      
      // Step 1: Generate key and encrypt (like SecretCreator does)
      const key = await generateKey();
      const { publicPart, privatePart } = splitKey(key);
      const encryptedBlob = await encrypt(originalContent, key);
      
      // Step 2: Encode key parts (like SecretCreator does)
      const publicKeyPart = toBase64url(publicPart);
      const privateKeyPart = toBase64url(privatePart);
      
      // Step 3: Build URL (like SecretCreator does)
      const secretId = 'test1234abcd5678';
      const url = buildSecretUrl({
        baseUrl: testConfig.baseUrl,
        secretId,
        publicKeyPart,
      });
      
      // Step 4: Mock API response (like Backend would return)
      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob,
          privateKeyPart,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;
      
      // Step 5: View the secret (like SecretViewer does)
      const result = await viewSecret(url, testConfig, mockFetch);
      
      // Verify the decrypted content matches the original
      expect(result.status).toBe('success');
      if (result.status === 'success') {
        expect(result.content).toBe(originalContent);
        expect(result.isPasswordProtected).toBe(false);
      }
    });

    it('should fail to decrypt with wrong public key part', async () => {
      const originalContent = 'Secret content';
      
      // Create a secret
      const key = await generateKey();
      const { privatePart } = splitKey(key);
      const encryptedBlob = await encrypt(originalContent, key);
      const privateKeyPart = toBase64url(privatePart);
      
      // Generate a DIFFERENT key for the URL (simulating a tampered URL)
      const wrongKey = await generateKey();
      const { publicPart: wrongPublicPart } = splitKey(wrongKey);
      const wrongPublicKeyPart = toBase64url(wrongPublicPart);
      
      // Build URL with wrong public key
      const secretId = 'test1234abcd5678';
      const url = buildSecretUrl({
        baseUrl: testConfig.baseUrl,
        secretId,
        publicKeyPart: wrongPublicKeyPart,
      });
      
      // Mock API returns the correct private key part
      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob,
          privateKeyPart,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;
      
      // Attempt to view should fail
      await expect(viewSecret(url, testConfig, mockFetch))
        .rejects.toThrow(SecretViewError);
    });

    it('should successfully decrypt a password-protected secret end-to-end', async () => {
      // Simulate the full flow for password-protected secrets
      const originalContent = 'This is a password-protected secret';
      const password = 'mySecretPassword123';
      
      // Step 1: Generate key and encrypt with combined key (inner layer)
      const key = await generateKey();
      const { publicPart, privatePart } = splitKey(key);
      const innerEncryptedBlob = await encrypt(originalContent, key);
      
      // Step 2: Generate salt and derive password key
      const salt = generateSalt();
      const passwordDerivedKey = await deriveKey(password, salt);
      
      // Step 3: Encrypt the inner blob with password-derived key (outer layer)
      const innerJson = JSON.stringify(innerEncryptedBlob);
      const outerEncryptedBlob = await encrypt(innerJson, passwordDerivedKey);
      
      // Step 4: Encode key parts
      const publicKeyPart = toBase64url(publicPart);
      const privateKeyPart = toBase64url(privatePart);
      const passwordSalt = toBase64url(salt);
      
      // Step 5: Build URL
      const secretId = 'test1234abcd5678';
      const url = buildSecretUrl({
        baseUrl: testConfig.baseUrl,
        secretId,
        publicKeyPart,
      });
      
      // Step 6: Mock API response with password salt
      const mockFetch = vi.fn(async () => {
        return new Response(JSON.stringify({
          encryptedBlob: outerEncryptedBlob,
          privateKeyPart,
          passwordSalt,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;
      
      // Step 7: View the secret - should return password_required
      const viewResult = await viewSecret(url, testConfig, mockFetch);
      expect(viewResult.status).toBe('password_required');
      
      if (viewResult.status === 'password_required') {
        // Step 8: Decrypt with password
        const decryptResult = await decryptWithPassword(viewResult, password);
        
        expect(decryptResult.status).toBe('success');
        expect(decryptResult.content).toBe(originalContent);
        expect(decryptResult.isPasswordProtected).toBe(true);
      }
    });
  });
});
