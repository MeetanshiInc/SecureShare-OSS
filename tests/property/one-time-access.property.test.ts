/**
 * Property-Based Tests for One-Time Access Guarantee
 * 
 * **Validates: Requirements 2.3, 2.4, 2.8**
 * 
 * Property 5: One-Time Access Guarantee
 * For any stored secret, after the first successful retrieval, all subsequent
 * retrieval attempts should return a not-found response. The secret data should
 * be completely removed from storage after first access.
 * 
 * Requirements context:
 * - 2.3: Return the Encrypted_Blob and Private_Key_Part exactly once
 * - 2.4: Immediately delete the secret from Secret_Store after retrieval
 * - 2.8: If the secret has already been viewed or does not exist, return a not-found response
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as fc from 'fast-check';
import {
  handleCreateSecret,
  handleGetSecret,
  type CreateSecretResponse,
  type GetSecretResponse,
  type ErrorResponse,
} from '../../src/worker/handlers';
import type { SecretStore, StoredSecret } from '../../src/worker/secret-store';
import type { EncryptedPayload } from '../../src/shared/crypto/encryptor';

/**
 * Creates a mock SecretStore for testing that simulates Cloudflare KV behavior.
 * The store implements atomic get-and-delete semantics.
 */
function createMockSecretStore(): SecretStore & {
  storedSecrets: Map<string, StoredSecret>;
} {
  const storedSecrets = new Map<string, StoredSecret>();
  
  return {
    storedSecrets,
    async store(secretId: string, data: StoredSecret, _ttlSeconds?: number): Promise<void> {
      storedSecrets.set(secretId, data);
    },
    async getAndDelete(secretId: string): Promise<StoredSecret | null> {
      const secret = storedSecrets.get(secretId);
      if (secret) {
        storedSecrets.delete(secretId);
        return secret;
      }
      return null;
    },
  };
}

/**
 * Arbitrary generator for valid encrypted payloads.
 * Generates base64-like strings for ciphertext, iv, and tag.
 */
const encryptedPayloadArbitrary: fc.Arbitrary<EncryptedPayload> = fc.record({
  ciphertext: fc.base64String({ minLength: 0, maxLength: 200 }),
  iv: fc.base64String({ minLength: 12, maxLength: 24 }),
  tag: fc.base64String({ minLength: 16, maxLength: 32 }),
});

/**
 * Arbitrary generator for valid private key parts (base64url-encoded 128-bit keys).
 */
const privateKeyPartArbitrary: fc.Arbitrary<string> = fc.base64String({ minLength: 16, maxLength: 32 });

/**
 * Arbitrary generator for optional password salt.
 */
const passwordSaltArbitrary: fc.Arbitrary<string | undefined> = fc.option(
  fc.base64String({ minLength: 16, maxLength: 24 }),
  { nil: undefined }
);

/**
 * Arbitrary generator for optional notification email.
 */
const notifyEmailArbitrary: fc.Arbitrary<string | undefined> = fc.option(
  fc.emailAddress(),
  { nil: undefined }
);

/**
 * Arbitrary generator for expiration options.
 */
const expiresInArbitrary: fc.Arbitrary<'1h' | '24h' | '7d' | '30d' | undefined> = fc.oneof(
  fc.constant(undefined),
  fc.constant('1h' as const),
  fc.constant('24h' as const),
  fc.constant('7d' as const),
  fc.constant('30d' as const)
);

/**
 * Creates a Request object with JSON body for creating a secret.
 */
function createSecretRequest(
  encryptedBlob: EncryptedPayload,
  privateKeyPart: string,
  options?: {
    expiresIn?: '1h' | '24h' | '7d' | '30d';
    notifyEmail?: string;
    passwordSalt?: string;
  }
): Request {
  const body = {
    encryptedBlob,
    privateKeyPart,
    ...options,
  };
  
  return new Request('https://example.com/api/secrets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/**
 * Parses a Response body as JSON.
 */
async function parseJsonResponse<T>(response: Response): Promise<T> {
  return response.json() as Promise<T>;
}

describe('Property 5: One-Time Access Guarantee', () => {
  let mockStore: ReturnType<typeof createMockSecretStore>;
  
  beforeEach(() => {
    mockStore = createMockSecretStore();
  });

  /**
   * **Validates: Requirements 2.3, 2.4, 2.8**
   * 
   * Property: For any stored secret, the first retrieval should succeed and
   * return the correct data, while all subsequent retrieval attempts should
   * return a not-found response.
   */
  it('first retrieval succeeds, all subsequent retrievals return not-found', async () => {
    await fc.assert(
      fc.asyncProperty(
        encryptedPayloadArbitrary,
        privateKeyPartArbitrary,
        // Number of subsequent retrieval attempts (1-10)
        fc.integer({ min: 1, max: 10 }),
        async (encryptedBlob, privateKeyPart, numSubsequentAttempts) => {
          // Create a fresh store for each test case
          const store = createMockSecretStore();
          
          // Step 1: Create a secret
          const createRequest = createSecretRequest(encryptedBlob, privateKeyPart);
          const createResponse = await handleCreateSecret(createRequest, store);
          
          expect(createResponse.status).toBe(201);
          const { secretId } = await parseJsonResponse<CreateSecretResponse>(createResponse);
          
          // Step 2: First retrieval should succeed (Req 2.3)
          const firstResponse = await handleGetSecret(secretId, store);
          expect(firstResponse.status).toBe(200);
          
          const firstBody = await parseJsonResponse<GetSecretResponse>(firstResponse);
          expect(firstBody.encryptedBlob).toEqual(encryptedBlob);
          expect(firstBody.privateKeyPart).toBe(privateKeyPart);
          
          // Step 3: All subsequent retrievals should return not-found (Req 2.4, 2.8)
          for (let i = 0; i < numSubsequentAttempts; i++) {
            const subsequentResponse = await handleGetSecret(secretId, store);
            expect(subsequentResponse.status).toBe(404);
            
            const errorBody = await parseJsonResponse<ErrorResponse>(subsequentResponse);
            expect(errorBody.code).toBe('NOT_FOUND');
          }
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 2.4**
   * 
   * Property: After the first successful retrieval, the secret data should be
   * completely removed from storage. The storage should not contain any trace
   * of the secret.
   */
  it('secret is completely removed from storage after first access', async () => {
    await fc.assert(
      fc.asyncProperty(
        encryptedPayloadArbitrary,
        privateKeyPartArbitrary,
        passwordSaltArbitrary,
        notifyEmailArbitrary,
        async (encryptedBlob, privateKeyPart, passwordSalt, notifyEmail) => {
          // Create a fresh store for each test case
          const store = createMockSecretStore();
          
          // Create a secret with optional fields
          const options: { passwordSalt?: string; notifyEmail?: string } = {};
          if (passwordSalt !== undefined) options.passwordSalt = passwordSalt;
          if (notifyEmail !== undefined) options.notifyEmail = notifyEmail;
          
          const createRequest = createSecretRequest(encryptedBlob, privateKeyPart, options);
          const createResponse = await handleCreateSecret(createRequest, store);
          
          expect(createResponse.status).toBe(201);
          const { secretId } = await parseJsonResponse<CreateSecretResponse>(createResponse);
          
          // Verify secret exists in storage before retrieval
          expect(store.storedSecrets.has(secretId)).toBe(true);
          
          // Retrieve the secret
          const getResponse = await handleGetSecret(secretId, store);
          expect(getResponse.status).toBe(200);
          
          // Verify secret is completely removed from storage (Req 2.4)
          expect(store.storedSecrets.has(secretId)).toBe(false);
          expect(store.storedSecrets.size).toBe(0);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 2.3, 2.8**
   * 
   * Property: Multiple secrets can be created and each can only be accessed
   * exactly once. Accessing one secret should not affect other secrets.
   */
  it('multiple secrets each have independent one-time access', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate 2-5 secrets
        fc.array(
          fc.record({
            encryptedBlob: encryptedPayloadArbitrary,
            privateKeyPart: privateKeyPartArbitrary,
          }),
          { minLength: 2, maxLength: 5 }
        ),
        async (secrets) => {
          // Create a fresh store for each test case
          const store = createMockSecretStore();
          
          // Create all secrets and collect their IDs
          const secretIds: string[] = [];
          for (const secret of secrets) {
            const createRequest = createSecretRequest(secret.encryptedBlob, secret.privateKeyPart);
            const createResponse = await handleCreateSecret(createRequest, store);
            expect(createResponse.status).toBe(201);
            
            const { secretId } = await parseJsonResponse<CreateSecretResponse>(createResponse);
            secretIds.push(secretId);
          }
          
          // Verify all secrets are stored
          expect(store.storedSecrets.size).toBe(secrets.length);
          
          // Access each secret once - should succeed
          for (let i = 0; i < secrets.length; i++) {
            const secretId = secretIds[i]!;
            const secret = secrets[i]!;
            
            const getResponse = await handleGetSecret(secretId, store);
            expect(getResponse.status).toBe(200);
            
            const body = await parseJsonResponse<GetSecretResponse>(getResponse);
            expect(body.encryptedBlob).toEqual(secret.encryptedBlob);
            expect(body.privateKeyPart).toBe(secret.privateKeyPart);
          }
          
          // All secrets should now be deleted
          expect(store.storedSecrets.size).toBe(0);
          
          // Second access to any secret should fail
          for (const secretId of secretIds) {
            const getResponse = await handleGetSecret(secretId, store);
            expect(getResponse.status).toBe(404);
          }
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 2.8**
   * 
   * Property: Attempting to retrieve a non-existent secret should return
   * a not-found response, indistinguishable from an already-viewed secret.
   */
  it('non-existent secrets return not-found response', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate random 16-character alphanumeric IDs
        fc.stringOf(
          fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'),
          { minLength: 16, maxLength: 16 }
        ),
        async (randomSecretId) => {
          // Create a fresh store for each test case
          const store = createMockSecretStore();
          
          // Attempt to retrieve a non-existent secret
          const getResponse = await handleGetSecret(randomSecretId, store);
          
          // Should return 404 NOT_FOUND (Req 2.8)
          expect(getResponse.status).toBe(404);
          
          const errorBody = await parseJsonResponse<ErrorResponse>(getResponse);
          expect(errorBody.code).toBe('NOT_FOUND');
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 2.3, 2.4, 2.8**
   * 
   * Property: The one-time access guarantee holds regardless of the secret's
   * optional fields (password salt, notification email, expiration).
   */
  it('one-time access holds with all optional fields', async () => {
    await fc.assert(
      fc.asyncProperty(
        encryptedPayloadArbitrary,
        privateKeyPartArbitrary,
        passwordSaltArbitrary,
        notifyEmailArbitrary,
        expiresInArbitrary,
        async (encryptedBlob, privateKeyPart, passwordSalt, notifyEmail, expiresIn) => {
          // Create a fresh store for each test case
          const store = createMockSecretStore();
          
          // Create a secret with all optional fields
          const options: {
            passwordSalt?: string;
            notifyEmail?: string;
            expiresIn?: '1h' | '24h' | '7d' | '30d';
          } = {};
          if (passwordSalt !== undefined) options.passwordSalt = passwordSalt;
          if (notifyEmail !== undefined) options.notifyEmail = notifyEmail;
          if (expiresIn !== undefined) options.expiresIn = expiresIn;
          
          const createRequest = createSecretRequest(encryptedBlob, privateKeyPart, options);
          const createResponse = await handleCreateSecret(createRequest, store);
          
          expect(createResponse.status).toBe(201);
          const { secretId } = await parseJsonResponse<CreateSecretResponse>(createResponse);
          
          // First retrieval should succeed
          const firstResponse = await handleGetSecret(secretId, store);
          expect(firstResponse.status).toBe(200);
          
          const body = await parseJsonResponse<GetSecretResponse>(firstResponse);
          expect(body.encryptedBlob).toEqual(encryptedBlob);
          expect(body.privateKeyPart).toBe(privateKeyPart);
          
          // Password salt should be included if it was set
          if (passwordSalt !== undefined) {
            expect(body.passwordSalt).toBe(passwordSalt);
          }
          
          // Second retrieval should fail
          const secondResponse = await handleGetSecret(secretId, store);
          expect(secondResponse.status).toBe(404);
          
          // Storage should be empty
          expect(store.storedSecrets.size).toBe(0);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});
