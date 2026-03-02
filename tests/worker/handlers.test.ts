/**
 * Unit tests for API request handlers
 * 
 * Tests verify:
 * - POST /api/secrets creates secrets with valid data
 * - GET /api/secrets/:secretId retrieves and deletes secrets
 * - Request validation rejects invalid inputs
 * - Error responses are generic (no internal details exposed)
 * - One-time access is enforced
 * 
 * Requirements tested:
 * - 1.4: Send only the Encrypted_Blob and Private_Key_Part to the Backend_API
 * - 1.5: Generate a unique Secret_ID and store the data in Secret_Store
 * - 1.6: Return the Secret_ID to the Frontend
 * - 2.2: Request the Encrypted_Blob and Private_Key_Part from the Backend_API using the Secret_ID
 * - 2.3: Return the Encrypted_Blob and Private_Key_Part exactly once
 * - 8.4: Return a generic error without exposing internal details
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  handleCreateSecret,
  handleGetSecret,
  handleRequest,
  extractSecretIdFromPath,
  type CreateSecretRequest,
  type CreateSecretResponse,
  type GetSecretResponse,
  type ErrorResponse,
} from '../../src/worker/handlers';
import type { SecretStore, StoredSecret } from '../../src/worker/secret-store';
import type { EncryptedPayload } from '../../src/shared/crypto/encryptor';

/**
 * Creates a mock SecretStore for testing
 */
function createMockSecretStore(): SecretStore & {
  storedSecrets: Map<string, StoredSecret>;
  storeCalls: Array<{ secretId: string; data: StoredSecret; ttl: number | undefined }>;
} {
  const storedSecrets = new Map<string, StoredSecret>();
  const storeCalls: Array<{ secretId: string; data: StoredSecret; ttl: number | undefined }> = [];
  
  return {
    storedSecrets,
    storeCalls,
    async store(secretId: string, data: StoredSecret, ttlSeconds?: number): Promise<void> {
      storeCalls.push({ secretId, data, ttl: ttlSeconds });
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
 * Creates a valid EncryptedPayload for testing
 */
function createTestEncryptedPayload(): EncryptedPayload {
  return {
    ciphertext: 'dGVzdCBjaXBoZXJ0ZXh0',
    iv: 'dGVzdCBpdiAxMjM0',
    tag: 'dGVzdCB0YWcgMTIzNDU2',
  };
}

/**
 * Creates a valid CreateSecretRequest for testing
 */
function createTestCreateRequest(overrides?: Partial<CreateSecretRequest>): CreateSecretRequest {
  return {
    encryptedBlob: createTestEncryptedPayload(),
    privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
    ...overrides,
  };
}

/**
 * Creates a Request object with JSON body
 */
function createJsonRequest(
  url: string,
  method: string,
  body?: unknown
): Request {
  const init: RequestInit = {
    method,
    headers: {
      'Content-Type': 'application/json',
    },
  };
  
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  
  return new Request(url, init);
}

/**
 * Parses a Response body as JSON
 */
async function parseJsonResponse<T>(response: Response): Promise<T> {
  return response.json() as Promise<T>;
}

describe('API Handlers', () => {
  describe('handleCreateSecret', () => {
    let mockStore: ReturnType<typeof createMockSecretStore>;
    
    beforeEach(() => {
      mockStore = createMockSecretStore();
    });

    it('should create a secret and return secretId', async () => {
      const requestBody = createTestCreateRequest();
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleCreateSecret(request, mockStore);
      
      expect(response.status).toBe(201);
      
      const body = await parseJsonResponse<CreateSecretResponse>(response);
      expect(body.secretId).toBeDefined();
      expect(body.secretId.length).toBe(16);
      expect(/^[A-Za-z0-9]+$/.test(body.secretId)).toBe(true);
    });

    it('should store the encrypted blob and private key part', async () => {
      const requestBody = createTestCreateRequest();
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      await handleCreateSecret(request, mockStore);
      
      expect(mockStore.storeCalls.length).toBe(1);
      const storeCall = mockStore.storeCalls[0]!;
      expect(storeCall.data.encryptedBlob).toEqual(requestBody.encryptedBlob);
      expect(storeCall.data.privateKeyPart).toBe(requestBody.privateKeyPart);
    });

    it('should store optional notifyEmail', async () => {
      const requestBody = createTestCreateRequest({ notifyEmail: 'test@example.com' });
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      await handleCreateSecret(request, mockStore);
      
      const storeCall = mockStore.storeCalls[0]!;
      expect(storeCall.data.notifyEmail).toBe('test@example.com');
    });

    it('should store optional passwordSalt', async () => {
      const requestBody = createTestCreateRequest({ passwordSalt: 'c2FsdDEyMzQ1Njc4' });
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      await handleCreateSecret(request, mockStore);
      
      const storeCall = mockStore.storeCalls[0]!;
      expect(storeCall.data.passwordSalt).toBe('c2FsdDEyMzQ1Njc4');
    });

    it('should use default TTL when expiresIn is not provided', async () => {
      const requestBody = createTestCreateRequest();
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      await handleCreateSecret(request, mockStore);
      
      const storeCall = mockStore.storeCalls[0]!;
      expect(storeCall.ttl).toBe(2592000); // 30 days default
    });

    it('should use correct TTL for 1h expiration', async () => {
      const requestBody = createTestCreateRequest({ expiresIn: '1h' });
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      await handleCreateSecret(request, mockStore);
      
      const storeCall = mockStore.storeCalls[0]!;
      expect(storeCall.ttl).toBe(3600);
    });

    it('should use correct TTL for 24h expiration', async () => {
      const requestBody = createTestCreateRequest({ expiresIn: '24h' });
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      await handleCreateSecret(request, mockStore);
      
      const storeCall = mockStore.storeCalls[0]!;
      expect(storeCall.ttl).toBe(86400);
    });

    it('should use correct TTL for 7d expiration', async () => {
      const requestBody = createTestCreateRequest({ expiresIn: '7d' });
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      await handleCreateSecret(request, mockStore);
      
      const storeCall = mockStore.storeCalls[0]!;
      expect(storeCall.ttl).toBe(604800);
    });

    it('should use correct TTL for 30d expiration', async () => {
      const requestBody = createTestCreateRequest({ expiresIn: '30d' });
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      await handleCreateSecret(request, mockStore);
      
      const storeCall = mockStore.storeCalls[0]!;
      expect(storeCall.ttl).toBe(2592000);
    });

    it('should set createdAt timestamp', async () => {
      const requestBody = createTestCreateRequest();
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const beforeCreate = Date.now();
      await handleCreateSecret(request, mockStore);
      const afterCreate = Date.now();
      
      const storeCall = mockStore.storeCalls[0]!;
      expect(storeCall.data.createdAt).toBeGreaterThanOrEqual(beforeCreate);
      expect(storeCall.data.createdAt).toBeLessThanOrEqual(afterCreate);
    });

    it('should return 400 for invalid JSON body', async () => {
      const request = new Request('https://example.com/api/secrets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'not valid json',
      });
      
      const response = await handleCreateSecret(request, mockStore);
      
      expect(response.status).toBe(400);
      const body = await parseJsonResponse<ErrorResponse>(response);
      expect(body.code).toBe('INVALID_REQUEST');
    });

    it('should return 400 for missing encryptedBlob', async () => {
      const requestBody = { privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ' };
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleCreateSecret(request, mockStore);
      
      expect(response.status).toBe(400);
      const body = await parseJsonResponse<ErrorResponse>(response);
      expect(body.code).toBe('INVALID_REQUEST');
    });

    it('should return 400 for missing privateKeyPart', async () => {
      const requestBody = { encryptedBlob: createTestEncryptedPayload() };
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleCreateSecret(request, mockStore);
      
      expect(response.status).toBe(400);
      const body = await parseJsonResponse<ErrorResponse>(response);
      expect(body.code).toBe('INVALID_REQUEST');
    });

    it('should return 400 for invalid encryptedBlob structure', async () => {
      const requestBody = {
        encryptedBlob: { ciphertext: 'test' }, // missing iv and tag
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
      };
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleCreateSecret(request, mockStore);
      
      expect(response.status).toBe(400);
      const body = await parseJsonResponse<ErrorResponse>(response);
      expect(body.code).toBe('INVALID_REQUEST');
    });

    it('should return 400 for invalid expiresIn value', async () => {
      const requestBody = createTestCreateRequest({ expiresIn: '2h' as any });
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleCreateSecret(request, mockStore);
      
      expect(response.status).toBe(400);
      const body = await parseJsonResponse<ErrorResponse>(response);
      expect(body.code).toBe('INVALID_REQUEST');
    });

    it('should return 400 for non-string notifyEmail', async () => {
      const requestBody = { ...createTestCreateRequest(), notifyEmail: 123 };
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleCreateSecret(request, mockStore);
      
      expect(response.status).toBe(400);
      const body = await parseJsonResponse<ErrorResponse>(response);
      expect(body.code).toBe('INVALID_REQUEST');
    });

    it('should return 400 for non-string passwordSalt', async () => {
      const requestBody = { ...createTestCreateRequest(), passwordSalt: 123 };
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleCreateSecret(request, mockStore);
      
      expect(response.status).toBe(400);
      const body = await parseJsonResponse<ErrorResponse>(response);
      expect(body.code).toBe('INVALID_REQUEST');
    });

    it('should return 500 when store fails', async () => {
      const failingStore: SecretStore = {
        async store(): Promise<void> {
          throw new Error('KV storage error');
        },
        async getAndDelete(): Promise<StoredSecret | null> {
          return null;
        },
      };
      
      const requestBody = createTestCreateRequest();
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleCreateSecret(request, failingStore);
      
      expect(response.status).toBe(500);
      const body = await parseJsonResponse<ErrorResponse>(response);
      expect(body.code).toBe('INTERNAL_ERROR');
      // Verify error message is generic (Requirement 8.4)
      expect(body.error).not.toContain('KV');
      expect(body.error).not.toContain('storage');
    });

    it('should accept empty ciphertext (for empty plaintext)', async () => {
      const requestBody = createTestCreateRequest({
        encryptedBlob: {
          ciphertext: '',
          iv: 'dGVzdCBpdiAxMjM0',
          tag: 'dGVzdCB0YWcgMTIzNDU2',
        },
      });
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleCreateSecret(request, mockStore);
      
      expect(response.status).toBe(201);
    });

    it('should return Content-Type application/json', async () => {
      const requestBody = createTestCreateRequest();
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleCreateSecret(request, mockStore);
      
      expect(response.headers.get('Content-Type')).toBe('application/json');
    });
  });

  describe('handleGetSecret', () => {
    let mockStore: ReturnType<typeof createMockSecretStore>;
    
    beforeEach(() => {
      mockStore = createMockSecretStore();
    });

    it('should retrieve a stored secret', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      const response = await handleGetSecret(secretId, mockStore);
      
      expect(response.status).toBe(200);
      
      const body = await parseJsonResponse<GetSecretResponse>(response);
      expect(body.encryptedBlob).toEqual(storedSecret.encryptedBlob);
      expect(body.privateKeyPart).toBe(storedSecret.privateKeyPart);
    });

    it('should include passwordSalt when present', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        passwordSalt: 'c2FsdDEyMzQ1Njc4',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      const response = await handleGetSecret(secretId, mockStore);
      
      const body = await parseJsonResponse<GetSecretResponse>(response);
      expect(body.passwordSalt).toBe('c2FsdDEyMzQ1Njc4');
    });

    it('should NOT include notifyEmail in response', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        notifyEmail: 'test@example.com',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      const response = await handleGetSecret(secretId, mockStore);
      
      const body = await parseJsonResponse<GetSecretResponse>(response);
      expect((body as any).notifyEmail).toBeUndefined();
    });

    it('should delete secret after retrieval (one-time access)', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      // First retrieval should succeed
      const response1 = await handleGetSecret(secretId, mockStore);
      expect(response1.status).toBe(200);
      
      // Second retrieval should fail
      const response2 = await handleGetSecret(secretId, mockStore);
      expect(response2.status).toBe(404);
    });

    it('should return 404 for non-existent secret', async () => {
      const response = await handleGetSecret('Abc123XYZ789defg', mockStore);
      
      expect(response.status).toBe(404);
      const body = await parseJsonResponse<ErrorResponse>(response);
      expect(body.code).toBe('NOT_FOUND');
    });

    it('should return 404 for invalid secret ID format', async () => {
      const response = await handleGetSecret('invalid', mockStore);
      
      expect(response.status).toBe(404);
      const body = await parseJsonResponse<ErrorResponse>(response);
      expect(body.code).toBe('NOT_FOUND');
    });

    it('should return 404 for secret ID with special characters', async () => {
      const response = await handleGetSecret('Abc123-XYZ_789!@', mockStore);
      
      expect(response.status).toBe(404);
    });

    it('should return 500 when getAndDelete fails', async () => {
      const failingStore: SecretStore = {
        async store(): Promise<void> {},
        async getAndDelete(): Promise<StoredSecret | null> {
          throw new Error('KV retrieval error');
        },
      };
      
      const response = await handleGetSecret('Abc123XYZ789defg', failingStore);
      
      expect(response.status).toBe(500);
      const body = await parseJsonResponse<ErrorResponse>(response);
      expect(body.code).toBe('INTERNAL_ERROR');
      // Verify error message is generic (Requirement 8.4)
      expect(body.error).not.toContain('KV');
      expect(body.error).not.toContain('retrieval');
    });

    it('should return Content-Type application/json', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      const response = await handleGetSecret(secretId, mockStore);
      
      expect(response.headers.get('Content-Type')).toBe('application/json');
    });
  });

  describe('extractSecretIdFromPath', () => {
    it('should extract secret ID from valid path', () => {
      expect(extractSecretIdFromPath('/api/secrets/Abc123XYZ789defg')).toBe('Abc123XYZ789defg');
    });

    it('should return null for path without secret ID', () => {
      expect(extractSecretIdFromPath('/api/secrets')).toBeNull();
      expect(extractSecretIdFromPath('/api/secrets/')).toBeNull();
    });

    it('should return null for invalid path format', () => {
      expect(extractSecretIdFromPath('/api/other/Abc123XYZ789defg')).toBeNull();
      expect(extractSecretIdFromPath('/secrets/Abc123XYZ789defg')).toBeNull();
    });

    it('should return null for path with extra segments', () => {
      expect(extractSecretIdFromPath('/api/secrets/Abc123XYZ789defg/extra')).toBeNull();
    });

    it('should handle various secret ID formats', () => {
      expect(extractSecretIdFromPath('/api/secrets/abc')).toBe('abc');
      expect(extractSecretIdFromPath('/api/secrets/123')).toBe('123');
      expect(extractSecretIdFromPath('/api/secrets/ABC123xyz789DEF0')).toBe('ABC123xyz789DEF0');
    });
  });

  describe('handleRequest', () => {
    let mockStore: ReturnType<typeof createMockSecretStore>;
    
    beforeEach(() => {
      mockStore = createMockSecretStore();
    });

    it('should route POST /api/secrets to handleCreateSecret', async () => {
      const requestBody = createTestCreateRequest();
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleRequest(request, mockStore);
      
      expect(response.status).toBe(201);
      const body = await parseJsonResponse<CreateSecretResponse>(response);
      expect(body.secretId).toBeDefined();
    });

    it('should route GET /api/secrets/:secretId to handleGetSecret', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      const request = new Request(`https://example.com/api/secrets/${secretId}`, {
        method: 'GET',
      });
      
      const response = await handleRequest(request, mockStore);
      
      expect(response.status).toBe(200);
      const body = await parseJsonResponse<GetSecretResponse>(response);
      expect(body.encryptedBlob).toEqual(storedSecret.encryptedBlob);
    });

    it('should return 404 for unknown routes', async () => {
      const request = new Request('https://example.com/api/unknown', {
        method: 'GET',
      });
      
      const response = await handleRequest(request, mockStore);
      
      expect(response).not.toBeNull();
      expect(response!.status).toBe(404);
    });

    it('should return 404 for unsupported methods on /api/secrets', async () => {
      const request = new Request('https://example.com/api/secrets', {
        method: 'DELETE',
      });
      
      const response = await handleRequest(request, mockStore);
      
      expect(response).not.toBeNull();
      expect(response!.status).toBe(404);
    });

    it('should return 404 for PUT on /api/secrets/:secretId', async () => {
      const request = new Request('https://example.com/api/secrets/Abc123XYZ789defg', {
        method: 'PUT',
      });
      
      const response = await handleRequest(request, mockStore);
      
      expect(response).not.toBeNull();
      expect(response!.status).toBe(404);
    });

    it('should return null for non-API routes (static asset handling)', async () => {
      const request = new Request('https://example.com/', {
        method: 'GET',
      });
      
      const response = await handleRequest(request, mockStore);
      
      expect(response).toBeNull();
    });
  });

  describe('Error Response Safety (Requirement 8.4)', () => {
    it('should not expose internal details in INVALID_REQUEST errors', async () => {
      const mockStore = createMockSecretStore();
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', {});
      
      const response = await handleCreateSecret(request, mockStore);
      const body = await parseJsonResponse<ErrorResponse>(response);
      
      // Error message should be generic
      expect(body.error).toBe('Invalid request');
      expect(body.error).not.toContain('encryptedBlob');
      expect(body.error).not.toContain('privateKeyPart');
    });

    it('should not expose internal details in NOT_FOUND errors', async () => {
      const mockStore = createMockSecretStore();
      
      const response = await handleGetSecret('Abc123XYZ789defg', mockStore);
      const body = await parseJsonResponse<ErrorResponse>(response);
      
      // Error message should be generic
      expect(body.error).toBe('Secret not found or has already been viewed');
      expect(body.error).not.toContain('KV');
      expect(body.error).not.toContain('database');
    });

    it('should not expose internal details in INTERNAL_ERROR errors', async () => {
      const failingStore: SecretStore = {
        async store(): Promise<void> {
          throw new Error('Detailed internal error: KV namespace binding failed');
        },
        async getAndDelete(): Promise<StoredSecret | null> {
          return null;
        },
      };
      
      const requestBody = createTestCreateRequest();
      const request = createJsonRequest('https://example.com/api/secrets', 'POST', requestBody);
      
      const response = await handleCreateSecret(request, failingStore);
      const body = await parseJsonResponse<ErrorResponse>(response);
      
      // Error message should be generic
      expect(body.error).toBe('An error occurred');
      expect(body.error).not.toContain('KV');
      expect(body.error).not.toContain('namespace');
      expect(body.error).not.toContain('binding');
    });
  });
});


import { vi } from 'vitest';
import type { NotificationService } from '../../src/worker/notification-service';

/**
 * Creates a mock NotificationService for testing
 */
function createMockNotificationService(): NotificationService & {
  sendCalls: Array<{ email: string; viewedAt: Date }>;
} {
  const sendCalls: Array<{ email: string; viewedAt: Date }> = [];
  
  return {
    sendCalls,
    async sendViewNotification(email: string, viewedAt: Date) {
      sendCalls.push({ email, viewedAt });
      return { success: true };
    },
  };
}

describe('Notification Integration', () => {
  describe('handleGetSecret with NotificationService', () => {
    let mockStore: ReturnType<typeof createMockSecretStore>;
    let mockNotificationService: ReturnType<typeof createMockNotificationService>;
    
    beforeEach(() => {
      mockStore = createMockSecretStore();
      mockNotificationService = createMockNotificationService();
    });

    it('should send notification when notifyEmail is present', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        notifyEmail: 'test@example.com',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      await handleGetSecret(secretId, mockStore, mockNotificationService);
      
      // Wait a tick for the async notification to be called
      await new Promise(resolve => setTimeout(resolve, 10));
      
      expect(mockNotificationService.sendCalls.length).toBe(1);
      expect(mockNotificationService.sendCalls[0]!.email).toBe('test@example.com');
    });

    it('should not send notification when notifyEmail is not present', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      await handleGetSecret(secretId, mockStore, mockNotificationService);
      
      // Wait a tick
      await new Promise(resolve => setTimeout(resolve, 10));
      
      expect(mockNotificationService.sendCalls.length).toBe(0);
    });

    it('should not send notification when notificationService is not provided', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        notifyEmail: 'test@example.com',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      // Call without notification service
      const response = await handleGetSecret(secretId, mockStore);
      
      // Should still return success
      expect(response.status).toBe(200);
    });

    it('should still return secret even if notification fails', async () => {
      const failingNotificationService: NotificationService = {
        async sendViewNotification() {
          throw new Error('Email service down');
        },
      };
      
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        notifyEmail: 'test@example.com',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      const response = await handleGetSecret(secretId, mockStore, failingNotificationService);
      
      // Should still return the secret successfully
      expect(response.status).toBe(200);
      const body = await response.json() as GetSecretResponse;
      expect(body.encryptedBlob).toEqual(storedSecret.encryptedBlob);
    });

    it('should include timestamp in notification', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        notifyEmail: 'test@example.com',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      const beforeCall = new Date();
      await handleGetSecret(secretId, mockStore, mockNotificationService);
      const afterCall = new Date();
      
      // Wait a tick
      await new Promise(resolve => setTimeout(resolve, 10));
      
      expect(mockNotificationService.sendCalls.length).toBe(1);
      const viewedAt = mockNotificationService.sendCalls[0]!.viewedAt;
      expect(viewedAt.getTime()).toBeGreaterThanOrEqual(beforeCall.getTime());
      expect(viewedAt.getTime()).toBeLessThanOrEqual(afterCall.getTime());
    });

    it('should delete email from storage after retrieval (Requirement 5.5)', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        notifyEmail: 'test@example.com',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      await handleGetSecret(secretId, mockStore, mockNotificationService);
      
      // The secret (including email) should be deleted from storage
      expect(mockStore.storedSecrets.has(secretId)).toBe(false);
    });

    it('should not include notifyEmail in response (email is internal only)', async () => {
      const secretId = 'Abc123XYZ789defg';
      const storedSecret: StoredSecret = {
        encryptedBlob: createTestEncryptedPayload(),
        privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
        notifyEmail: 'test@example.com',
        createdAt: Date.now(),
      };
      mockStore.storedSecrets.set(secretId, storedSecret);
      
      const response = await handleGetSecret(secretId, mockStore, mockNotificationService);
      const body = await response.json() as any;
      
      // notifyEmail should NOT be in the response
      expect(body.notifyEmail).toBeUndefined();
    });
  });
});
