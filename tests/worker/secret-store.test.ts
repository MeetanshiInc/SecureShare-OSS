/**
 * Unit tests for SecretStore module
 * 
 * Tests verify:
 * - Secret ID generation produces valid 16-char alphanumeric IDs
 * - Secret ID validation works correctly
 * - TTL mapping works for all expiration options
 * - Store operation saves data with correct TTL
 * - GetAndDelete retrieves and removes secrets atomically
 * - Error handling for invalid inputs
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  generateSecretId,
  isValidSecretId,
  getTtlSeconds,
  createSecretStore,
  SECRET_ID_LENGTH,
  DEFAULT_TTL_SECONDS,
  TTL_MAP,
  type StoredSecret,
} from '../../src/worker/secret-store';
import type { EncryptedPayload } from '../../src/shared/crypto/encryptor';

/**
 * Creates a mock KV namespace for testing
 */
function createMockKV(): KVNamespace {
  const store = new Map<string, { value: string; expiration: number | null }>();
  
  return {
    get: vi.fn(async (key: string) => {
      const entry = store.get(key);
      if (!entry) return null;
      
      // Check if expired (for testing purposes)
      if (entry.expiration !== null && Date.now() > entry.expiration) {
        store.delete(key);
        return null;
      }
      
      return entry.value;
    }),
    put: vi.fn(async (key: string, value: string, options?: { expirationTtl?: number }) => {
      const expiration = options?.expirationTtl 
        ? Date.now() + (options.expirationTtl * 1000)
        : null;
      store.set(key, { value, expiration });
    }),
    delete: vi.fn(async (key: string) => {
      store.delete(key);
    }),
    // Add other required KVNamespace methods as stubs
    list: vi.fn(),
    getWithMetadata: vi.fn(),
  } as unknown as KVNamespace;
}

/**
 * Creates a valid StoredSecret for testing
 */
function createTestSecret(overrides?: Partial<StoredSecret>): StoredSecret {
  const encryptedBlob: EncryptedPayload = {
    ciphertext: 'dGVzdCBjaXBoZXJ0ZXh0',
    iv: 'dGVzdCBpdiAxMjM0',
    tag: 'dGVzdCB0YWcgMTIzNDU2',
  };
  
  return {
    encryptedBlob,
    privateKeyPart: 'dGVzdCBwcml2YXRlIGtleQ',
    createdAt: Date.now(),
    ...overrides,
  };
}

describe('SecretStore', () => {
  describe('generateSecretId', () => {
    it('should generate a 16-character string', () => {
      const id = generateSecretId();
      expect(id.length).toBe(SECRET_ID_LENGTH);
    });

    it('should generate only alphanumeric characters', () => {
      const id = generateSecretId();
      expect(/^[A-Za-z0-9]+$/.test(id)).toBe(true);
    });

    it('should generate different IDs on each call', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateSecretId());
      }
      // All 100 IDs should be unique
      expect(ids.size).toBe(100);
    });

    it('should use cryptographically secure random values', () => {
      // Generate many IDs and check distribution
      const charCounts = new Map<string, number>();
      const iterations = 1000;
      
      for (let i = 0; i < iterations; i++) {
        const id = generateSecretId();
        for (const char of id) {
          charCounts.set(char, (charCounts.get(char) || 0) + 1);
        }
      }
      
      // Should use a variety of characters (at least 50 different chars)
      expect(charCounts.size).toBeGreaterThan(50);
    });
  });

  describe('isValidSecretId', () => {
    it('should return true for valid 16-char alphanumeric ID', () => {
      expect(isValidSecretId('Abc123XYZ789defg')).toBe(true);
    });

    it('should return true for generated IDs', () => {
      const id = generateSecretId();
      expect(isValidSecretId(id)).toBe(true);
    });

    it('should return false for ID that is too short', () => {
      expect(isValidSecretId('Abc123')).toBe(false);
    });

    it('should return false for ID that is too long', () => {
      expect(isValidSecretId('Abc123XYZ789defgHIJK')).toBe(false);
    });

    it('should return false for ID with special characters', () => {
      expect(isValidSecretId('Abc123XYZ789-_!@')).toBe(false);
    });

    it('should return false for ID with spaces', () => {
      expect(isValidSecretId('Abc123 XYZ789de')).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(isValidSecretId('')).toBe(false);
    });

    it('should return false for non-string input', () => {
      expect(isValidSecretId(null as unknown as string)).toBe(false);
      expect(isValidSecretId(undefined as unknown as string)).toBe(false);
      expect(isValidSecretId(123 as unknown as string)).toBe(false);
    });
  });

  describe('getTtlSeconds', () => {
    it('should return 3600 for "1h"', () => {
      expect(getTtlSeconds('1h')).toBe(3600);
    });

    it('should return 86400 for "24h"', () => {
      expect(getTtlSeconds('24h')).toBe(86400);
    });

    it('should return 604800 for "7d"', () => {
      expect(getTtlSeconds('7d')).toBe(604800);
    });

    it('should return 2592000 for "30d"', () => {
      expect(getTtlSeconds('30d')).toBe(2592000);
    });

    it('should return default TTL for undefined', () => {
      expect(getTtlSeconds(undefined)).toBe(DEFAULT_TTL_SECONDS);
    });

    it('should return default TTL for invalid option', () => {
      expect(getTtlSeconds('invalid')).toBe(DEFAULT_TTL_SECONDS);
    });

    it('should return default TTL for empty string', () => {
      expect(getTtlSeconds('')).toBe(DEFAULT_TTL_SECONDS);
    });
  });

  describe('TTL_MAP', () => {
    it('should have correct values for all expiration options', () => {
      expect(TTL_MAP['1h']).toBe(3600);
      expect(TTL_MAP['24h']).toBe(86400);
      expect(TTL_MAP['7d']).toBe(604800);
      expect(TTL_MAP['30d']).toBe(2592000);
    });
  });

  describe('DEFAULT_TTL_SECONDS', () => {
    it('should be 30 days in seconds', () => {
      expect(DEFAULT_TTL_SECONDS).toBe(2592000);
    });
  });

  describe('createSecretStore', () => {
    let mockKV: KVNamespace;
    
    beforeEach(() => {
      mockKV = createMockKV();
    });

    describe('store', () => {
      it('should store secret with default TTL', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret();
        
        await store.store(secretId, secret);
        
        expect(mockKV.put).toHaveBeenCalledWith(
          secretId,
          expect.any(String),
          { expirationTtl: DEFAULT_TTL_SECONDS }
        );
      });

      it('should store secret with custom TTL', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret();
        const customTtl = 3600;
        
        await store.store(secretId, secret, customTtl);
        
        expect(mockKV.put).toHaveBeenCalledWith(
          secretId,
          expect.any(String),
          { expirationTtl: customTtl }
        );
      });

      it('should serialize secret data as JSON', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret();
        
        await store.store(secretId, secret);
        
        const putCall = vi.mocked(mockKV.put).mock.calls[0];
        const storedValue = putCall?.[1];
        expect(storedValue).toBeDefined();
        
        const parsed = JSON.parse(storedValue as string);
        expect(parsed.encryptedBlob).toEqual(secret.encryptedBlob);
        expect(parsed.privateKeyPart).toBe(secret.privateKeyPart);
      });

      it('should store optional notifyEmail', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret({ notifyEmail: 'test@example.com' });
        
        await store.store(secretId, secret);
        
        const putCall = vi.mocked(mockKV.put).mock.calls[0];
        const parsed = JSON.parse(putCall?.[1] as string);
        expect(parsed.notifyEmail).toBe('test@example.com');
      });

      it('should store optional passwordSalt', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret({ passwordSalt: 'c2FsdDEyMzQ1Njc4' });
        
        await store.store(secretId, secret);
        
        const putCall = vi.mocked(mockKV.put).mock.calls[0];
        const parsed = JSON.parse(putCall?.[1] as string);
        expect(parsed.passwordSalt).toBe('c2FsdDEyMzQ1Njc4');
      });

      it('should set createdAt if not provided', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret();
        delete (secret as Partial<StoredSecret>).createdAt;
        
        const beforeStore = Date.now();
        await store.store(secretId, secret);
        const afterStore = Date.now();
        
        const putCall = vi.mocked(mockKV.put).mock.calls[0];
        const parsed = JSON.parse(putCall?.[1] as string);
        expect(parsed.createdAt).toBeGreaterThanOrEqual(beforeStore);
        expect(parsed.createdAt).toBeLessThanOrEqual(afterStore);
      });

      it('should throw error for invalid secret ID', async () => {
        const store = createSecretStore(mockKV);
        const secret = createTestSecret();
        
        await expect(store.store('invalid', secret)).rejects.toThrow('Invalid secret ID format');
      });

      it('should throw error for missing encryptedBlob', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret();
        delete (secret as Partial<StoredSecret>).encryptedBlob;
        
        await expect(store.store(secretId, secret as StoredSecret)).rejects.toThrow('Missing required fields');
      });

      it('should throw error for missing privateKeyPart', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret();
        delete (secret as Partial<StoredSecret>).privateKeyPart;
        
        await expect(store.store(secretId, secret as StoredSecret)).rejects.toThrow('Missing required fields');
      });
    });

    describe('getAndDelete', () => {
      it('should retrieve stored secret', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret();
        
        await store.store(secretId, secret);
        const retrieved = await store.getAndDelete(secretId);
        
        expect(retrieved).not.toBeNull();
        expect(retrieved?.encryptedBlob).toEqual(secret.encryptedBlob);
        expect(retrieved?.privateKeyPart).toBe(secret.privateKeyPart);
      });

      it('should delete secret after retrieval', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret();
        
        await store.store(secretId, secret);
        await store.getAndDelete(secretId);
        
        expect(mockKV.delete).toHaveBeenCalledWith(secretId);
      });

      it('should return null for non-existent secret', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        
        const retrieved = await store.getAndDelete(secretId);
        
        expect(retrieved).toBeNull();
      });

      it('should return null for invalid secret ID format', async () => {
        const store = createSecretStore(mockKV);
        
        const retrieved = await store.getAndDelete('invalid');
        
        expect(retrieved).toBeNull();
      });

      it('should return null on second retrieval (one-time access)', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret();
        
        await store.store(secretId, secret);
        
        // First retrieval should succeed
        const first = await store.getAndDelete(secretId);
        expect(first).not.toBeNull();
        
        // Second retrieval should return null
        const second = await store.getAndDelete(secretId);
        expect(second).toBeNull();
      });

      it('should retrieve optional notifyEmail', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret({ notifyEmail: 'test@example.com' });
        
        await store.store(secretId, secret);
        const retrieved = await store.getAndDelete(secretId);
        
        expect(retrieved?.notifyEmail).toBe('test@example.com');
      });

      it('should retrieve optional passwordSalt', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const secret = createTestSecret({ passwordSalt: 'c2FsdDEyMzQ1Njc4' });
        
        await store.store(secretId, secret);
        const retrieved = await store.getAndDelete(secretId);
        
        expect(retrieved?.passwordSalt).toBe('c2FsdDEyMzQ1Njc4');
      });

      it('should retrieve createdAt timestamp', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        const createdAt = Date.now();
        const secret = createTestSecret({ createdAt });
        
        await store.store(secretId, secret);
        const retrieved = await store.getAndDelete(secretId);
        
        expect(retrieved?.createdAt).toBe(createdAt);
      });

      it('should return null for corrupted JSON data', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        
        // Manually store invalid JSON
        await mockKV.put(secretId, 'not valid json');
        
        const retrieved = await store.getAndDelete(secretId);
        
        expect(retrieved).toBeNull();
        // Should still delete the corrupted entry
        expect(mockKV.delete).toHaveBeenCalledWith(secretId);
      });

      it('should return null for data missing required fields', async () => {
        const store = createSecretStore(mockKV);
        const secretId = generateSecretId();
        
        // Store data missing required fields
        await mockKV.put(secretId, JSON.stringify({ someField: 'value' }));
        
        const retrieved = await store.getAndDelete(secretId);
        
        expect(retrieved).toBeNull();
      });
    });
  });

  describe('SECRET_ID_LENGTH', () => {
    it('should be 16', () => {
      expect(SECRET_ID_LENGTH).toBe(16);
    });
  });
});
