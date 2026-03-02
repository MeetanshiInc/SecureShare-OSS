/**
 * Property-Based Tests for Error Response Safety
 * 
 * **Validates: Requirements 8.4**
 * 
 * Property 10: Error Response Safety
 * For any error condition in the backend API, the error response should be
 * generic and should not expose internal details, stack traces, or sensitive data.
 * 
 * Requirements context:
 * - 8.4: IF an error occurs during secret retrieval, THEN THE Backend_API SHALL
 *        return a generic error without exposing internal details
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  handleCreateSecret,
  handleGetSecret,
  handleRequest,
  type ErrorResponse,
} from '../../src/worker/handlers';
import type { SecretStore, StoredSecret } from '../../src/worker/secret-store';

/**
 * List of sensitive patterns that should NEVER appear in error responses.
 * These patterns indicate internal implementation details, stack traces,
 * or sensitive data that could be exploited by attackers.
 */
const FORBIDDEN_PATTERNS = [
  // Stack trace indicators
  /at\s+\w+\s+\(/i,           // "at functionName ("
  /\.ts:\d+:\d+/,              // TypeScript file references
  /\.js:\d+:\d+/,              // JavaScript file references
  /Error:\s+.{50,}/,           // Long error messages (likely stack traces)
  /\n\s+at\s+/,                // Multi-line stack traces
  
  // Internal path indicators
  /\/src\//,                   // Source directory paths
  /\/node_modules\//,          // Node modules paths
  /\/worker\//,                // Worker directory paths
  /\/dist\//,                  // Distribution directory paths
  /file:\/\//,                 // File URLs
  /C:\\|D:\\/,                 // Windows paths
  
  // Internal implementation details
  /KV\s*(namespace|binding|storage)/i,  // Cloudflare KV internals
  /Cloudflare/i,               // Platform-specific details
  /wrangler/i,                 // Tooling details
  /namespace/i,                // Internal terminology
  /binding/i,                  // Internal terminology
  /database/i,                 // Storage implementation details
  /SQL|query/i,                // Database query details
  
  // Sensitive data patterns
  /privateKeyPart/i,           // Key terminology
  /encryptedBlob/i,            // Encryption terminology
  /password/i,                 // Password references
  /salt/i,                     // Cryptographic salt
  /email/i,                    // Email addresses
  /key/i,                      // Generic key references
  
  // Exception details
  /TypeError|ReferenceError|SyntaxError/,  // JavaScript error types
  /undefined is not|null is not/i,          // Common JS errors
  /cannot read property/i,                   // Property access errors
  /ENOENT|EACCES|EPERM/,                    // System errors
];

/**
 * Expected error fields that should be present in error responses.
 */
const EXPECTED_ERROR_FIELDS = ['error', 'code'];

/**
 * Valid error codes that the API can return.
 */
const VALID_ERROR_CODES = ['NOT_FOUND', 'INVALID_REQUEST', 'INTERNAL_ERROR'];

/**
 * Creates a mock SecretStore that always fails with the given error.
 */
function createFailingStore(errorMessage: string): SecretStore {
  return {
    async store(): Promise<void> {
      throw new Error(errorMessage);
    },
    async getAndDelete(): Promise<StoredSecret | null> {
      throw new Error(errorMessage);
    },
  };
}

/**
 * Creates a mock SecretStore that works normally.
 */
function createWorkingStore(): SecretStore & { storedSecrets: Map<string, StoredSecret> } {
  const storedSecrets = new Map<string, StoredSecret>();
  return {
    storedSecrets,
    async store(secretId: string, data: StoredSecret): Promise<void> {
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
 * Arbitrary generator for internal error messages that might be thrown.
 * These simulate various internal errors that could occur in the system.
 */
const internalErrorMessageArbitrary: fc.Arbitrary<string> = fc.oneof(
  // Cloudflare KV errors
  fc.constant('KV namespace binding failed'),
  fc.constant('KV storage error: quota exceeded'),
  fc.constant('KV GET operation timed out'),
  fc.constant('KV PUT operation failed: network error'),
  
  // Database errors
  fc.constant('Database connection failed'),
  fc.constant('SQL query execution error'),
  fc.constant('Transaction rollback: deadlock detected'),
  
  // System errors
  fc.constant('ENOENT: no such file or directory'),
  fc.constant('EACCES: permission denied'),
  fc.constant('EPERM: operation not permitted'),
  
  // JavaScript errors with stack traces
  fc.constant('TypeError: Cannot read property \'encryptedBlob\' of undefined\n    at handleGetSecret (/src/worker/handlers.ts:150:25)'),
  fc.constant('ReferenceError: privateKeyPart is not defined\n    at processRequest (/src/worker/handlers.ts:75:10)'),
  
  // Generic errors with sensitive info
  fc.constant('Failed to decrypt: invalid key length'),
  fc.constant('Email notification failed: SMTP connection refused'),
  fc.constant('Password salt validation error'),
  
  // Random error messages
  fc.string({ minLength: 10, maxLength: 200 }).map(s => `Internal error: ${s}`)
);

/**
 * Arbitrary generator for invalid request bodies.
 * These simulate various malformed inputs that should trigger validation errors.
 */
const invalidRequestBodyArbitrary: fc.Arbitrary<unknown> = fc.oneof(
  // Completely invalid types
  fc.constant(null),
  fc.constant(undefined),
  fc.constant('not an object'),
  fc.integer(),
  fc.boolean(),
  fc.array(fc.anything()),
  
  // Missing required fields
  fc.constant({}),
  fc.constant({ encryptedBlob: {} }),
  fc.constant({ privateKeyPart: 'test' }),
  
  // Invalid field types
  fc.record({
    encryptedBlob: fc.integer(),
    privateKeyPart: fc.string(),
  }),
  fc.record({
    encryptedBlob: fc.record({
      ciphertext: fc.string(),
      iv: fc.string(),
      tag: fc.string(),
    }),
    privateKeyPart: fc.integer(),
  }),
  
  // Invalid encryptedBlob structure
  fc.record({
    encryptedBlob: fc.record({
      ciphertext: fc.string(),
      // Missing iv and tag
    }),
    privateKeyPart: fc.string({ minLength: 1 }),
  }),
  
  // Invalid optional fields
  fc.record({
    encryptedBlob: fc.record({
      ciphertext: fc.string(),
      iv: fc.string({ minLength: 1 }),
      tag: fc.string({ minLength: 1 }),
    }),
    privateKeyPart: fc.string({ minLength: 1 }),
    expiresIn: fc.constantFrom('2h', '3d', 'invalid', 123),
  }),
  fc.record({
    encryptedBlob: fc.record({
      ciphertext: fc.string(),
      iv: fc.string({ minLength: 1 }),
      tag: fc.string({ minLength: 1 }),
    }),
    privateKeyPart: fc.string({ minLength: 1 }),
    notifyEmail: fc.integer(),
  }),
  fc.record({
    encryptedBlob: fc.record({
      ciphertext: fc.string(),
      iv: fc.string({ minLength: 1 }),
      tag: fc.string({ minLength: 1 }),
    }),
    privateKeyPart: fc.string({ minLength: 1 }),
    passwordSalt: fc.integer(),
  })
);

/**
 * Arbitrary generator for invalid secret IDs.
 * These simulate various malformed secret IDs that should trigger not-found errors.
 */
const invalidSecretIdArbitrary: fc.Arbitrary<string> = fc.oneof(
  // Too short
  fc.stringOf(fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), { minLength: 1, maxLength: 15 }),
  // Too long
  fc.stringOf(fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), { minLength: 17, maxLength: 50 }),
  // Contains special characters
  fc.stringOf(fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_!@#$%^&*()'), { minLength: 16, maxLength: 16 }),
  // Empty string
  fc.constant(''),
  // SQL injection attempts
  fc.constant("'; DROP TABLE secrets; --"),
  fc.constant('1 OR 1=1'),
  // Path traversal attempts
  fc.constant('../../../etc/passwd'),
  fc.constant('..\\..\\..\\windows\\system32'),
  // XSS attempts
  fc.constant('<script>alert(1)</script>'),
  fc.constant('javascript:alert(1)')
);

/**
 * Arbitrary generator for valid 16-character alphanumeric secret IDs
 * that don't exist in the store.
 */
const nonExistentSecretIdArbitrary: fc.Arbitrary<string> = fc.stringOf(
  fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'),
  { minLength: 16, maxLength: 16 }
);

/**
 * Creates a Request object with JSON body for creating a secret.
 */
function createSecretRequest(body: unknown): Request {
  return new Request('https://example.com/api/secrets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/**
 * Creates a Request object with invalid JSON body.
 */
function createInvalidJsonRequest(): Request {
  return new Request('https://example.com/api/secrets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: 'not valid json {{{',
  });
}

/**
 * Parses a Response body as JSON.
 */
async function parseJsonResponse<T>(response: Response): Promise<T> {
  return response.json() as Promise<T>;
}

/**
 * Validates that an error response is safe and doesn't expose internal details.
 */
function validateErrorResponseSafety(body: ErrorResponse): void {
  // Check that only expected fields are present
  const actualFields = Object.keys(body);
  for (const field of actualFields) {
    expect(EXPECTED_ERROR_FIELDS).toContain(field);
  }
  
  // Check that required fields are present
  expect(body.error).toBeDefined();
  expect(body.code).toBeDefined();
  
  // Check that error code is valid
  expect(VALID_ERROR_CODES).toContain(body.code);
  
  // Check that error message is a string
  expect(typeof body.error).toBe('string');
  
  // Check that error message doesn't contain forbidden patterns
  for (const pattern of FORBIDDEN_PATTERNS) {
    expect(body.error).not.toMatch(pattern);
  }
  
  // Check that error message is reasonably short (no stack traces)
  expect(body.error.length).toBeLessThan(100);
  
  // Check that error message doesn't contain newlines (no stack traces)
  expect(body.error).not.toContain('\n');
}

describe('Property 10: Error Response Safety', () => {
  /**
   * **Validates: Requirements 8.4**
   * 
   * Property: For any invalid request body sent to POST /api/secrets,
   * the error response should be generic and not expose validation details.
   */
  it('invalid request bodies produce safe error responses', async () => {
    await fc.assert(
      fc.asyncProperty(
        invalidRequestBodyArbitrary,
        async (invalidBody) => {
          const store = createWorkingStore();
          const request = createSecretRequest(invalidBody);
          
          const response = await handleCreateSecret(request, store);
          
          // Should return 400 Bad Request
          expect(response.status).toBe(400);
          
          const body = await parseJsonResponse<ErrorResponse>(response);
          
          // Validate error response safety
          validateErrorResponseSafety(body);
          
          // Should return INVALID_REQUEST code
          expect(body.code).toBe('INVALID_REQUEST');
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 8.4**
   * 
   * Property: For any internal error during secret creation,
   * the error response should be generic and not expose internal details.
   */
  it('internal errors during creation produce safe error responses', async () => {
    await fc.assert(
      fc.asyncProperty(
        internalErrorMessageArbitrary,
        async (errorMessage) => {
          const failingStore = createFailingStore(errorMessage);
          
          // Create a valid request that will trigger the internal error
          const validBody = {
            encryptedBlob: {
              ciphertext: 'dGVzdA==',
              iv: 'dGVzdGl2MTIzNA==',
              tag: 'dGVzdHRhZzEyMzQ1Ng==',
            },
            privateKeyPart: 'dGVzdHByaXZhdGVrZXk=',
          };
          const request = createSecretRequest(validBody);
          
          const response = await handleCreateSecret(request, failingStore);
          
          // Should return 500 Internal Server Error
          expect(response.status).toBe(500);
          
          const body = await parseJsonResponse<ErrorResponse>(response);
          
          // Validate error response safety
          validateErrorResponseSafety(body);
          
          // Should return INTERNAL_ERROR code
          expect(body.code).toBe('INTERNAL_ERROR');
          
          // Error message should NOT contain the original error message
          expect(body.error).not.toContain(errorMessage);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 8.4**
   * 
   * Property: For any internal error during secret retrieval,
   * the error response should be generic and not expose internal details.
   */
  it('internal errors during retrieval produce safe error responses', async () => {
    await fc.assert(
      fc.asyncProperty(
        internalErrorMessageArbitrary,
        nonExistentSecretIdArbitrary,
        async (errorMessage, secretId) => {
          const failingStore = createFailingStore(errorMessage);
          
          const response = await handleGetSecret(secretId, failingStore);
          
          // Should return 500 Internal Server Error
          expect(response.status).toBe(500);
          
          const body = await parseJsonResponse<ErrorResponse>(response);
          
          // Validate error response safety
          validateErrorResponseSafety(body);
          
          // Should return INTERNAL_ERROR code
          expect(body.code).toBe('INTERNAL_ERROR');
          
          // Error message should NOT contain the original error message
          expect(body.error).not.toContain(errorMessage);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 8.4**
   * 
   * Property: For any invalid secret ID format,
   * the error response should be generic and not expose validation details.
   */
  it('invalid secret IDs produce safe error responses', async () => {
    await fc.assert(
      fc.asyncProperty(
        invalidSecretIdArbitrary,
        async (invalidSecretId) => {
          const store = createWorkingStore();
          
          const response = await handleGetSecret(invalidSecretId, store);
          
          // Should return 404 Not Found
          expect(response.status).toBe(404);
          
          const body = await parseJsonResponse<ErrorResponse>(response);
          
          // Validate error response safety
          validateErrorResponseSafety(body);
          
          // Should return NOT_FOUND code
          expect(body.code).toBe('NOT_FOUND');
          
          // Error message should NOT contain the invalid secret ID
          // Only check for strings longer than 3 characters to avoid false positives
          // where short strings like "e" naturally appear in error messages
          if (invalidSecretId.length > 3) {
            expect(body.error).not.toContain(invalidSecretId);
          }
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 8.4**
   * 
   * Property: For any non-existent secret ID (valid format but not in store),
   * the error response should be generic and indistinguishable from already-viewed.
   */
  it('non-existent secrets produce safe error responses', async () => {
    await fc.assert(
      fc.asyncProperty(
        nonExistentSecretIdArbitrary,
        async (secretId) => {
          const store = createWorkingStore();
          
          const response = await handleGetSecret(secretId, store);
          
          // Should return 404 Not Found
          expect(response.status).toBe(404);
          
          const body = await parseJsonResponse<ErrorResponse>(response);
          
          // Validate error response safety
          validateErrorResponseSafety(body);
          
          // Should return NOT_FOUND code
          expect(body.code).toBe('NOT_FOUND');
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 8.4**
   * 
   * Property: For any invalid JSON in request body,
   * the error response should be generic and not expose parsing details.
   */
  it('invalid JSON produces safe error responses', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate various invalid JSON strings
        fc.oneof(
          fc.constant('not json'),
          fc.constant('{invalid}'),
          fc.constant('{"unclosed": '),
          fc.constant('[1, 2, 3'),
          fc.constant('undefined'),
          fc.constant('NaN'),
          fc.string({ minLength: 1 }).filter(s => {
            try {
              JSON.parse(s);
              return false;
            } catch {
              return true;
            }
          })
        ),
        async (invalidJson) => {
          const store = createWorkingStore();
          
          const request = new Request('https://example.com/api/secrets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: invalidJson,
          });
          
          const response = await handleCreateSecret(request, store);
          
          // Should return 400 Bad Request
          expect(response.status).toBe(400);
          
          const body = await parseJsonResponse<ErrorResponse>(response);
          
          // Validate error response safety
          validateErrorResponseSafety(body);
          
          // Should return INVALID_REQUEST code
          expect(body.code).toBe('INVALID_REQUEST');
          
          // Error message should NOT contain the invalid JSON
          // (skip check for empty strings as they are trivially contained in any string)
          if (invalidJson.length > 0) {
            expect(body.error).not.toContain(invalidJson);
          }
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 8.4**
   * 
   * Property: Error responses should only contain the expected fields
   * (error and code) and no additional sensitive information.
   */
  it('error responses contain only expected fields', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          // Invalid request
          fc.constant({ type: 'invalid_request', body: {} }),
          // Non-existent secret
          fc.constant({ type: 'not_found', secretId: 'Abc123XYZ789defg' }),
          // Internal error
          fc.constant({ type: 'internal_error', errorMessage: 'KV failed' })
        ),
        async (scenario) => {
          let response: Response;
          
          if (scenario.type === 'invalid_request') {
            const store = createWorkingStore();
            const request = createSecretRequest(scenario.body);
            response = await handleCreateSecret(request, store);
          } else if (scenario.type === 'not_found') {
            const store = createWorkingStore();
            response = await handleGetSecret(scenario.secretId, store);
          } else {
            const failingStore = createFailingStore(scenario.errorMessage);
            const validBody = {
              encryptedBlob: {
                ciphertext: 'dGVzdA==',
                iv: 'dGVzdGl2MTIzNA==',
                tag: 'dGVzdHRhZzEyMzQ1Ng==',
              },
              privateKeyPart: 'dGVzdHByaXZhdGVrZXk=',
            };
            const request = createSecretRequest(validBody);
            response = await handleCreateSecret(request, failingStore);
          }
          
          const body = await parseJsonResponse<ErrorResponse>(response);
          
          // Check that only expected fields are present
          const actualFields = Object.keys(body);
          expect(actualFields.length).toBe(2);
          expect(actualFields).toContain('error');
          expect(actualFields).toContain('code');
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 8.4**
   * 
   * Property: Error responses should not contain stack traces,
   * regardless of the type of error that occurred.
   */
  it('error responses never contain stack traces', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate error messages that look like stack traces
        fc.oneof(
          fc.constant('Error: Something failed\n    at handleRequest (/src/worker/handlers.ts:100:15)\n    at processRequest (/src/worker/index.ts:50:10)'),
          fc.constant('TypeError: Cannot read property \'id\' of undefined\n    at Object.<anonymous> (/src/worker/secret-store.ts:25:20)'),
          fc.constant('ReferenceError: secretId is not defined\n    at getSecret (/src/worker/handlers.ts:75:5)'),
          internalErrorMessageArbitrary
        ),
        async (errorWithStackTrace) => {
          const failingStore = createFailingStore(errorWithStackTrace);
          
          const validBody = {
            encryptedBlob: {
              ciphertext: 'dGVzdA==',
              iv: 'dGVzdGl2MTIzNA==',
              tag: 'dGVzdHRhZzEyMzQ1Ng==',
            },
            privateKeyPart: 'dGVzdHByaXZhdGVrZXk=',
          };
          const request = createSecretRequest(validBody);
          
          const response = await handleCreateSecret(request, failingStore);
          const body = await parseJsonResponse<ErrorResponse>(response);
          
          // Error message should not contain stack trace patterns
          expect(body.error).not.toMatch(/at\s+\w+\s+\(/);
          expect(body.error).not.toMatch(/\.ts:\d+:\d+/);
          expect(body.error).not.toMatch(/\.js:\d+:\d+/);
          expect(body.error).not.toContain('\n');
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 8.4**
   * 
   * Property: Unknown routes should return safe NOT_FOUND responses.
   */
  it('unknown routes produce safe error responses', async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate random API paths (must start with /api/)
        fc.stringOf(
          fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789/-_'),
          { minLength: 1, maxLength: 50 }
        ).map(path => `/api/${path}`),
        // Generate random HTTP methods
        fc.constantFrom('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'),
        async (path, method) => {
          // Skip valid routes
          if (path === '/api/secrets' && method === 'POST') return true;
          if (path.match(/^\/api\/secrets\/[A-Za-z0-9]{16}$/) && method === 'GET') return true;
          
          const store = createWorkingStore();
          const request = new Request(`https://example.com${path}`, { method });
          
          const response = await handleRequest(request, store);
          
          // API routes should always return a response (not null)
          expect(response).not.toBeNull();
          
          // Should return 404 Not Found
          expect(response!.status).toBe(404);
          
          const body = await parseJsonResponse<ErrorResponse>(response!);
          
          // Validate error response safety
          validateErrorResponseSafety(body);
          
          // Error message should NOT contain the path
          expect(body.error).not.toContain(path);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});
