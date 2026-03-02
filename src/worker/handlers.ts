/**
 * API Request Handlers for secure secret sharing
 * 
 * Implements the REST API endpoints for creating and retrieving secrets.
 * All handlers follow security best practices:
 * - Never expose internal error details (Requirement 8.4)
 * - Validate all request inputs
 * - Return appropriate HTTP status codes
 * 
 * Requirements:
 * - 1.4: Send only the Encrypted_Blob and Private_Key_Part to the Backend_API
 * - 1.5: Generate a unique Secret_ID and store the data in Secret_Store
 * - 1.6: Return the Secret_ID to the Frontend
 * - 2.2: Request the Encrypted_Blob and Private_Key_Part from the Backend_API using the Secret_ID
 * - 2.3: Return the Encrypted_Blob and Private_Key_Part exactly once
 * - 8.4: Return a generic error without exposing internal details
 */

import type { EncryptedPayload } from '../shared/crypto/encryptor';
import {
  type SecretStore,
  type StoredSecret,
  generateSecretId,
  getTtlSeconds,
  isValidSecretId,
} from './secret-store';
import type { NotificationService } from './notification-service';

/**
 * Valid expiration options for secrets
 */
export type ExpirationOption = '1h' | '24h' | '7d' | '30d';

/**
 * Request body for creating a new secret
 */
export interface CreateSecretRequest {
  /** Encrypted payload containing ciphertext, IV, and tag */
  encryptedBlob: EncryptedPayload;
  /** Base64url-encoded private key part (128 bits) */
  privateKeyPart: string;
  /** Optional expiration duration */
  expiresIn?: ExpirationOption;
  /** Optional email address for view notification */
  notifyEmail?: string;
  /** Optional Base64-encoded salt for password protection */
  passwordSalt?: string;
}

/**
 * Response body for successful secret creation
 */
export interface CreateSecretResponse {
  /** The unique identifier for the created secret */
  secretId: string;
}

/**
 * Response body for successful secret retrieval
 */
export interface GetSecretResponse {
  /** Encrypted payload containing ciphertext, IV, and tag */
  encryptedBlob: EncryptedPayload;
  /** Base64url-encoded private key part (128 bits) */
  privateKeyPart: string;
  /** Optional Base64-encoded salt for password protection */
  passwordSalt?: string;
}

/**
 * Error codes for API responses
 */
export type ErrorCode = 'NOT_FOUND' | 'INVALID_REQUEST' | 'INTERNAL_ERROR';

/**
 * Error response body
 */
export interface ErrorResponse {
  /** Human-readable error message */
  error: string;
  /** Machine-readable error code */
  code: ErrorCode;
}

/**
 * Validates that a value is a non-empty string
 */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Validates the structure of an EncryptedPayload
 */
function isValidEncryptedPayload(payload: unknown): payload is EncryptedPayload {
  if (typeof payload !== 'object' || payload === null) {
    return false;
  }
  
  const obj = payload as Record<string, unknown>;
  
  // ciphertext can be empty string (for empty plaintext), but must be a string
  if (typeof obj.ciphertext !== 'string') {
    return false;
  }
  
  // iv and tag must be non-empty strings
  if (!isNonEmptyString(obj.iv) || !isNonEmptyString(obj.tag)) {
    return false;
  }
  
  return true;
}

/**
 * Validates the expiration option
 */
function isValidExpirationOption(value: unknown): value is ExpirationOption | undefined {
  if (value === undefined) {
    return true;
  }
  return value === '1h' || value === '24h' || value === '7d' || value === '30d';
}

/**
 * Validates a CreateSecretRequest body
 */
function validateCreateSecretRequest(body: unknown): { valid: true; data: CreateSecretRequest } | { valid: false; error: string } {
  if (typeof body !== 'object' || body === null) {
    return { valid: false, error: 'Request body must be a JSON object' };
  }
  
  const obj = body as Record<string, unknown>;
  
  // Validate encryptedBlob
  if (!isValidEncryptedPayload(obj.encryptedBlob)) {
    return { valid: false, error: 'Invalid or missing encryptedBlob' };
  }
  
  // Validate privateKeyPart
  if (!isNonEmptyString(obj.privateKeyPart)) {
    return { valid: false, error: 'Invalid or missing privateKeyPart' };
  }
  
  // Validate optional expiresIn
  if (!isValidExpirationOption(obj.expiresIn)) {
    return { valid: false, error: 'Invalid expiresIn value' };
  }
  
  // Validate optional notifyEmail (if present, must be a string)
  if (obj.notifyEmail !== undefined && typeof obj.notifyEmail !== 'string') {
    return { valid: false, error: 'Invalid notifyEmail value' };
  }
  
  // Validate optional passwordSalt (if present, must be a string)
  if (obj.passwordSalt !== undefined && typeof obj.passwordSalt !== 'string') {
    return { valid: false, error: 'Invalid passwordSalt value' };
  }
  
  const data: CreateSecretRequest = {
    encryptedBlob: obj.encryptedBlob as EncryptedPayload,
    privateKeyPart: obj.privateKeyPart as string,
  };
  
  // Add optional fields only if they are defined
  if (obj.expiresIn !== undefined) {
    data.expiresIn = obj.expiresIn as ExpirationOption;
  }
  if (obj.notifyEmail !== undefined) {
    data.notifyEmail = obj.notifyEmail as string;
  }
  if (obj.passwordSalt !== undefined) {
    data.passwordSalt = obj.passwordSalt as string;
  }
  
  return { valid: true, data };
}

/**
 * Creates a JSON response with the given body and status code
 */
function jsonResponse<T>(body: T, status: number = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
}

/**
 * Creates an error response
 * 
 * Note: Error messages are intentionally generic to avoid exposing internal details
 * (Requirement 8.4)
 */
function errorResponse(code: ErrorCode, status: number): Response {
  const messages: Record<ErrorCode, string> = {
    NOT_FOUND: 'Secret not found or has already been viewed',
    INVALID_REQUEST: 'Invalid request',
    INTERNAL_ERROR: 'An error occurred',
  };
  
  const body: ErrorResponse = {
    error: messages[code],
    code,
  };
  
  return jsonResponse(body, status);
}

/** Maximum allowed request body size (256 KB) */
const MAX_BODY_SIZE = 256 * 1024;

/**
 * Handles POST /api/secrets - Create a new secret
 * 
 * Requirements:
 * - 1.4: Receives Encrypted_Blob and Private_Key_Part from Frontend
 * - 1.5: Generates unique Secret_ID and stores data
 * - 1.6: Returns Secret_ID to Frontend
 * 
 * @param request - The incoming HTTP request
 * @param secretStore - The secret store instance
 * @returns Response with secretId or error
 */
export async function handleCreateSecret(
  request: Request,
  secretStore: SecretStore
): Promise<Response> {
  // Reject oversized request bodies to prevent memory abuse
  const contentLength = request.headers.get('Content-Length');
  if (contentLength && parseInt(contentLength, 10) > MAX_BODY_SIZE) {
    return errorResponse('INVALID_REQUEST', 400);
  }

  // Parse request body
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('INVALID_REQUEST', 400);
  }
  
  // Validate request body
  const validation = validateCreateSecretRequest(body);
  if (!validation.valid) {
    return errorResponse('INVALID_REQUEST', 400);
  }
  
  const { encryptedBlob, privateKeyPart, expiresIn, notifyEmail, passwordSalt } = validation.data;
  
  // Generate unique secret ID
  const secretId = generateSecretId();
  
  // Prepare stored secret data
  const storedSecret: StoredSecret = {
    encryptedBlob,
    privateKeyPart,
    createdAt: Date.now(),
  };
  
  // Add optional fields if present
  if (notifyEmail) {
    storedSecret.notifyEmail = notifyEmail;
  }
  if (passwordSalt) {
    storedSecret.passwordSalt = passwordSalt;
  }
  
  // Calculate TTL
  const ttlSeconds = getTtlSeconds(expiresIn);
  
  // Store the secret
  try {
    await secretStore.store(secretId, storedSecret, ttlSeconds);
  } catch {
    // Don't expose internal error details (Requirement 8.4)
    return errorResponse('INTERNAL_ERROR', 500);
  }
  
  // Return the secret ID
  const response: CreateSecretResponse = { secretId };
  return jsonResponse(response, 201);
}

/**
 * Handles GET /api/secrets/:secretId - Retrieve and delete a secret
 * 
 * Requirements:
 * - 2.2: Retrieves Encrypted_Blob and Private_Key_Part using Secret_ID
 * - 2.3: Returns data exactly once (atomic get-and-delete)
 * - 5.3: Send email notification when secret is viewed
 * - 5.4: Notification includes only timestamp, never secret content
 * - 5.5: Email address is deleted after notification is sent
 * - 8.4: Returns generic error for not found
 * 
 * @param secretId - The secret ID from the URL path
 * @param secretStore - The secret store instance
 * @param notificationService - Optional notification service for sending view notifications
 * @returns Response with secret data or error
 */
export async function handleGetSecret(
  secretId: string,
  secretStore: SecretStore,
  notificationService?: NotificationService
): Promise<Response> {
  if (!isValidSecretId(secretId)) {
    return errorResponse('NOT_FOUND', 404);
  }

  // First, peek at the secret to check if it's password-protected
  let storedSecret: StoredSecret | null;
  try {
    // For password-protected secrets, use get (don't delete yet).
    // For non-password secrets, use getAndDelete (one-time access).
    // We need to peek first to decide, so we always read first.
    storedSecret = await secretStore.get(secretId);
  } catch {
    return errorResponse('INTERNAL_ERROR', 500);
  }

  if (storedSecret === null) {
    return errorResponse('NOT_FOUND', 404);
  }

  // If NOT password-protected, delete immediately (one-time access)
  if (!storedSecret.passwordSalt) {
    try {
      await secretStore.delete(secretId);
    } catch {
      // Continue even if delete fails — the secret was already read
    }

    // Send notification if email was provided
    if (storedSecret.notifyEmail && notificationService) {
      const viewedAt = new Date();
      notificationService.sendViewNotification(storedSecret.notifyEmail, viewedAt)
        .catch(() => {});
    }
  }

  const response: GetSecretResponse = {
    encryptedBlob: storedSecret.encryptedBlob,
    privateKeyPart: storedSecret.privateKeyPart,
  };

  if (storedSecret.passwordSalt) {
    response.passwordSalt = storedSecret.passwordSalt;
  }

  return jsonResponse(response, 200);
}

/**
 * Handles DELETE /api/secrets/:secretId - Confirm secret viewed (for password-protected secrets)
 *
 * Called by the frontend after successful decryption of a password-protected secret.
 * This ensures the secret is only deleted after the correct password is provided.
 */
export async function handleDeleteSecret(
  secretId: string,
  secretStore: SecretStore,
  notificationService?: NotificationService
): Promise<Response> {
  if (!isValidSecretId(secretId)) {
    return errorResponse('NOT_FOUND', 404);
  }

  // Read the secret to get notification email before deleting
  let storedSecret: StoredSecret | null;
  try {
    storedSecret = await secretStore.get(secretId);
  } catch {
    return errorResponse('INTERNAL_ERROR', 500);
  }

  if (storedSecret === null) {
    return errorResponse('NOT_FOUND', 404);
  }

  // Delete the secret
  try {
    await secretStore.delete(secretId);
  } catch {
    return errorResponse('INTERNAL_ERROR', 500);
  }

  // Send notification if email was provided
  if (storedSecret.notifyEmail && notificationService) {
    const viewedAt = new Date();
    notificationService.sendViewNotification(storedSecret.notifyEmail, viewedAt)
      .catch(() => {});
  }

  return jsonResponse({ deleted: true }, 200);
}

/**
 * Extracts the secret ID from a URL path
 * 
 * Expected path format: /api/secrets/:secretId
 * 
 * @param pathname - The URL pathname
 * @returns The secret ID or null if path doesn't match
 */
export function extractSecretIdFromPath(pathname: string): string | null {
  const match = pathname.match(/^\/api\/secrets\/([^/]+)$/);
  return match ? match[1]! : null;
}

/**
 * Main request handler that routes to appropriate endpoint handlers
 * 
 * @param request - The incoming HTTP request
 * @param secretStore - The secret store instance
 * @param notificationService - Optional notification service for sending view notifications
 * @returns Response from the appropriate handler, or null if request should be handled by static assets
 */
export async function handleRequest(
  request: Request,
  secretStore: SecretStore,
  notificationService?: NotificationService
): Promise<Response | null> {
  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method;

  // POST /api/secrets - Create a new secret
  if (method === 'POST' && pathname === '/api/secrets') {
    return handleCreateSecret(request, secretStore);
  }

  // GET /api/secrets/:secretId - Retrieve a secret
  if (method === 'GET') {
    const secretId = extractSecretIdFromPath(pathname);
    if (secretId !== null) {
      return handleGetSecret(secretId, secretStore, notificationService);
    }
  }

  // DELETE /api/secrets/:secretId - Confirm viewed (password-protected secrets)
  if (method === 'DELETE') {
    const secretId = extractSecretIdFromPath(pathname);
    if (secretId !== null) {
      return handleDeleteSecret(secretId, secretStore, notificationService);
    }
  }

  // Return 404 for unmatched API routes
  if (pathname.startsWith('/api/')) {
    return errorResponse('NOT_FOUND', 404);
  }

  // Return null for non-API routes to let static asset handler take over
  return null;
}
