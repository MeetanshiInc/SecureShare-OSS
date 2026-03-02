/**
 * SecretCreator module for secure secret sharing
 * 
 * Orchestrates the secret creation flow:
 * 1. Generate a cryptographically secure 256-bit key
 * 2. Split the key into public (URL fragment) and private (server) parts
 * 3. Encrypt the secret content using AES-256-GCM
 * 4. Optionally apply double encryption with password-derived key
 * 5. Send ONLY the encrypted blob and private key part to the API
 * 6. Build and return a shareable URL with the public key part in the fragment
 * 
 * Security guarantees:
 * - The public key part is NEVER sent to the server (Requirement 6.3)
 * - The unencrypted secret content is NEVER sent to the server (Requirement 6.4)
 * - All encryption happens client-side using Web Crypto API
 * 
 * Requirements:
 * - 1.1: Generate cryptographically secure random key using Web Crypto API
 * - 1.2: Split key into Public_Key_Part and Private_Key_Part
 * - 1.3: Encrypt the secret using AES-256-GCM with the Combined_Key
 * - 1.4: Send only the Encrypted_Blob and Private_Key_Part to the Backend_API
 * - 1.7: Construct a shareable URL with the Secret_ID in the path and Public_Key_Part in the URL_Fragment
 * - 3.3: When a password is provided, first encrypt with Combined_Key, then with Password_Derived_Key
 * - 3.4: Store the salt alongside the encrypted data
 * - 6.3: The Backend_API SHALL never receive the Public_Key_Part or the Combined_Key
 * - 6.4: The Backend_API SHALL never receive unencrypted secret content
 */

import { generateKey, splitKey } from '../shared/crypto/key-generator.js';
import { encrypt, type EncryptedPayload } from '../shared/crypto/encryptor.js';
import { generateSalt, deriveKey } from '../shared/crypto/password-deriver.js';
import { toBase64url } from '../shared/encoding.js';
import { buildSecretUrl } from '../shared/url-utils.js';
import { clearBuffer, clearBuffers } from '../shared/crypto/secure-memory.js';

/**
 * Valid expiration options for secrets
 */
export type ExpirationOption = '1h' | '24h' | '7d' | '30d';

/**
 * Options for creating a new secret
 */
export interface CreateSecretOptions {
  /** The secret content to encrypt and share */
  content: string;
  /** Optional password for additional encryption layer */
  password?: string;
  /** Optional expiration duration */
  expiresIn?: ExpirationOption;
  /** Optional email address for view notification */
  notifyEmail?: string;
}

/**
 * Request body sent to the API (excludes public key part and plaintext)
 */
export interface CreateSecretApiRequest {
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
 * Response from the API after creating a secret
 */
export interface CreateSecretApiResponse {
  /** The unique identifier for the created secret */
  secretId: string;
}

/**
 * Error thrown when secret creation fails
 */
export class SecretCreationError extends Error {
  constructor(
    message: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'SecretCreationError';
  }
}

/**
 * Configuration for the SecretCreator
 */
export interface SecretCreatorConfig {
  /** Base URL of the application (e.g., "https://example.com") */
  baseUrl: string;
  /** API endpoint for creating secrets (e.g., "/api/secrets") */
  apiEndpoint: string;
}

/**
 * Default configuration using relative paths
 */
export const DEFAULT_CONFIG: SecretCreatorConfig = {
  baseUrl: typeof window !== 'undefined' ? window.location.origin : 'https://localhost',
  apiEndpoint: '/api/secrets',
};

/**
 * Creates a new secret and returns a shareable URL.
 * 
 * This function orchestrates the entire secret creation flow:
 * 1. Generates a 256-bit cryptographic key
 * 2. Splits the key into public and private parts
 * 3. Encrypts the secret content with AES-256-GCM
 * 4. Sends the encrypted blob and private key part to the API
 * 5. Builds a shareable URL with the public key part in the fragment
 * 
 * Security: The public key part and plaintext content are NEVER sent to the server.
 * 
 * @param options - The secret creation options
 * @param config - Optional configuration (defaults to current origin)
 * @param fetchFn - Optional fetch function for testing (defaults to global fetch)
 * @returns Promise resolving to the shareable URL
 * @throws SecretCreationError if any step fails
 * 
 * @example
 * const url = await createSecret({
 *   content: "My secret message",
 *   expiresIn: "24h"
 * });
 * // Returns: "https://example.com/s/abc123def456gh78#AAAAAAAAAAAAAAAAAAAAAA"
 */
export async function createSecret(
  options: CreateSecretOptions,
  config: SecretCreatorConfig = DEFAULT_CONFIG,
  fetchFn: typeof fetch = fetch
): Promise<string> {
  const { content, password, expiresIn, notifyEmail } = options;

  // Validate content
  if (typeof content !== 'string') {
    throw new SecretCreationError('Secret content must be a string');
  }

  // Step 1: Generate a 256-bit cryptographic key (Requirement 1.1)
  let key: Uint8Array;
  try {
    key = await generateKey();
  } catch (error) {
    // Design spec: "Unable to generate secure key. Please try again."
    throw new SecretCreationError(
      'Unable to generate secure key. Please try again.',
      error instanceof Error ? error : undefined
    );
  }

  // Track sensitive buffers for cleanup (Requirement 8.6)
  let publicPart: Uint8Array | undefined;
  let privatePart: Uint8Array | undefined;
  let passwordSalt: Uint8Array | undefined;
  let passwordDerivedKey: Uint8Array | undefined;

  try {
    // Step 2: Split the key into public and private parts (Requirement 1.2)
    const splitResult = splitKey(key);
    publicPart = splitResult.publicPart;
    privatePart = splitResult.privatePart;

    // Step 3: Encrypt the secret content with AES-256-GCM (Requirement 1.3)
    let encryptedBlob: Awaited<ReturnType<typeof encrypt>>;
    try {
      encryptedBlob = await encrypt(content, key);
    } catch (error) {
      // Design spec: "Encryption failed. Please try again."
      throw new SecretCreationError(
        'Encryption failed. Please try again.',
        error instanceof Error ? error : undefined
      );
    }

    // Step 3.5: If password provided, apply double encryption (Requirement 3.3)
    // First encryption was with Combined_Key, now encrypt with Password_Derived_Key
    if (password) {
      // Generate a random salt for password derivation
      passwordSalt = generateSalt();
      
      // Derive a key from the password using PBKDF2 (Requirement 3.2)
      passwordDerivedKey = await deriveKey(password, passwordSalt);
      
      // Double encryption: encrypt the already-encrypted blob's ciphertext
      // We serialize the first encrypted payload and encrypt it again
      const firstEncryptionJson = JSON.stringify(encryptedBlob);
      try {
        encryptedBlob = await encrypt(firstEncryptionJson, passwordDerivedKey);
      } catch (error) {
        // Design spec: "Encryption failed. Please try again."
        throw new SecretCreationError(
          'Encryption failed. Please try again.',
          error instanceof Error ? error : undefined
        );
      }
    }

    // Step 4: Encode the key parts for transport
    const publicKeyPartEncoded = toBase64url(publicPart);
    const privateKeyPartEncoded = toBase64url(privatePart);

    // Step 5: Build the API request (Requirement 1.4)
    // SECURITY: Only send encrypted blob and private key part
    // The public key part is NEVER sent to the server (Requirement 6.3)
    // The plaintext content is NEVER sent to the server (Requirement 6.4)
    const apiRequest: CreateSecretApiRequest = {
      encryptedBlob,
      privateKeyPart: privateKeyPartEncoded,
    };

    // Add optional fields if provided
    if (expiresIn) {
      apiRequest.expiresIn = expiresIn;
    }
    if (notifyEmail) {
      apiRequest.notifyEmail = notifyEmail;
    }
    // Include password salt if password protection is enabled (Requirement 3.4)
    if (passwordSalt) {
      apiRequest.passwordSalt = toBase64url(passwordSalt);
    }

    // Step 6: Send the request to the API
    const apiUrl = `${config.baseUrl}${config.apiEndpoint}`;
    let response: Response;
    try {
      response = await fetchFn(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(apiRequest),
      });
    } catch (error) {
      // Design spec: "Network error. Please check your connection."
      throw new SecretCreationError(
        'Network error. Please check your connection.',
        error instanceof Error ? error : undefined
      );
    }

    // Handle API errors
    if (!response.ok) {
      let errorMessage = 'Failed to create secret';
      try {
        const errorBody = await response.json() as { error?: string };
        if (errorBody && typeof errorBody.error === 'string') {
          errorMessage = errorBody.error;
        }
      } catch {
        // Ignore JSON parsing errors, use default message
      }
      throw new SecretCreationError(`API error: ${errorMessage}`);
    }

    // Parse the API response
    let apiResponse: CreateSecretApiResponse;
    try {
      apiResponse = await response.json();
    } catch {
      throw new SecretCreationError('Invalid API response format');
    }

    // Validate the response
    if (!apiResponse.secretId || typeof apiResponse.secretId !== 'string') {
      throw new SecretCreationError('API response missing secretId');
    }

    // Step 7: Build the shareable URL (Requirement 1.7)
    // The public key part goes in the URL fragment (never sent to server)
    const shareableUrl = buildSecretUrl({
      baseUrl: config.baseUrl,
      secretId: apiResponse.secretId,
      publicKeyPart: publicKeyPartEncoded,
    });

    return shareableUrl;
  } catch (error) {
    // Re-throw SecretCreationError as-is
    if (error instanceof SecretCreationError) {
      throw error;
    }

    // Wrap other errors
    const message = error instanceof Error ? error.message : 'Unknown error';
    throw new SecretCreationError(`Failed to create secret: ${message}`, error instanceof Error ? error : undefined);
  } finally {
    // SECURITY: Clear all sensitive buffers from memory (Requirement 8.6)
    // This ensures keys are cleared even if an error occurs
    clearBuffer(key);
    clearBuffers(publicPart, privatePart, passwordSalt, passwordDerivedKey);
  }
}

/**
 * SecretCreator interface for dependency injection and testing
 */
export interface SecretCreator {
  createSecret(options: CreateSecretOptions): Promise<string>;
}

/**
 * Creates a SecretCreator instance with the given configuration
 * 
 * @param config - Configuration for the SecretCreator
 * @param fetchFn - Optional fetch function for testing
 * @returns SecretCreator instance
 */
export function createSecretCreator(
  config: SecretCreatorConfig = DEFAULT_CONFIG,
  fetchFn: typeof fetch = fetch
): SecretCreator {
  return {
    createSecret: (options: CreateSecretOptions) => createSecret(options, config, fetchFn),
  };
}
