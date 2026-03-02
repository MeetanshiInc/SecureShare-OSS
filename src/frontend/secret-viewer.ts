/**
 * SecretViewer module for secure secret sharing
 * 
 * Orchestrates the secret viewing flow:
 * 1. Extract the Secret_ID from the URL path and Public_Key_Part from the URL fragment
 * 2. Request the Encrypted_Blob and Private_Key_Part from the Backend_API
 * 3. Combine the Public_Key_Part and Private_Key_Part to reconstruct the Combined_Key
 * 4. Decrypt the Encrypted_Blob using AES-256-GCM with the Combined_Key
 * 5. Display the decrypted secret content to the user
 * 
 * For password-protected secrets:
 * 1. Return a result indicating password is required (with the salt)
 * 2. Caller prompts for password and calls decryptWithPassword()
 * 3. Derive key from password using the salt
 * 4. First decrypt with password-derived key (outer layer)
 * 5. Then decrypt with combined key (inner layer)
 * 
 * Security guarantees:
 * - The public key part is extracted from the URL fragment (never sent to server)
 * - All decryption happens client-side using Web Crypto API
 * - The server never has access to the complete decryption key
 * - Wrong password attempts do not consume the one-time access (handled by backend)
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

import { combineKey } from '../shared/crypto/key-generator.js';
import { decrypt, type EncryptedPayload } from '../shared/crypto/encryptor.js';
import { deriveKey } from '../shared/crypto/password-deriver.js';
import { fromBase64url } from '../shared/encoding.js';
import { parseSecretUrl, type ParsedSecretUrl } from '../shared/url-utils.js';
import { clearBuffers } from '../shared/crypto/secure-memory.js';

/**
 * Response from the API when retrieving a secret
 */
export interface GetSecretApiResponse {
  /** Encrypted payload containing ciphertext, IV, and tag */
  encryptedBlob: EncryptedPayload;
  /** Base64url-encoded private key part (128 bits) */
  privateKeyPart: string;
  /** Optional Base64-encoded salt for password protection */
  passwordSalt?: string;
}

/**
 * Error response from the API
 */
export interface ApiErrorResponse {
  /** Human-readable error message */
  error: string;
  /** Machine-readable error code */
  code: 'NOT_FOUND' | 'INVALID_REQUEST' | 'INTERNAL_ERROR';
}

/**
 * Result of viewing a secret - either decrypted content or password required
 */
export type ViewSecretResult = ViewSecretSuccess | ViewSecretPasswordRequired;

/**
 * Successful decryption result
 */
export interface ViewSecretSuccess {
  /** Indicates successful decryption */
  status: 'success';
  /** The decrypted secret content */
  content: string;
  /** Whether the secret was password-protected */
  isPasswordProtected: boolean;
}

/**
 * Result indicating password is required for decryption
 */
export interface ViewSecretPasswordRequired {
  /** Indicates password is required */
  status: 'password_required';
  /** The secret ID for later deletion after successful decryption */
  secretId: string;
  /** The password salt (Base64url-encoded) for key derivation */
  passwordSalt: string;
  /** The encrypted blob for later decryption */
  encryptedBlob: EncryptedPayload;
  /** The private key part (Base64url-encoded) for later decryption */
  privateKeyPart: string;
  /** The public key part (Base64url-encoded) from the URL fragment */
  publicKeyPart: string;
}

/**
 * Error types for secret viewing
 */
export type SecretViewErrorType =
  | 'INVALID_URL'
  | 'SECRET_NOT_FOUND'
  | 'SECRET_ALREADY_VIEWED'
  | 'NETWORK_ERROR'
  | 'DECRYPTION_FAILED'
  | 'INVALID_RESPONSE'
  | 'WRONG_PASSWORD';

/**
 * Error thrown when secret viewing fails
 */
export class SecretViewError extends Error {
  constructor(
    message: string,
    public readonly type: SecretViewErrorType,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'SecretViewError';
  }
}

/**
 * Configuration for the SecretViewer
 */
export interface SecretViewerConfig {
  /** Base URL of the application (e.g., "https://example.com") */
  baseUrl: string;
  /** API endpoint for retrieving secrets (e.g., "/api/secrets") */
  apiEndpoint: string;
}

/**
 * Default configuration using relative paths
 */
export const DEFAULT_CONFIG: SecretViewerConfig = {
  baseUrl: typeof window !== 'undefined' ? window.location.origin : 'https://localhost',
  apiEndpoint: '/api/secrets',
};

/**
 * Extracts the secret ID and public key part from the current URL.
 * 
 * This function parses the URL to extract:
 * - Secret ID from the path (/s/{secretId})
 * - Public key part from the fragment (#{publicKeyPart})
 * 
 * @param url - The full URL to parse
 * @returns The parsed secret ID and public key part
 * @throws SecretViewError if the URL format is invalid
 * 
 * Requirements:
 * - 2.1: Extract the Secret_ID from the URL path and the Public_Key_Part from the URL_Fragment
 */
export function extractSecretInfoFromUrl(url: string): ParsedSecretUrl {
  try {
    return parseSecretUrl(url);
  } catch (error) {
    // Design spec: "Invalid secret link format."
    throw new SecretViewError(
      'Invalid secret link format.',
      'INVALID_URL',
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Fetches the encrypted secret data from the API.
 * 
 * This function:
 * 1. Makes a GET request to /api/secrets/{secretId}
 * 2. Handles various error responses (404, 410, etc.)
 * 3. Returns the encrypted blob and private key part
 * 
 * @param secretId - The secret ID to retrieve
 * @param config - Configuration options
 * @param fetchFn - Optional fetch function for testing
 * @returns The API response with encrypted data
 * @throws SecretViewError if the request fails
 * 
 * Requirements:
 * - 2.2: Request the Encrypted_Blob and Private_Key_Part from the Backend_API using the Secret_ID
 * - 2.9: Display an appropriate error message if the secret has already been viewed or does not exist
 */
export async function fetchSecretFromApi(
  secretId: string,
  config: SecretViewerConfig = DEFAULT_CONFIG,
  fetchFn: typeof fetch = fetch
): Promise<GetSecretApiResponse> {
  const apiUrl = `${config.baseUrl}${config.apiEndpoint}/${secretId}`;

  let response: Response;
  try {
    response = await fetchFn(apiUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });
  } catch (error) {
    // Design spec: "Network error. Please check your connection."
    throw new SecretViewError(
      'Network error. Please check your connection.',
      'NETWORK_ERROR',
      error instanceof Error ? error : undefined
    );
  }

  // Handle error responses
  if (!response.ok) {
    // Handle 404 - Secret not found or already viewed
    // Design spec: "This secret has already been viewed or has expired."
    if (response.status === 404) {
      throw new SecretViewError(
        'This secret has already been viewed or has expired.',
        'SECRET_NOT_FOUND'
      );
    }

    // Handle 410 Gone - Secret was explicitly marked as viewed
    // Design spec: "This secret has already been viewed or has expired."
    if (response.status === 410) {
      throw new SecretViewError(
        'This secret has already been viewed or has expired.',
        'SECRET_ALREADY_VIEWED'
      );
    }

    // Handle other errors generically
    // Design spec: "Network error. Please check your connection."
    throw new SecretViewError(
      'Network error. Please check your connection.',
      'NETWORK_ERROR'
    );
  }

  // Parse the response
  let apiResponse: GetSecretApiResponse;
  try {
    apiResponse = await response.json();
  } catch {
    throw new SecretViewError(
      'Invalid response from server.',
      'INVALID_RESPONSE'
    );
  }

  // Validate the response structure
  if (!apiResponse.encryptedBlob || !apiResponse.privateKeyPart) {
    throw new SecretViewError(
      'Invalid response from server: missing required fields.',
      'INVALID_RESPONSE'
    );
  }

  return apiResponse;
}

/**
 * Decrypts the secret content using the combined key.
 * 
 * This function:
 * 1. Decodes the public and private key parts from Base64url
 * 2. Combines them to reconstruct the full 256-bit key
 * 3. Decrypts the encrypted blob using AES-256-GCM
 * 
 * @param encryptedBlob - The encrypted payload from the API
 * @param publicKeyPart - Base64url-encoded public key part from URL fragment
 * @param privateKeyPart - Base64url-encoded private key part from API
 * @returns The decrypted secret content
 * @throws SecretViewError if decryption fails
 * 
 * Requirements:
 * - 2.5: Combine the Public_Key_Part and Private_Key_Part to reconstruct the Combined_Key
 * - 2.6: Decrypt the Encrypted_Blob using AES-256-GCM with the Combined_Key
 */
export async function decryptSecret(
  encryptedBlob: EncryptedPayload,
  publicKeyPart: string,
  privateKeyPart: string
): Promise<string> {
  // Decode the key parts from Base64url
  let publicKeyBytes: Uint8Array | undefined;
  let privateKeyBytes: Uint8Array | undefined;
  let combinedKey: Uint8Array | undefined;

  try {
    try {
      publicKeyBytes = fromBase64url(publicKeyPart);
    } catch (error) {
      // Design spec: "Invalid secret link format."
      throw new SecretViewError(
        'Invalid secret link format.',
        'INVALID_URL',
        error instanceof Error ? error : undefined
      );
    }

    try {
      privateKeyBytes = fromBase64url(privateKeyPart);
    } catch (error) {
      // Design spec: "Invalid secret link format." (server data corruption)
      throw new SecretViewError(
        'Invalid secret link format.',
        'INVALID_RESPONSE',
        error instanceof Error ? error : undefined
      );
    }

    // Combine the key parts to reconstruct the full key (Requirement 2.5)
    try {
      combinedKey = combineKey(publicKeyBytes, privateKeyBytes);
    } catch (error) {
      // Design spec: "Unable to decrypt secret. The link may be invalid."
      throw new SecretViewError(
        'Unable to decrypt secret. The link may be invalid.',
        'DECRYPTION_FAILED',
        error instanceof Error ? error : undefined
      );
    }

    // Decrypt the secret content (Requirement 2.6)
    try {
      const decryptedContent = await decrypt(encryptedBlob, combinedKey);
      return decryptedContent;
    } catch (error) {
      // Design spec: "Unable to decrypt secret. The link may be invalid."
      throw new SecretViewError(
        'Unable to decrypt secret. The link may be invalid.',
        'DECRYPTION_FAILED',
        error instanceof Error ? error : undefined
      );
    }
  } finally {
    // SECURITY: Clear all sensitive buffers from memory (Requirement 8.6)
    clearBuffers(publicKeyBytes, privateKeyBytes, combinedKey);
  }
}

/**
 * Views a secret by retrieving and decrypting it.
 * 
 * This is the main entry point for viewing secrets. It orchestrates:
 * 1. Extracting secret info from the URL
 * 2. Fetching encrypted data from the API
 * 3. Combining keys and decrypting the content
 * 
 * For password-protected secrets, this function will return a result
 * with status='password_required' containing the salt and encrypted data.
 * The caller should then prompt for the password and call decryptWithPassword().
 * 
 * @param url - The full secret URL (including fragment)
 * @param config - Optional configuration
 * @param fetchFn - Optional fetch function for testing
 * @returns The decrypted secret content or password-required result
 * @throws SecretViewError if any step fails
 * 
 * Requirements:
 * - 2.1: Extract the Secret_ID from the URL path and the Public_Key_Part from the URL_Fragment
 * - 2.2: Request the Encrypted_Blob and Private_Key_Part from the Backend_API using the Secret_ID
 * - 2.5: Combine the Public_Key_Part and Private_Key_Part to reconstruct the Combined_Key
 * - 2.6: Decrypt the Encrypted_Blob using AES-256-GCM with the Combined_Key
 * - 2.7: Display the decrypted secret content to the user
 * - 2.9: Display an appropriate error message if the secret has already been viewed or does not exist
 * - 3.5: When viewing a password-protected secret, prompt for the password and derive the key using the stored salt
 */
export async function viewSecret(
  url: string,
  config: SecretViewerConfig = DEFAULT_CONFIG,
  fetchFn: typeof fetch = fetch
): Promise<ViewSecretResult> {
  // Step 1: Extract secret ID and public key part from URL (Requirement 2.1)
  const { secretId, publicKeyPart } = extractSecretInfoFromUrl(url);

  // Step 2: Fetch encrypted data from API (Requirement 2.2)
  const apiResponse = await fetchSecretFromApi(secretId, config, fetchFn);

  // Check if password protection is enabled (Requirement 3.5)
  // Return password-required result so caller can prompt for password
  if (apiResponse.passwordSalt) {
    return {
      status: 'password_required',
      secretId,
      passwordSalt: apiResponse.passwordSalt,
      encryptedBlob: apiResponse.encryptedBlob,
      privateKeyPart: apiResponse.privateKeyPart,
      publicKeyPart,
    };
  }

  // Step 3 & 4: Combine keys and decrypt (Requirements 2.5, 2.6)
  const content = await decryptSecret(
    apiResponse.encryptedBlob,
    publicKeyPart,
    apiResponse.privateKeyPart
  );

  // Step 5: Return the decrypted content (Requirement 2.7)
  return {
    status: 'success',
    content,
    isPasswordProtected: false,
  };
}

/**
 * Views a secret using the secret ID and public key part directly.
 * 
 * This is an alternative entry point when the URL has already been parsed.
 * Useful for testing or when the URL parsing is done separately.
 * 
 * For password-protected secrets, this function will return a result
 * with status='password_required' containing the salt and encrypted data.
 * The caller should then prompt for the password and call decryptWithPassword().
 * 
 * @param secretId - The secret ID from the URL path
 * @param publicKeyPart - The public key part from the URL fragment
 * @param config - Optional configuration
 * @param fetchFn - Optional fetch function for testing
 * @returns The decrypted secret content or password-required result
 * @throws SecretViewError if any step fails
 */
export async function viewSecretById(
  secretId: string,
  publicKeyPart: string,
  config: SecretViewerConfig = DEFAULT_CONFIG,
  fetchFn: typeof fetch = fetch
): Promise<ViewSecretResult> {
  // Fetch encrypted data from API
  const apiResponse = await fetchSecretFromApi(secretId, config, fetchFn);

  // Check if password protection is enabled (Requirement 3.5)
  if (apiResponse.passwordSalt) {
    return {
      status: 'password_required',
      secretId,
      passwordSalt: apiResponse.passwordSalt,
      encryptedBlob: apiResponse.encryptedBlob,
      privateKeyPart: apiResponse.privateKeyPart,
      publicKeyPart,
    };
  }

  // Combine keys and decrypt
  const content = await decryptSecret(
    apiResponse.encryptedBlob,
    publicKeyPart,
    apiResponse.privateKeyPart
  );

  return {
    status: 'success',
    content,
    isPasswordProtected: false,
  };
}

/**
 * Decrypts a password-protected secret using the provided password.
 * 
 * This function performs double decryption:
 * 1. Derives a key from the password using PBKDF2 with the stored salt
 * 2. Decrypts the outer layer with the password-derived key
 * 3. Decrypts the inner layer with the combined key (public + private parts)
 * 
 * If the password is incorrect, this function throws a WRONG_PASSWORD error.
 * The caller can retry with a different password without consuming the one-time access
 * (the API does not delete the secret on failed password attempts).
 * 
 * @param passwordRequiredResult - The result from viewSecret/viewSecretById with status='password_required'
 * @param password - The password to use for decryption
 * @returns The decrypted secret content
 * @throws SecretViewError with type='WRONG_PASSWORD' if the password is incorrect
 * @throws SecretViewError with type='DECRYPTION_FAILED' if decryption fails for other reasons
 * 
 * Requirements:
 * - 3.5: When viewing a password-protected secret, prompt for the password and derive the key using the stored salt
 * - 3.6: Allow the user to retry with a different password if decryption fails, without consuming the one-time access
 */
export async function decryptWithPassword(
  passwordRequiredResult: ViewSecretPasswordRequired,
  password: string
): Promise<ViewSecretSuccess> {
  const {
    passwordSalt,
    encryptedBlob,
    privateKeyPart,
    publicKeyPart,
  } = passwordRequiredResult;

  // Track sensitive buffers for cleanup (Requirement 8.6)
  let saltBytes: Uint8Array | undefined;
  let passwordDerivedKey: Uint8Array | undefined;

  try {
    // Step 1: Decode the password salt from Base64url
    try {
      saltBytes = fromBase64url(passwordSalt);
    } catch (error) {
      throw new SecretViewError(
        'Invalid password salt from server.',
        'INVALID_RESPONSE',
        error instanceof Error ? error : undefined
      );
    }

    // Step 2: Derive the password key using PBKDF2 (Requirement 3.5)
    try {
      passwordDerivedKey = await deriveKey(password, saltBytes);
    } catch (error) {
      throw new SecretViewError(
        'Failed to derive key from password.',
        'DECRYPTION_FAILED',
        error instanceof Error ? error : undefined
      );
    }

    // Step 3: Decrypt the outer layer with the password-derived key
    // The outer layer contains a JSON-serialized EncryptedPayload
    let innerEncryptedPayload: EncryptedPayload;
    try {
      const innerJson = await decrypt(encryptedBlob, passwordDerivedKey);
      innerEncryptedPayload = JSON.parse(innerJson) as EncryptedPayload;
    } catch (error) {
      // If decryption fails, it's likely due to wrong password (Requirement 3.6)
      throw new SecretViewError(
        'Incorrect password. Please try again.',
        'WRONG_PASSWORD',
        error instanceof Error ? error : undefined
      );
    }

    // Validate the inner payload structure
    // Note: ciphertext can be empty string for empty plaintext, so we check for undefined/null
    if (innerEncryptedPayload.ciphertext === undefined || innerEncryptedPayload.ciphertext === null ||
        !innerEncryptedPayload.iv || !innerEncryptedPayload.tag) {
      throw new SecretViewError(
        'Invalid encrypted data structure.',
        'DECRYPTION_FAILED'
      );
    }

    // Step 4: Decrypt the inner layer with the combined key
    const content = await decryptSecret(
      innerEncryptedPayload,
      publicKeyPart,
      privateKeyPart
    );

    return {
      status: 'success',
      content,
      isPasswordProtected: true,
    };
  } finally {
    // SECURITY: Clear all sensitive buffers from memory (Requirement 8.6)
    clearBuffers(saltBytes, passwordDerivedKey);
  }
}

/**
 * Gets user-friendly error message for display
 * 
 * @param error - The error to get a message for
 * @returns A user-friendly error message
 */
export function getErrorMessage(error: unknown): string {
  if (error instanceof SecretViewError) {
    return error.message;
  }
  
  if (error instanceof Error) {
    return `An unexpected error occurred: ${error.message}`;
  }
  
  return 'An unexpected error occurred. Please try again.';
}

/**
 * SecretViewer interface for dependency injection and testing
 */
export interface SecretViewer {
  viewSecret(url: string): Promise<ViewSecretResult>;
  viewSecretById(secretId: string, publicKeyPart: string): Promise<ViewSecretResult>;
  decryptWithPassword(passwordRequiredResult: ViewSecretPasswordRequired, password: string): Promise<ViewSecretSuccess>;
}

/**
 * Creates a SecretViewer instance with the given configuration
 * 
 * @param config - Configuration for the SecretViewer
 * @param fetchFn - Optional fetch function for testing
 * @returns SecretViewer instance
 */
export function createSecretViewer(
  config: SecretViewerConfig = DEFAULT_CONFIG,
  fetchFn: typeof fetch = fetch
): SecretViewer {
  return {
    viewSecret: (url: string) => viewSecret(url, config, fetchFn),
    viewSecretById: (secretId: string, publicKeyPart: string) =>
      viewSecretById(secretId, publicKeyPart, config, fetchFn),
    decryptWithPassword: (passwordRequiredResult: ViewSecretPasswordRequired, password: string) =>
      decryptWithPassword(passwordRequiredResult, password),
  };
}
