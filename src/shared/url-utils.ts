/**
 * URL builder and parser utilities for secure secret sharing
 * 
 * Handles construction and parsing of secret URLs with the following structure:
 * https://example.com/s/{secretId}#{publicKeyPart}
 * 
 * Security considerations:
 * - The publicKeyPart is ONLY placed in the URL fragment (after #)
 * - URL fragments are never sent to the server by browsers
 * - This ensures the server never has access to the complete decryption key
 * 
 * Requirements:
 * - 1.7: Construct a shareable URL with the Secret_ID in the path and Public_Key_Part in the URL_Fragment
 * - 2.1: Extract the Public_Key_Part from the URL_Fragment
 */

import { isValidBase64url } from './encoding.js';

/**
 * Regular expression for validating secret IDs
 * Secret IDs must be exactly 16 alphanumeric characters
 */
const SECRET_ID_REGEX = /^[A-Za-z0-9]{16}$/;

/**
 * Expected length of Base64url-encoded 128-bit key part
 * 128 bits = 16 bytes = 22 Base64url characters (ceil(16 * 4/3) = 22)
 */
const PUBLIC_KEY_PART_LENGTH = 22;

/**
 * Result of parsing a secret URL
 */
export interface ParsedSecretUrl {
  /** The 16-character alphanumeric secret identifier */
  secretId: string;
  /** The Base64url-encoded 128-bit public key part */
  publicKeyPart: string;
}

/**
 * Options for building a secret URL
 */
export interface BuildSecretUrlOptions {
  /** Base URL of the application (e.g., "https://example.com") */
  baseUrl: string;
  /** The 16-character alphanumeric secret identifier */
  secretId: string;
  /** The Base64url-encoded 128-bit public key part */
  publicKeyPart: string;
}

/**
 * Error thrown when URL validation fails
 */
export class UrlValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UrlValidationError';
  }
}

/**
 * Validates that a secret ID is properly formatted.
 * 
 * Secret IDs must be:
 * - Exactly 16 characters long
 * - Contain only alphanumeric characters (A-Z, a-z, 0-9)
 * 
 * @param secretId - The secret ID to validate
 * @returns true if valid, false otherwise
 * 
 * @example
 * isValidSecretId("abc123def456gh78"); // true
 * isValidSecretId("short"); // false
 * isValidSecretId("has-special-chars!"); // false
 */
export function isValidSecretId(secretId: string): boolean {
  if (typeof secretId !== 'string') {
    return false;
  }
  return SECRET_ID_REGEX.test(secretId);
}

/**
 * Validates that a public key part is properly formatted.
 * 
 * Public key parts must be:
 * - Exactly 22 characters long (Base64url encoding of 128 bits)
 * - Valid Base64url encoding
 * 
 * @param publicKeyPart - The public key part to validate
 * @returns true if valid, false otherwise
 * 
 * @example
 * isValidPublicKeyPart("AAAAAAAAAAAAAAAAAAAAAA"); // true (22 chars)
 * isValidPublicKeyPart("short"); // false
 * isValidPublicKeyPart("invalid!characters!!!!!"); // false
 */
export function isValidPublicKeyPart(publicKeyPart: string): boolean {
  if (typeof publicKeyPart !== 'string') {
    return false;
  }
  if (publicKeyPart.length !== PUBLIC_KEY_PART_LENGTH) {
    return false;
  }
  return isValidBase64url(publicKeyPart);
}

/**
 * Builds a shareable secret URL with the secret ID in the path and public key part in the fragment.
 * 
 * The URL structure is: {baseUrl}/s/{secretId}#{publicKeyPart}
 * 
 * Security: The public key part is placed ONLY in the URL fragment (after #).
 * URL fragments are never sent to the server by browsers, ensuring the server
 * never has access to the complete decryption key.
 * 
 * @param options - The URL building options
 * @returns The complete shareable URL
 * @throws UrlValidationError if any parameter is invalid
 * 
 * @example
 * const url = buildSecretUrl({
 *   baseUrl: "https://example.com",
 *   secretId: "abc123def456gh78",
 *   publicKeyPart: "AAAAAAAAAAAAAAAAAAAAAA"
 * });
 * // Returns: "https://example.com/s/abc123def456gh78#AAAAAAAAAAAAAAAAAAAAAA"
 * 
 * Requirements:
 * - 1.7: Construct a shareable URL with the Secret_ID in the path and Public_Key_Part in the URL_Fragment
 */
export function buildSecretUrl(options: BuildSecretUrlOptions): string {
  const { baseUrl, secretId, publicKeyPart } = options;

  // Validate baseUrl
  if (typeof baseUrl !== 'string' || baseUrl.trim() === '') {
    throw new UrlValidationError('Base URL must be a non-empty string');
  }

  // Validate secretId
  if (!isValidSecretId(secretId)) {
    throw new UrlValidationError(
      'Secret ID must be exactly 16 alphanumeric characters'
    );
  }

  // Validate publicKeyPart
  if (!isValidPublicKeyPart(publicKeyPart)) {
    throw new UrlValidationError(
      'Public key part must be exactly 22 valid Base64url characters'
    );
  }

  // Parse and validate the base URL
  let parsedBaseUrl: URL;
  try {
    parsedBaseUrl = new URL(baseUrl);
  } catch {
    throw new UrlValidationError('Invalid base URL format');
  }

  // Ensure the base URL doesn't already have a fragment
  if (parsedBaseUrl.hash) {
    throw new UrlValidationError('Base URL must not contain a fragment');
  }

  // Build the URL with secret ID in path and public key part in fragment
  // Remove trailing slash from origin if present
  const origin = parsedBaseUrl.origin;
  const pathname = parsedBaseUrl.pathname.replace(/\/$/, '');
  
  // Construct the final URL
  // The public key part goes ONLY in the fragment (after #)
  return `${origin}${pathname}/s/${secretId}#${publicKeyPart}`;
}

/**
 * Parses a secret URL to extract the secret ID and public key part.
 * 
 * Expected URL structure: {baseUrl}/s/{secretId}#{publicKeyPart}
 * 
 * The function validates:
 * - URL has the correct path structure (/s/{secretId})
 * - Secret ID is 16 alphanumeric characters
 * - Public key part is in the fragment (not path or query)
 * - Public key part is 22 valid Base64url characters
 * 
 * @param url - The secret URL to parse
 * @returns The parsed secret ID and public key part
 * @throws UrlValidationError if the URL format is invalid
 * 
 * @example
 * const { secretId, publicKeyPart } = parseSecretUrl(
 *   "https://example.com/s/abc123def456gh78#AAAAAAAAAAAAAAAAAAAAAA"
 * );
 * // secretId: "abc123def456gh78"
 * // publicKeyPart: "AAAAAAAAAAAAAAAAAAAAAA"
 * 
 * Requirements:
 * - 2.1: Extract the Public_Key_Part from the URL_Fragment
 */
export function parseSecretUrl(url: string): ParsedSecretUrl {
  if (typeof url !== 'string' || url.trim() === '') {
    throw new UrlValidationError('URL must be a non-empty string');
  }

  // Parse the URL
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new UrlValidationError('Invalid URL format');
  }

  // Extract the pathname and find the secret ID
  const pathname = parsedUrl.pathname;
  
  // Match the expected path pattern: /s/{secretId} or /{prefix}/s/{secretId}
  const pathMatch = pathname.match(/\/s\/([^/]+)\/?$/);
  if (!pathMatch) {
    throw new UrlValidationError(
      'URL path must contain /s/{secretId} pattern'
    );
  }

  const secretId = pathMatch[1]!;

  // Validate the secret ID
  if (!isValidSecretId(secretId)) {
    throw new UrlValidationError(
      'Secret ID must be exactly 16 alphanumeric characters'
    );
  }

  // Ensure the public key part is NOT in the path or query string
  // This is a security check to ensure the key is only in the fragment
  if (parsedUrl.search) {
    // Check if query string contains anything that looks like a key
    const queryParams = new URLSearchParams(parsedUrl.search);
    for (const [key, value] of queryParams) {
      if (key === 'key' || key === 'publicKeyPart' || value.length === PUBLIC_KEY_PART_LENGTH) {
        throw new UrlValidationError(
          'Public key part must not be in query string - it should only be in the URL fragment'
        );
      }
    }
  }

  // Extract the public key part from the fragment
  const fragment = parsedUrl.hash.slice(1); // Remove the leading '#'
  
  if (!fragment) {
    throw new UrlValidationError(
      'URL must contain a fragment with the public key part'
    );
  }

  // Validate the public key part
  if (!isValidPublicKeyPart(fragment)) {
    throw new UrlValidationError(
      'Public key part in fragment must be exactly 22 valid Base64url characters'
    );
  }

  return {
    secretId,
    publicKeyPart: fragment,
  };
}

/**
 * URL utilities interface for dependency injection and testing
 */
export interface UrlUtils {
  buildSecretUrl(options: BuildSecretUrlOptions): string;
  parseSecretUrl(url: string): ParsedSecretUrl;
  isValidSecretId(secretId: string): boolean;
  isValidPublicKeyPart(publicKeyPart: string): boolean;
}

/**
 * Default URL utilities implementation using the module functions
 */
export const urlUtils: UrlUtils = {
  buildSecretUrl,
  parseSecretUrl,
  isValidSecretId,
  isValidPublicKeyPart,
};
