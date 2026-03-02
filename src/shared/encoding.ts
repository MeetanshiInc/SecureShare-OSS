/**
 * Base64url encoding utilities for secure secret sharing
 * 
 * Implements URL-safe Base64 encoding (RFC 4648 Section 5) for encoding
 * the Public_Key_Part in URL fragments.
 * 
 * Base64url differs from standard Base64:
 * - Uses '-' instead of '+'
 * - Uses '_' instead of '/'
 * - Omits padding '=' characters (optional on decode)
 * 
 * Requirements:
 * - 9.3: The Public_Key_Part SHALL be encoded in the URL_Fragment using base64url encoding
 */

/**
 * Encodes a Uint8Array to a Base64url string (URL-safe Base64 without padding).
 * 
 * The encoding follows RFC 4648 Section 5:
 * - Standard Base64 alphabet with '+' replaced by '-' and '/' replaced by '_'
 * - No padding characters ('=')
 * 
 * @param bytes - The bytes to encode
 * @returns Base64url-encoded string (URL-safe, no padding)
 * @throws Error if input is not a Uint8Array
 * 
 * @example
 * const key = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
 * const encoded = toBase64url(key); // "SGVsbG8"
 */
export function toBase64url(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error('Input must be a Uint8Array');
  }

  // Convert Uint8Array to binary string
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }

  // Encode to standard Base64
  const base64 = btoa(binary);

  // Convert to Base64url:
  // - Replace '+' with '-'
  // - Replace '/' with '_'
  // - Remove padding '='
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decodes a Base64url string to a Uint8Array.
 * 
 * The decoding handles:
 * - URL-safe alphabet ('-' and '_')
 * - Missing padding (adds it back as needed)
 * - Standard Base64 input (for compatibility)
 * 
 * @param base64url - The Base64url string to decode
 * @returns Decoded bytes as Uint8Array
 * @throws Error if the string is not valid Base64url encoding
 * 
 * @example
 * const decoded = fromBase64url("SGVsbG8"); // Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f])
 */
export function fromBase64url(base64url: string): Uint8Array {
  if (typeof base64url !== 'string') {
    throw new Error('Input must be a string');
  }

  // Convert Base64url to standard Base64:
  // - Replace '-' with '+'
  // - Replace '_' with '/'
  let base64 = base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  // Add padding if necessary
  // Base64 strings must have length divisible by 4
  const paddingNeeded = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(paddingNeeded);

  // Decode from Base64
  let binary: string;
  try {
    binary = atob(base64);
  } catch {
    throw new Error('Invalid Base64url encoding');
  }

  // Convert binary string to Uint8Array
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

/**
 * Validates that a string is valid Base64url encoding.
 * 
 * Checks that:
 * - String contains only valid Base64url characters (A-Z, a-z, 0-9, -, _)
 * - String can be successfully decoded
 * 
 * @param str - The string to validate
 * @returns true if valid Base64url, false otherwise
 * 
 * @example
 * isValidBase64url("SGVsbG8"); // true
 * isValidBase64url("Hello!"); // false
 */
export function isValidBase64url(str: string): boolean {
  if (typeof str !== 'string') {
    return false;
  }

  // Check for valid Base64url characters only
  // Base64url alphabet: A-Z, a-z, 0-9, -, _
  // Note: We allow empty string as valid (encodes empty byte array)
  if (!/^[A-Za-z0-9_-]*$/.test(str)) {
    return false;
  }

  // Try to decode to verify it's valid
  try {
    fromBase64url(str);
    return true;
  } catch {
    return false;
  }
}

/**
 * Encoding interface for dependency injection and testing
 */
export interface Encoding {
  toBase64url(bytes: Uint8Array): string;
  fromBase64url(base64url: string): Uint8Array;
  isValidBase64url(str: string): boolean;
}

/**
 * Default Encoding implementation using the module functions
 */
export const encoding: Encoding = {
  toBase64url,
  fromBase64url,
  isValidBase64url,
};
