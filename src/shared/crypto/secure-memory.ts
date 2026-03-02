/**
 * Secure Memory module for secure secret sharing
 * 
 * Provides utilities for securely clearing sensitive data from memory.
 * This helps mitigate the risk of sensitive data being exposed through
 * memory dumps, garbage collection, or other memory inspection techniques.
 * 
 * Requirements:
 * - 8.6: Clear sensitive data from memory after use
 * 
 * Note: JavaScript does not provide true secure memory clearing guarantees
 * due to garbage collection and JIT compilation. However, these utilities
 * provide best-effort clearing that reduces the window of exposure.
 */

/**
 * Securely clears a Uint8Array by overwriting all bytes with zeros.
 * 
 * This function overwrites the array contents in-place to minimize
 * the time sensitive data remains in memory. While JavaScript's
 * garbage collector may still have copies, this reduces exposure.
 * 
 * @param buffer - The Uint8Array to clear (modified in-place)
 * 
 * @example
 * const key = new Uint8Array([0x01, 0x02, 0x03]);
 * clearBuffer(key);
 * // key is now [0x00, 0x00, 0x00]
 */
export function clearBuffer(buffer: Uint8Array | null | undefined): void {
  if (!buffer || !(buffer instanceof Uint8Array)) {
    return;
  }
  
  // Overwrite with zeros
  buffer.fill(0);
}

/**
 * Securely clears multiple Uint8Array buffers.
 * 
 * Convenience function for clearing multiple buffers at once.
 * 
 * @param buffers - Array of Uint8Arrays to clear
 * 
 * @example
 * clearBuffers([key, salt, iv]);
 */
export function clearBuffers(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const buffer of buffers) {
    clearBuffer(buffer);
  }
}

/**
 * Creates a string filled with null characters to help clear string references.
 * 
 * Note: JavaScript strings are immutable, so we cannot truly clear them.
 * This function returns a replacement string that can be assigned to
 * the variable, allowing the original string to be garbage collected.
 * 
 * @param length - The length of the replacement string (optional)
 * @returns An empty string (the safest replacement)
 * 
 * @example
 * let password = "secret";
 * password = clearString();
 * // password is now ""
 */
export function clearString(): string {
  return '';
}

/**
 * Executes a function with automatic cleanup of sensitive buffers.
 * 
 * This utility ensures that sensitive buffers are cleared even if
 * an error occurs during execution. Use this pattern when working
 * with encryption keys and other sensitive data.
 * 
 * @param fn - The function to execute
 * @param buffersToClean - Buffers to clear after execution
 * @returns The result of the function
 * @throws Re-throws any error from the function after cleanup
 * 
 * @example
 * const result = await withSecureCleanup(
 *   async () => {
 *     const key = await generateKey();
 *     return encrypt(data, key);
 *   },
 *   [key]
 * );
 */
export async function withSecureCleanup<T>(
  fn: () => Promise<T>,
  buffersToClean: (Uint8Array | null | undefined)[]
): Promise<T> {
  try {
    return await fn();
  } finally {
    clearBuffers(...buffersToClean);
  }
}

/**
 * Synchronous version of withSecureCleanup.
 * 
 * @param fn - The function to execute
 * @param buffersToClean - Buffers to clear after execution
 * @returns The result of the function
 * @throws Re-throws any error from the function after cleanup
 */
export function withSecureCleanupSync<T>(
  fn: () => T,
  buffersToClean: (Uint8Array | null | undefined)[]
): T {
  try {
    return fn();
  } finally {
    clearBuffers(...buffersToClean);
  }
}

/**
 * SecureMemory interface for dependency injection and testing
 */
export interface SecureMemory {
  clearBuffer(buffer: Uint8Array | null | undefined): void;
  clearBuffers(...buffers: (Uint8Array | null | undefined)[]): void;
  clearString(): string;
  withSecureCleanup<T>(fn: () => Promise<T>, buffersToClean: (Uint8Array | null | undefined)[]): Promise<T>;
  withSecureCleanupSync<T>(fn: () => T, buffersToClean: (Uint8Array | null | undefined)[]): T;
}

/**
 * Default SecureMemory implementation using the module functions
 */
export const secureMemory: SecureMemory = {
  clearBuffer,
  clearBuffers,
  clearString,
  withSecureCleanup,
  withSecureCleanupSync,
};
