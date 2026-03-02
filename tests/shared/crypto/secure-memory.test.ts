/**
 * Unit tests for secure-memory module
 * 
 * Tests the memory cleanup utilities for sensitive data.
 * 
 * Requirements:
 * - 8.6: Clear sensitive data from memory after use
 */

import { describe, it, expect } from 'vitest';
import {
  clearBuffer,
  clearBuffers,
  clearString,
  withSecureCleanup,
  withSecureCleanupSync,
} from '../../../src/shared/crypto/secure-memory';

describe('secure-memory', () => {
  describe('clearBuffer', () => {
    it('should zero out all bytes in a Uint8Array', () => {
      const buffer = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
      
      clearBuffer(buffer);
      
      expect(buffer).toEqual(new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00]));
    });

    it('should handle empty buffer', () => {
      const buffer = new Uint8Array(0);
      
      clearBuffer(buffer);
      
      expect(buffer.length).toBe(0);
    });

    it('should handle large buffer', () => {
      const buffer = new Uint8Array(1024);
      buffer.fill(0xFF);
      
      clearBuffer(buffer);
      
      expect(buffer.every(b => b === 0)).toBe(true);
    });

    it('should handle null input gracefully', () => {
      expect(() => clearBuffer(null)).not.toThrow();
    });

    it('should handle undefined input gracefully', () => {
      expect(() => clearBuffer(undefined)).not.toThrow();
    });

    it('should handle non-Uint8Array input gracefully', () => {
      // @ts-expect-error - Testing invalid input
      expect(() => clearBuffer('not a buffer')).not.toThrow();
      // @ts-expect-error - Testing invalid input
      expect(() => clearBuffer(123)).not.toThrow();
      // @ts-expect-error - Testing invalid input
      expect(() => clearBuffer({})).not.toThrow();
    });
  });

  describe('clearBuffers', () => {
    it('should clear multiple buffers', () => {
      const buffer1 = new Uint8Array([0x01, 0x02, 0x03]);
      const buffer2 = new Uint8Array([0x04, 0x05, 0x06]);
      const buffer3 = new Uint8Array([0x07, 0x08, 0x09]);
      
      clearBuffers(buffer1, buffer2, buffer3);
      
      expect(buffer1).toEqual(new Uint8Array([0x00, 0x00, 0x00]));
      expect(buffer2).toEqual(new Uint8Array([0x00, 0x00, 0x00]));
      expect(buffer3).toEqual(new Uint8Array([0x00, 0x00, 0x00]));
    });

    it('should handle mixed null/undefined/valid buffers', () => {
      const buffer1 = new Uint8Array([0x01, 0x02]);
      const buffer2 = null;
      const buffer3 = new Uint8Array([0x03, 0x04]);
      const buffer4 = undefined;
      
      expect(() => clearBuffers(buffer1, buffer2, buffer3, buffer4)).not.toThrow();
      
      expect(buffer1).toEqual(new Uint8Array([0x00, 0x00]));
      expect(buffer3).toEqual(new Uint8Array([0x00, 0x00]));
    });

    it('should handle empty arguments', () => {
      expect(() => clearBuffers()).not.toThrow();
    });
  });

  describe('clearString', () => {
    it('should return an empty string', () => {
      const result = clearString();
      expect(result).toBe('');
    });
  });

  describe('withSecureCleanup', () => {
    it('should execute function and clear buffers on success', async () => {
      const buffer1 = new Uint8Array([0x01, 0x02, 0x03]);
      const buffer2 = new Uint8Array([0x04, 0x05, 0x06]);
      
      const result = await withSecureCleanup(
        async () => {
          // Simulate some async work
          await Promise.resolve();
          return 'success';
        },
        [buffer1, buffer2]
      );
      
      expect(result).toBe('success');
      expect(buffer1).toEqual(new Uint8Array([0x00, 0x00, 0x00]));
      expect(buffer2).toEqual(new Uint8Array([0x00, 0x00, 0x00]));
    });

    it('should clear buffers even when function throws', async () => {
      const buffer = new Uint8Array([0x01, 0x02, 0x03]);
      
      await expect(
        withSecureCleanup(
          async () => {
            throw new Error('Test error');
          },
          [buffer]
        )
      ).rejects.toThrow('Test error');
      
      // Buffer should still be cleared
      expect(buffer).toEqual(new Uint8Array([0x00, 0x00, 0x00]));
    });

    it('should handle null/undefined buffers in cleanup list', async () => {
      const buffer = new Uint8Array([0x01, 0x02]);
      
      const result = await withSecureCleanup(
        async () => 'done',
        [buffer, null, undefined]
      );
      
      expect(result).toBe('done');
      expect(buffer).toEqual(new Uint8Array([0x00, 0x00]));
    });
  });

  describe('withSecureCleanupSync', () => {
    it('should execute function and clear buffers on success', () => {
      const buffer = new Uint8Array([0x01, 0x02, 0x03]);
      
      const result = withSecureCleanupSync(
        () => 'success',
        [buffer]
      );
      
      expect(result).toBe('success');
      expect(buffer).toEqual(new Uint8Array([0x00, 0x00, 0x00]));
    });

    it('should clear buffers even when function throws', () => {
      const buffer = new Uint8Array([0x01, 0x02, 0x03]);
      
      expect(() =>
        withSecureCleanupSync(
          () => {
            throw new Error('Test error');
          },
          [buffer]
        )
      ).toThrow('Test error');
      
      // Buffer should still be cleared
      expect(buffer).toEqual(new Uint8Array([0x00, 0x00, 0x00]));
    });
  });
});
