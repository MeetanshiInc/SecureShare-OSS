/**
 * Property-Based Tests for Notification Content Safety
 * 
 * **Validates: Requirements 5.4**
 * 
 * Property 11: Notification Content Safety
 * For any view notification sent, the notification content should contain only
 * the timestamp of access and should never contain any secret content,
 * encryption keys, or other sensitive data.
 * 
 * Requirements context:
 * - 5.4: THE notification email SHALL contain only the timestamp of access
 *        and SHALL NOT contain any secret content
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  createNotificationService,
  formatNotificationSubject,
  formatNotificationBody,
  type EmailSender,
} from '../../src/worker/notification-service';

/**
 * Arbitrary generator for secret content that might accidentally leak.
 * Generates various types of sensitive content including:
 * - Plain text secrets
 * - Unicode strings
 * - Special characters
 * - Multi-line content
 * - JSON-like content
 */
const secretContentArbitrary: fc.Arbitrary<string> = fc.oneof(
  // Plain text secrets
  fc.string({ minLength: 1, maxLength: 500 }),
  // Unicode strings
  fc.unicodeString({ minLength: 1, maxLength: 200 }),
  // Strings with special characters
  fc.stringOf(
    fc.constantFrom(
      ...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\`~\n\t\r'
    ),
    { minLength: 1, maxLength: 300 }
  ),
  // Password-like strings
  fc.string({ minLength: 8, maxLength: 32 }).map(s => `password: ${s}`),
  fc.string({ minLength: 8, maxLength: 32 }).map(s => `secret: ${s}`),
  // API keys and tokens
  fc.stringOf(
    fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'),
    { minLength: 32, maxLength: 64 }
  ).map(s => `api_key_${s}`),
  // Credit card-like numbers
  fc.stringOf(fc.constantFrom(...'0123456789'), { minLength: 16, maxLength: 16 }).map(
    s => `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}`
  ),
  // JSON-like content
  fc.record({
    username: fc.string({ minLength: 1, maxLength: 20 }),
    password: fc.string({ minLength: 8, maxLength: 32 }),
  }).map(obj => JSON.stringify(obj))
);

/**
 * Arbitrary generator for encryption keys (byte arrays represented as base64).
 * Generates various key formats that should never appear in notifications.
 */
const encryptionKeyArbitrary: fc.Arbitrary<string> = fc.oneof(
  // 128-bit keys (16 bytes) as base64
  fc.uint8Array({ minLength: 16, maxLength: 16 }).map(arr => 
    Buffer.from(arr).toString('base64')
  ),
  // 256-bit keys (32 bytes) as base64
  fc.uint8Array({ minLength: 32, maxLength: 32 }).map(arr => 
    Buffer.from(arr).toString('base64')
  ),
  // Base64url encoded keys
  fc.uint8Array({ minLength: 16, maxLength: 32 }).map(arr => 
    Buffer.from(arr).toString('base64url')
  ),
  // Hex-encoded keys
  fc.uint8Array({ minLength: 16, maxLength: 32 }).map(arr => 
    Buffer.from(arr).toString('hex')
  )
);

/**
 * Arbitrary generator for email addresses.
 */
const emailArbitrary: fc.Arbitrary<string> = fc.tuple(
  fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789._-'), { minLength: 1, maxLength: 20 }),
  fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789'), { minLength: 2, maxLength: 15 }),
  fc.constantFrom('com', 'org', 'net', 'io', 'co.uk', 'edu')
).map(([local, domain, tld]) => `${local}@${domain}.${tld}`);

/**
 * Arbitrary generator for timestamps.
 */
const timestampArbitrary: fc.Arbitrary<Date> = fc.date({
  min: new Date('2020-01-01T00:00:00.000Z'),
  max: new Date('2030-12-31T23:59:59.999Z'),
});

/**
 * Arbitrary generator for sensitive data patterns that should never appear.
 */
const sensitiveDataArbitrary: fc.Arbitrary<{
  secretContent: string;
  encryptionKey: string;
  privateKeyPart: string;
  publicKeyPart: string;
  passwordSalt: string;
  ciphertext: string;
}> = fc.record({
  secretContent: secretContentArbitrary,
  encryptionKey: encryptionKeyArbitrary,
  privateKeyPart: fc.uint8Array({ minLength: 16, maxLength: 16 }).map(arr => 
    Buffer.from(arr).toString('base64url')
  ),
  publicKeyPart: fc.uint8Array({ minLength: 16, maxLength: 16 }).map(arr => 
    Buffer.from(arr).toString('base64url')
  ),
  passwordSalt: fc.uint8Array({ minLength: 16, maxLength: 16 }).map(arr => 
    Buffer.from(arr).toString('base64')
  ),
  ciphertext: fc.uint8Array({ minLength: 32, maxLength: 256 }).map(arr => 
    Buffer.from(arr).toString('base64')
  ),
});

/**
 * Checks if a string contains any of the sensitive data.
 * Returns the name of the sensitive data found, or null if none found.
 */
function findSensitiveDataInString(
  text: string,
  sensitiveData: {
    secretContent: string;
    encryptionKey: string;
    privateKeyPart: string;
    publicKeyPart: string;
    passwordSalt: string;
    ciphertext: string;
  }
): string | null {
  // Only check for non-trivial strings (length > 3) to avoid false positives
  // with very short strings that might appear coincidentally
  
  if (sensitiveData.secretContent.length > 3 && text.includes(sensitiveData.secretContent)) {
    return 'secretContent';
  }
  if (sensitiveData.encryptionKey.length > 3 && text.includes(sensitiveData.encryptionKey)) {
    return 'encryptionKey';
  }
  if (sensitiveData.privateKeyPart.length > 3 && text.includes(sensitiveData.privateKeyPart)) {
    return 'privateKeyPart';
  }
  if (sensitiveData.publicKeyPart.length > 3 && text.includes(sensitiveData.publicKeyPart)) {
    return 'publicKeyPart';
  }
  if (sensitiveData.passwordSalt.length > 3 && text.includes(sensitiveData.passwordSalt)) {
    return 'passwordSalt';
  }
  if (sensitiveData.ciphertext.length > 3 && text.includes(sensitiveData.ciphertext)) {
    return 'ciphertext';
  }
  
  return null;
}

describe('Property 11: Notification Content Safety', () => {
  /**
   * **Validates: Requirements 5.4**
   * 
   * Property: The notification subject should be static and never contain
   * any dynamic content that could leak sensitive information.
   */
  it('notification subject is static and contains no sensitive data', async () => {
    await fc.assert(
      fc.asyncProperty(
        sensitiveDataArbitrary,
        async (sensitiveData) => {
          const subject = formatNotificationSubject();
          
          // Subject should be a static string
          expect(subject).toBe('Your shared secret has been viewed');
          
          // Subject should not contain any sensitive data
          const foundSensitive = findSensitiveDataInString(subject, sensitiveData);
          expect(foundSensitive).toBeNull();
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 5.4**
   * 
   * Property: The notification body should contain only the timestamp
   * and should never contain any secret content, encryption keys, or
   * other sensitive data.
   */
  it('notification body contains only timestamp and no sensitive data', async () => {
    await fc.assert(
      fc.asyncProperty(
        timestampArbitrary,
        sensitiveDataArbitrary,
        async (viewedAt, sensitiveData) => {
          const body = formatNotificationBody(viewedAt);
          
          // Body should contain the timestamp
          expect(body).toContain(viewedAt.toISOString());
          
          // Body should not contain any sensitive data
          const foundSensitive = findSensitiveDataInString(body, sensitiveData);
          expect(foundSensitive).toBeNull();
          
          // Body should only contain expected static text and the timestamp
          expect(body).toContain('Viewed at:');
          expect(body).toContain('secret was viewed');
          expect(body).toContain('permanently deleted');
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 5.4**
   * 
   * Property: When sending a notification through the NotificationService,
   * the email content (subject and body) should never contain any sensitive
   * data regardless of what sensitive data exists in the system.
   */
  it('notification service never leaks sensitive data in emails', async () => {
    await fc.assert(
      fc.asyncProperty(
        emailArbitrary,
        timestampArbitrary,
        sensitiveDataArbitrary,
        async (email, viewedAt, sensitiveData) => {
          let capturedSubject = '';
          let capturedBody = '';
          
          // Create a capturing email sender to inspect what gets sent
          const capturingEmailSender: EmailSender = async (_to, subject, body) => {
            capturedSubject = subject;
            capturedBody = body;
            return { success: true };
          };
          
          const service = createNotificationService(capturingEmailSender);
          await service.sendViewNotification(email, viewedAt);
          
          // Subject should not contain any sensitive data
          const subjectSensitive = findSensitiveDataInString(capturedSubject, sensitiveData);
          expect(subjectSensitive).toBeNull();
          
          // Body should not contain any sensitive data
          const bodySensitive = findSensitiveDataInString(capturedBody, sensitiveData);
          expect(bodySensitive).toBeNull();
          
          // Body should contain the timestamp
          expect(capturedBody).toContain(viewedAt.toISOString());
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 5.4**
   * 
   * Property: The notification body should not contain any template
   * placeholders or injection points that could be exploited to leak data.
   */
  it('notification body has no template injection points', async () => {
    await fc.assert(
      fc.asyncProperty(
        timestampArbitrary,
        async (viewedAt) => {
          const body = formatNotificationBody(viewedAt);
          
          // Should not contain template placeholders
          expect(body).not.toContain('{{');
          expect(body).not.toContain('}}');
          expect(body).not.toContain('${');
          expect(body).not.toContain('%s');
          expect(body).not.toContain('%d');
          expect(body).not.toContain('{0}');
          expect(body).not.toContain('{1}');
          
          // Should not contain field labels that suggest dynamic content
          expect(body).not.toContain('secret:');
          expect(body).not.toContain('content:');
          expect(body).not.toContain('password:');
          expect(body).not.toContain('key:');
          expect(body).not.toContain('encrypted:');
          expect(body).not.toContain('ciphertext:');
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 5.4**
   * 
   * Property: The notification content should be consistent regardless
   * of the timestamp value - only the timestamp itself should vary.
   */
  it('notification content structure is consistent across timestamps', async () => {
    await fc.assert(
      fc.asyncProperty(
        timestampArbitrary,
        timestampArbitrary,
        async (timestamp1, timestamp2) => {
          const body1 = formatNotificationBody(timestamp1);
          const body2 = formatNotificationBody(timestamp2);
          
          // Replace timestamps with a placeholder to compare structure
          const normalizedBody1 = body1.replace(timestamp1.toISOString(), 'TIMESTAMP');
          const normalizedBody2 = body2.replace(timestamp2.toISOString(), 'TIMESTAMP');
          
          // Structure should be identical
          expect(normalizedBody1).toBe(normalizedBody2);
          
          // Subject should always be the same
          expect(formatNotificationSubject()).toBe(formatNotificationSubject());
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 5.4**
   * 
   * Property: The notification should not contain any cryptographic
   * terminology that might indicate sensitive data is present.
   */
  it('notification does not contain cryptographic terminology', async () => {
    await fc.assert(
      fc.asyncProperty(
        timestampArbitrary,
        async (viewedAt) => {
          const subject = formatNotificationSubject();
          const body = formatNotificationBody(viewedAt);
          const fullContent = `${subject}\n${body}`.toLowerCase();
          
          // Should not contain cryptographic terms
          expect(fullContent).not.toContain('ciphertext');
          expect(fullContent).not.toContain('plaintext');
          expect(fullContent).not.toContain('private key');
          expect(fullContent).not.toContain('public key');
          expect(fullContent).not.toContain('encryption key');
          expect(fullContent).not.toContain('decryption');
          expect(fullContent).not.toContain('aes');
          expect(fullContent).not.toContain('gcm');
          expect(fullContent).not.toContain('iv ');
          expect(fullContent).not.toContain('initialization vector');
          expect(fullContent).not.toContain('salt');
          expect(fullContent).not.toContain('pbkdf');
          expect(fullContent).not.toContain('hash');
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 5.4**
   * 
   * Property: Even with malicious or unusual timestamps, the notification
   * should remain safe and not expose any sensitive information.
   */
  it('notification is safe with edge case timestamps', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(
          // Normal timestamps
          timestampArbitrary,
          // Edge case timestamps
          fc.constant(new Date(0)), // Unix epoch
          fc.constant(new Date('1970-01-01T00:00:00.000Z')),
          fc.constant(new Date('2099-12-31T23:59:59.999Z')),
          fc.constant(new Date('2000-01-01T00:00:00.000Z')), // Y2K
          fc.constant(new Date('2038-01-19T03:14:07.000Z')), // Unix 32-bit overflow
        ),
        sensitiveDataArbitrary,
        async (viewedAt, sensitiveData) => {
          const body = formatNotificationBody(viewedAt);
          
          // Body should contain the timestamp in ISO format
          expect(body).toContain(viewedAt.toISOString());
          
          // Body should not contain any sensitive data
          const foundSensitive = findSensitiveDataInString(body, sensitiveData);
          expect(foundSensitive).toBeNull();
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 5.4**
   * 
   * Property: The notification email recipient address should be the only
   * email-related data passed to the email sender - no other emails should
   * appear in subject or body.
   */
  it('notification does not leak email addresses in content', async () => {
    await fc.assert(
      fc.asyncProperty(
        emailArbitrary,
        emailArbitrary, // A different email that might accidentally leak
        timestampArbitrary,
        async (recipientEmail, otherEmail, viewedAt) => {
          let capturedTo = '';
          let capturedSubject = '';
          let capturedBody = '';
          
          const capturingEmailSender: EmailSender = async (to, subject, body) => {
            capturedTo = to;
            capturedSubject = subject;
            capturedBody = body;
            return { success: true };
          };
          
          const service = createNotificationService(capturingEmailSender);
          await service.sendViewNotification(recipientEmail, viewedAt);
          
          // The recipient email should be passed to the sender
          expect(capturedTo).toBe(recipientEmail);
          
          // Subject should not contain any email addresses
          expect(capturedSubject).not.toContain('@');
          expect(capturedSubject).not.toContain(recipientEmail);
          expect(capturedSubject).not.toContain(otherEmail);
          
          // Body should not contain any email addresses
          expect(capturedBody).not.toContain('@');
          expect(capturedBody).not.toContain(recipientEmail);
          expect(capturedBody).not.toContain(otherEmail);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});
