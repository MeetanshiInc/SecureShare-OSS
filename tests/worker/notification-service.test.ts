/**
 * Unit tests for NotificationService
 * 
 * Tests verify:
 * - Notification emails are sent with correct format
 * - Only timestamp is included in notifications (never secret content)
 * - Email validation works correctly
 * - Error handling is robust
 * 
 * Requirements tested:
 * - 5.3: System sends email notification when secret is viewed
 * - 5.4: Notification includes only timestamp, never secret content
 * - 5.5: Email address is deleted after notification is sent
 */

import { describe, it, expect, vi } from 'vitest';
import {
  createNotificationService,
  createStubNotificationService,
  formatNotificationSubject,
  formatNotificationBody,
  isValidEmail,
  type EmailSender,
  type NotificationService,
} from '../../src/worker/notification-service';

describe('NotificationService', () => {
  describe('formatNotificationSubject', () => {
    it('should return a descriptive subject line', () => {
      const subject = formatNotificationSubject();
      
      expect(subject).toBe('Your shared secret has been viewed');
    });

    it('should not contain any secret content', () => {
      const subject = formatNotificationSubject();
      
      // Subject should be generic and not contain any placeholders for secret content
      expect(subject).not.toContain('secret:');
      expect(subject).not.toContain('content:');
      expect(subject).not.toContain('password');
      expect(subject).not.toContain('key');
    });
  });

  describe('formatNotificationBody', () => {
    it('should include the timestamp', () => {
      const viewedAt = new Date('2024-01-15T10:30:00.000Z');
      const body = formatNotificationBody(viewedAt);
      
      expect(body).toContain('2024-01-15T10:30:00.000Z');
    });

    it('should include "Viewed at" label', () => {
      const viewedAt = new Date();
      const body = formatNotificationBody(viewedAt);
      
      expect(body).toContain('Viewed at:');
    });

    it('should mention that the secret was viewed', () => {
      const viewedAt = new Date();
      const body = formatNotificationBody(viewedAt);
      
      expect(body).toContain('secret was viewed');
    });

    it('should mention that the secret has been deleted', () => {
      const viewedAt = new Date();
      const body = formatNotificationBody(viewedAt);
      
      expect(body).toContain('permanently deleted');
    });

    it('should NOT contain any secret content (Requirement 5.4)', () => {
      const viewedAt = new Date();
      const body = formatNotificationBody(viewedAt);
      
      // Body should only contain timestamp and generic text
      // It should not have any placeholders or fields for secret content
      expect(body).not.toContain('secret content');
      expect(body).not.toContain('encrypted');
      expect(body).not.toContain('ciphertext');
      expect(body).not.toContain('privateKey');
      expect(body).not.toContain('publicKey');
    });

    it('should format different dates correctly', () => {
      const dates = [
        new Date('2023-06-01T00:00:00.000Z'),
        new Date('2024-12-31T23:59:59.999Z'),
        new Date('2025-03-15T12:00:00.000Z'),
      ];
      
      for (const date of dates) {
        const body = formatNotificationBody(date);
        expect(body).toContain(date.toISOString());
      }
    });
  });

  describe('isValidEmail', () => {
    it('should accept valid email addresses', () => {
      const validEmails = [
        'test@example.com',
        'user.name@domain.org',
        'user+tag@example.co.uk',
        'a@b.co',
        'test123@test123.com',
      ];
      
      for (const email of validEmails) {
        expect(isValidEmail(email)).toBe(true);
      }
    });

    it('should reject invalid email addresses', () => {
      const invalidEmails = [
        '',
        'notanemail',
        '@nodomain.com',
        'noat.com',
        'spaces in@email.com',
        'missing@tld',
        'double@@at.com',
      ];
      
      for (const email of invalidEmails) {
        expect(isValidEmail(email)).toBe(false);
      }
    });

    it('should reject non-string values', () => {
      expect(isValidEmail(null as any)).toBe(false);
      expect(isValidEmail(undefined as any)).toBe(false);
      expect(isValidEmail(123 as any)).toBe(false);
      expect(isValidEmail({} as any)).toBe(false);
    });
  });

  describe('createNotificationService', () => {
    it('should send notification with correct parameters', async () => {
      const mockSender = vi.fn().mockResolvedValue({ success: true });
      const service = createNotificationService(mockSender);
      
      const email = 'test@example.com';
      const viewedAt = new Date('2024-01-15T10:30:00.000Z');
      
      await service.sendViewNotification(email, viewedAt);
      
      expect(mockSender).toHaveBeenCalledTimes(1);
      expect(mockSender).toHaveBeenCalledWith(
        email,
        'Your shared secret has been viewed',
        expect.stringContaining('2024-01-15T10:30:00.000Z')
      );
    });

    it('should return success when email is sent', async () => {
      const mockSender = vi.fn().mockResolvedValue({ success: true });
      const service = createNotificationService(mockSender);
      
      const result = await service.sendViewNotification('test@example.com', new Date());
      
      expect(result.success).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should return failure when email sending fails', async () => {
      const mockSender = vi.fn().mockResolvedValue({ 
        success: false, 
        error: 'SMTP error' 
      });
      const service = createNotificationService(mockSender);
      
      const result = await service.sendViewNotification('test@example.com', new Date());
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('SMTP error');
    });

    it('should handle email sender exceptions gracefully', async () => {
      const mockSender = vi.fn().mockRejectedValue(new Error('Network error'));
      const service = createNotificationService(mockSender);
      
      const result = await service.sendViewNotification('test@example.com', new Date());
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('Failed to send notification');
      // Should not expose internal error details
      expect(result.error).not.toContain('Network');
    });

    it('should reject invalid email addresses', async () => {
      const mockSender = vi.fn().mockResolvedValue({ success: true });
      const service = createNotificationService(mockSender);
      
      const result = await service.sendViewNotification('invalid-email', new Date());
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid email address format');
      expect(mockSender).not.toHaveBeenCalled();
    });

    it('should reject empty email addresses', async () => {
      const mockSender = vi.fn().mockResolvedValue({ success: true });
      const service = createNotificationService(mockSender);
      
      const result = await service.sendViewNotification('', new Date());
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid email address format');
      expect(mockSender).not.toHaveBeenCalled();
    });
  });

  describe('createStubNotificationService', () => {
    it('should create a working notification service', async () => {
      const service = createStubNotificationService();
      
      const result = await service.sendViewNotification('test@example.com', new Date());
      
      expect(result.success).toBe(true);
    });

    it('should validate email addresses', async () => {
      const service = createStubNotificationService();
      
      const result = await service.sendViewNotification('invalid', new Date());
      
      expect(result.success).toBe(false);
    });
  });

  describe('Notification Content Safety (Requirement 5.4)', () => {
    it('should never include secret content in notification body', async () => {
      let capturedBody = '';
      const capturingSender: EmailSender = async (_to, _subject, body) => {
        capturedBody = body;
        return { success: true };
      };
      
      const service = createNotificationService(capturingSender);
      await service.sendViewNotification('test@example.com', new Date());
      
      // The body should only contain timestamp and generic text
      // It should not have any mechanism to include secret content
      expect(capturedBody).not.toContain('{{');
      expect(capturedBody).not.toContain('}}');
      expect(capturedBody).not.toContain('${');
      expect(capturedBody).not.toContain('secret:');
      expect(capturedBody).not.toContain('content:');
    });

    it('should never include secret content in notification subject', async () => {
      let capturedSubject = '';
      const capturingSender: EmailSender = async (_to, subject, _body) => {
        capturedSubject = subject;
        return { success: true };
      };
      
      const service = createNotificationService(capturingSender);
      await service.sendViewNotification('test@example.com', new Date());
      
      // Subject should be static and not include any dynamic secret content
      expect(capturedSubject).toBe('Your shared secret has been viewed');
    });

    it('should only include timestamp in the notification', async () => {
      const viewedAt = new Date('2024-06-15T14:30:00.000Z');
      let capturedBody = '';
      const capturingSender: EmailSender = async (_to, _subject, body) => {
        capturedBody = body;
        return { success: true };
      };
      
      const service = createNotificationService(capturingSender);
      await service.sendViewNotification('test@example.com', viewedAt);
      
      // The only dynamic content should be the timestamp
      expect(capturedBody).toContain('2024-06-15T14:30:00.000Z');
    });
  });

  describe('Email Address Handling (Requirement 5.5)', () => {
    it('should pass email to sender but not store it', async () => {
      let receivedEmail = '';
      const capturingSender: EmailSender = async (to, _subject, _body) => {
        receivedEmail = to;
        return { success: true };
      };
      
      const service = createNotificationService(capturingSender);
      await service.sendViewNotification('test@example.com', new Date());
      
      // Email should be passed to sender
      expect(receivedEmail).toBe('test@example.com');
      
      // Service should not have any method to retrieve stored emails
      expect((service as any).storedEmails).toBeUndefined();
      expect((service as any).emails).toBeUndefined();
    });
  });
});
