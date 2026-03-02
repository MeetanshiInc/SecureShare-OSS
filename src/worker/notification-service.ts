/**
 * NotificationService module for secure secret sharing
 * 
 * Handles email notifications when secrets are viewed.
 * 
 * Security requirements:
 * - 5.3: Send email notification when secret is viewed
 * - 5.4: Notification includes only timestamp, never secret content
 * - 5.5: Email address is deleted after notification is sent
 * 
 * Note: This implementation provides a pluggable interface for email sending.
 * In production, this would integrate with Cloudflare Email Workers, SendGrid,
 * or another email service. The current implementation includes a stub that
 * logs the notification for development/testing purposes.
 */

/**
 * Result of a notification send attempt
 */
export interface NotificationResult {
  /** Whether the notification was sent successfully */
  success: boolean;
  /** Error message if the notification failed */
  error?: string;
}

/**
 * Interface for the notification service
 * 
 * Implementations must ensure:
 * - Only timestamp is included in notifications (never secret content)
 * - Email addresses are not logged or persisted after sending
 */
export interface NotificationService {
  /**
   * Send a view notification email
   * 
   * @param email - The email address to notify
   * @param viewedAt - The timestamp when the secret was viewed
   * @returns Result indicating success or failure
   */
  sendViewNotification(email: string, viewedAt: Date): Promise<NotificationResult>;
}

/**
 * Email sender function type for dependency injection
 * 
 * This allows different email implementations to be plugged in:
 * - Cloudflare Email Workers
 * - SendGrid
 * - AWS SES
 * - Mock/stub for testing
 */
export type EmailSender = (
  to: string,
  subject: string,
  body: string
) => Promise<{ success: boolean; error?: string }>;

/**
 * Formats the notification email subject
 * 
 * @returns The email subject line
 */
export function formatNotificationSubject(): string {
  return 'Your shared secret has been viewed';
}

/**
 * Formats the notification email body
 * 
 * IMPORTANT: This function must NEVER include any secret content.
 * Only the timestamp of when the secret was viewed is included.
 * 
 * @param viewedAt - The timestamp when the secret was viewed
 * @returns The email body text
 */
export function formatNotificationBody(viewedAt: Date): string {
  const formattedDate = viewedAt.toISOString();
  
  return `Your shared secret was viewed.

Viewed at: ${formattedDate}

This is an automated notification. The secret has been permanently deleted and can no longer be accessed.

---
Secure Secret Sharing Service`;
}

/**
 * Validates an email address format
 * 
 * Uses a simple regex that covers most valid email formats.
 * This is not meant to be exhaustive but to catch obvious errors.
 * 
 * @param email - The email address to validate
 * @returns true if the email format appears valid
 */
export function isValidEmail(email: string): boolean {
  if (typeof email !== 'string' || email.length === 0) {
    return false;
  }
  
  // Simple email validation regex
  // Matches: local@domain.tld
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Creates a NotificationService with the provided email sender
 * 
 * @param emailSender - Function to send emails
 * @returns A NotificationService implementation
 */
export function createNotificationService(emailSender: EmailSender): NotificationService {
  return {
    async sendViewNotification(email: string, viewedAt: Date): Promise<NotificationResult> {
      // Validate email format
      if (!isValidEmail(email)) {
        return {
          success: false,
          error: 'Invalid email address format',
        };
      }
      
      // Format the notification (timestamp only, never secret content)
      const subject = formatNotificationSubject();
      const body = formatNotificationBody(viewedAt);
      
      try {
        // Send the email
        const result = await emailSender(email, subject, body);
        return result;
      } catch (error) {
        // Don't expose internal error details
        return {
          success: false,
          error: 'Failed to send notification',
        };
      }
    },
  };
}

/**
 * Stub email sender for development and testing
 * 
 * This implementation logs the notification details (except the email address)
 * and always returns success. In production, this would be replaced with
 * an actual email service integration.
 * 
 * Note: The email address is intentionally NOT logged to comply with
 * Requirement 8.3 (SHALL NOT log any email addresses used for notifications)
 */
export const stubEmailSender: EmailSender = async (
  _to: string,
  subject: string,
  _body: string
): Promise<{ success: boolean; error?: string }> => {
  // Log that a notification was sent (without the email address)
  // In production, this would actually send the email
  console.log(`[NotificationService] Notification sent: ${subject}`);
  
  return { success: true };
};

/**
 * Creates a stub NotificationService for development and testing
 * 
 * @returns A NotificationService that logs notifications but doesn't send real emails
 */
export function createStubNotificationService(): NotificationService {
  return createNotificationService(stubEmailSender);
}

/**
 * Factory type for creating NotificationService instances
 */
export type NotificationServiceFactory = () => NotificationService;

/**
 * Default factory that creates a stub notification service
 * 
 * In production, this would be replaced with a factory that creates
 * a real email-sending notification service.
 */
export const notificationServiceFactory: NotificationServiceFactory = createStubNotificationService;
