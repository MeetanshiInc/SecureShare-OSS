/**
 * Security Headers Middleware for secure secret sharing
 * 
 * Adds Content-Security-Policy and other security headers to all responses.
 * This middleware wraps responses and adds headers that protect against:
 * - XSS attacks (via CSP)
 * - Clickjacking (via frame-ancestors and X-Frame-Options)
 * - MIME type sniffing (via X-Content-Type-Options)
 * - Information leakage (via Referrer-Policy)
 * - Downgrade attacks (via Strict-Transport-Security)
 * 
 * Requirements:
 * - 7.1: Include Content-Security-Policy headers in all responses
 * - 7.2: Prohibit inline scripts except for the application's own code
 * - 7.3: Prohibit loading external JavaScript resources
 * - 7.4: Restrict form actions to same-origin only
 * - 7.5: Enable frame-ancestors 'none' to prevent clickjacking
 */

/**
 * Content-Security-Policy directives
 * 
 * - default-src 'self': Only allow resources from same origin by default
 * - script-src 'self': Only allow scripts from same origin (no inline, no external)
 * - style-src 'self' 'unsafe-inline': Allow styles from same origin and inline styles
 * - form-action 'self': Only allow form submissions to same origin
 * - frame-ancestors 'none': Prevent embedding in frames (clickjacking protection)
 * - base-uri 'self': Restrict base URL to same origin
 * - object-src 'none': Disallow plugins (Flash, Java, etc.)
 * - img-src 'self' data:: Allow images from same origin and data URIs
 * - connect-src 'self': Only allow fetch/XHR to same origin
 */
export const CSP_DIRECTIVES: Record<string, string> = {
  'default-src': "'self'",
  'script-src': "'self'",
  'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com",
  'font-src': "'self' https://fonts.gstatic.com",
  'form-action': "'self'",
  'frame-ancestors': "'none'",
  'base-uri': "'self'",
  'object-src': "'none'",
  'img-src': "'self' data:",
  'connect-src': "'self'",
};

/**
 * Builds the Content-Security-Policy header value from directives
 * 
 * @param directives - Object mapping directive names to values
 * @returns The CSP header value string
 */
export function buildCspHeader(directives: Record<string, string>): string {
  return Object.entries(directives)
    .map(([directive, value]) => `${directive} ${value}`)
    .join('; ');
}

/**
 * Security headers to add to all responses
 */
export interface SecurityHeaders {
  /** Content-Security-Policy header value */
  'Content-Security-Policy': string;
  /** Prevent MIME type sniffing */
  'X-Content-Type-Options': string;
  /** Prevent clickjacking (legacy header, CSP frame-ancestors is preferred) */
  'X-Frame-Options': string;
  /** Control referrer information */
  'Referrer-Policy': string;
  /** Enforce HTTPS connections */
  'Strict-Transport-Security': string;
}

/**
 * Default security headers configuration
 */
export const DEFAULT_SECURITY_HEADERS: SecurityHeaders = {
  'Content-Security-Policy': buildCspHeader(CSP_DIRECTIVES),
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
};

/**
 * Adds security headers to a Response object
 * 
 * Creates a new Response with the same body and status, but with
 * security headers added. Existing headers are preserved.
 * 
 * @param response - The original Response object
 * @param securityHeaders - Security headers to add (defaults to DEFAULT_SECURITY_HEADERS)
 * @returns A new Response with security headers added
 */
export function addSecurityHeaders(
  response: Response,
  securityHeaders: SecurityHeaders = DEFAULT_SECURITY_HEADERS
): Response {
  // Clone the response to avoid modifying the original
  const newHeaders = new Headers(response.headers);
  
  // Add security headers
  for (const [name, value] of Object.entries(securityHeaders)) {
    newHeaders.set(name, value);
  }
  
  // Create a new response with the updated headers
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}

/**
 * Middleware function type
 * Takes a request handler and returns a wrapped handler with security headers
 */
export type RequestHandler = (request: Request) => Promise<Response>;

/**
 * Creates a middleware that adds security headers to all responses
 * 
 * This is a higher-order function that wraps a request handler and
 * automatically adds security headers to all responses.
 * 
 * @param handler - The request handler to wrap
 * @param securityHeaders - Security headers to add (defaults to DEFAULT_SECURITY_HEADERS)
 * @returns A wrapped handler that adds security headers to responses
 * 
 * @example
 * ```typescript
 * const handler = async (request: Request) => {
 *   return new Response('Hello, World!');
 * };
 * 
 * const secureHandler = withSecurityHeaders(handler);
 * const response = await secureHandler(request);
 * // response now has CSP and other security headers
 * ```
 */
export function withSecurityHeaders(
  handler: RequestHandler,
  securityHeaders: SecurityHeaders = DEFAULT_SECURITY_HEADERS
): RequestHandler {
  return async (request: Request): Promise<Response> => {
    const response = await handler(request);
    return addSecurityHeaders(response, securityHeaders);
  };
}

/**
 * Validates that a response has all required security headers
 * 
 * This is useful for testing to ensure security headers are properly applied.
 * 
 * @param response - The Response to validate
 * @returns An object with validation results for each header
 */
export function validateSecurityHeaders(response: Response): {
  valid: boolean;
  headers: Record<string, { present: boolean; value: string | null }>;
} {
  const requiredHeaders = [
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Referrer-Policy',
    'Strict-Transport-Security',
  ];
  
  const headers: Record<string, { present: boolean; value: string | null }> = {};
  let valid = true;
  
  for (const headerName of requiredHeaders) {
    const value = response.headers.get(headerName);
    const present = value !== null;
    headers[headerName] = { present, value };
    
    if (!present) {
      valid = false;
    }
  }
  
  return { valid, headers };
}

/**
 * Parses a CSP header value into its directives
 * 
 * @param cspHeader - The CSP header value string
 * @returns An object mapping directive names to their values
 */
export function parseCspHeader(cspHeader: string): Record<string, string> {
  const directives: Record<string, string> = {};
  
  // Split by semicolon and process each directive
  const parts = cspHeader.split(';').map(part => part.trim()).filter(part => part.length > 0);
  
  for (const part of parts) {
    // Split directive name from value (first space separates them)
    const spaceIndex = part.indexOf(' ');
    if (spaceIndex === -1) {
      // Directive with no value (e.g., 'upgrade-insecure-requests')
      directives[part] = '';
    } else {
      const name = part.substring(0, spaceIndex);
      const value = part.substring(spaceIndex + 1);
      directives[name] = value;
    }
  }
  
  return directives;
}

/**
 * Validates that a CSP header contains required security directives
 * 
 * Checks for:
 * - script-src that doesn't allow 'unsafe-inline' or external sources
 * - frame-ancestors 'none' to prevent clickjacking
 * - form-action 'self' to prevent form hijacking
 * 
 * @param cspHeader - The CSP header value string
 * @returns Validation result with details
 */
export function validateCspDirectives(cspHeader: string): {
  valid: boolean;
  issues: string[];
} {
  const directives = parseCspHeader(cspHeader);
  const issues: string[] = [];
  
  // Check script-src doesn't allow unsafe-inline (Requirement 7.2)
  const scriptSrc = directives['script-src'];
  if (!scriptSrc) {
    issues.push("Missing 'script-src' directive");
  } else if (scriptSrc.includes("'unsafe-inline'")) {
    issues.push("'script-src' should not allow 'unsafe-inline'");
  }
  
  // Check frame-ancestors is 'none' (Requirement 7.5)
  const frameAncestors = directives['frame-ancestors'];
  if (!frameAncestors) {
    issues.push("Missing 'frame-ancestors' directive");
  } else if (!frameAncestors.includes("'none'")) {
    issues.push("'frame-ancestors' should be 'none' to prevent clickjacking");
  }
  
  // Check form-action is 'self' (Requirement 7.4)
  const formAction = directives['form-action'];
  if (!formAction) {
    issues.push("Missing 'form-action' directive");
  } else if (!formAction.includes("'self'")) {
    issues.push("'form-action' should include 'self'");
  }
  
  // Check that external JS is not allowed (Requirement 7.3)
  // script-src should only have 'self' and not http:// or https:// URLs
  if (scriptSrc) {
    const hasExternalUrl = /https?:\/\//.test(scriptSrc);
    if (hasExternalUrl) {
      issues.push("'script-src' should not allow external URLs");
    }
  }
  
  return {
    valid: issues.length === 0,
    issues,
  };
}
