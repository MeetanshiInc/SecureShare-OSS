/**
 * Property-Based Tests for CSP Headers
 * 
 * **Validates: Requirements 7.1**
 * 
 * Property 9: CSP Headers Present
 * For any API response from the backend, the response should include
 * Content-Security-Policy headers that prohibit inline scripts, external
 * JavaScript, and frame embedding.
 * 
 * Requirements context:
 * - 7.1: Include Content-Security-Policy headers in all responses
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  addSecurityHeaders,
  withSecurityHeaders,
  validateSecurityHeaders,
  validateCspDirectives,
  parseCspHeader,
  type RequestHandler,
} from '../../src/worker/middleware';

/**
 * Arbitrary generator for HTTP status codes that can have a body.
 * Excludes 1xx (informational), 204 (No Content), 205 (Reset Content),
 * and 304 (Not Modified) as these cannot have a response body per HTTP spec.
 * Also excludes some less common codes that may have restrictions.
 */
const httpStatusCodeArbitrary: fc.Arbitrary<number> = fc.oneof(
  // Success responses (most common that support bodies)
  fc.constantFrom(200, 201, 202, 203),
  // Redirection responses (excluding 304)
  fc.constantFrom(301, 302, 303, 307, 308),
  // Client error responses
  fc.constantFrom(400, 401, 403, 404, 405, 409, 422, 429),
  // Server error responses
  fc.constantFrom(500, 501, 502, 503, 504)
);

/**
 * Arbitrary generator for content types commonly used in API responses.
 */
const contentTypeArbitrary: fc.Arbitrary<string> = fc.oneof(
  fc.constant('application/json'),
  fc.constant('application/json; charset=utf-8'),
  fc.constant('text/plain'),
  fc.constant('text/plain; charset=utf-8'),
  fc.constant('text/html'),
  fc.constant('text/html; charset=utf-8'),
  fc.constant('application/octet-stream'),
  fc.constant('application/xml'),
  fc.constant('text/css'),
  fc.constant('application/javascript')
);

/**
 * Arbitrary generator for response body content.
 * Generates various types of content that might appear in API responses.
 */
const responseBodyArbitrary: fc.Arbitrary<string> = fc.oneof(
  // Empty body
  fc.constant(''),
  // JSON responses
  fc.record({
    message: fc.string(),
    code: fc.string(),
  }).map(obj => JSON.stringify(obj)),
  // Plain text
  fc.string({ minLength: 0, maxLength: 500 }),
  // JSON with nested objects
  fc.record({
    data: fc.record({
      id: fc.string(),
      value: fc.string(),
    }),
    status: fc.string(),
  }).map(obj => JSON.stringify(obj)),
  // JSON arrays
  fc.array(fc.string(), { minLength: 0, maxLength: 5 }).map(arr => JSON.stringify(arr))
);

/**
 * Arbitrary generator for custom header values.
 * HTTP headers trim leading/trailing whitespace, so we generate non-whitespace-only values.
 */
const headerValueArbitrary: fc.Arbitrary<string> = fc.stringOf(
  fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'),
  { minLength: 1, maxLength: 50 }
);

/**
 * Arbitrary generator for custom headers that might be present on responses.
 */
const customHeadersArbitrary: fc.Arbitrary<Record<string, string>> = fc.dictionary(
  fc.constantFrom(
    'X-Request-Id',
    'X-Correlation-Id',
    'Cache-Control',
    'ETag',
    'Last-Modified',
    'X-Custom-Header'
  ),
  headerValueArbitrary
);

/**
 * Creates a Response object with the given parameters.
 */
function createResponse(
  body: string,
  status: number,
  contentType: string,
  customHeaders: Record<string, string> = {}
): Response {
  const headers: Record<string, string> = {
    'Content-Type': contentType,
    ...customHeaders,
  };
  
  return new Response(body, {
    status,
    headers,
  });
}

describe('Property 9: CSP Headers Present', () => {
  /**
   * **Validates: Requirements 7.1**
   * 
   * Property: For any response with any status code, after applying security
   * headers middleware, the response should have a Content-Security-Policy header.
   */
  it('CSP header is present for all response status codes', async () => {
    await fc.assert(
      fc.asyncProperty(
        httpStatusCodeArbitrary,
        responseBodyArbitrary,
        contentTypeArbitrary,
        async (statusCode, body, contentType) => {
          // Create a response with the given status code
          const originalResponse = createResponse(body, statusCode, contentType);
          
          // Apply security headers
          const securedResponse = addSecurityHeaders(originalResponse);
          
          // Verify CSP header is present
          const cspHeader = securedResponse.headers.get('Content-Security-Policy');
          expect(cspHeader).not.toBeNull();
          expect(cspHeader!.length).toBeGreaterThan(0);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 7.1**
   * 
   * Property: For any response with any content type, after applying security
   * headers middleware, the response should have a valid CSP header that passes
   * all security validations.
   */
  it('CSP header passes validation for all content types', async () => {
    await fc.assert(
      fc.asyncProperty(
        httpStatusCodeArbitrary,
        responseBodyArbitrary,
        contentTypeArbitrary,
        async (statusCode, body, contentType) => {
          // Create a response with the given content type
          const originalResponse = createResponse(body, statusCode, contentType);
          
          // Apply security headers
          const securedResponse = addSecurityHeaders(originalResponse);
          
          // Validate all security headers are present
          const headerValidation = validateSecurityHeaders(securedResponse);
          expect(headerValidation.valid).toBe(true);
          
          // Validate CSP directives
          const cspHeader = securedResponse.headers.get('Content-Security-Policy')!;
          const cspValidation = validateCspDirectives(cspHeader);
          expect(cspValidation.valid).toBe(true);
          expect(cspValidation.issues).toHaveLength(0);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 7.1**
   * 
   * Property: For any response, the CSP header should prohibit inline scripts
   * by not including 'unsafe-inline' in the script-src directive.
   */
  it('CSP prohibits inline scripts (no unsafe-inline in script-src)', async () => {
    await fc.assert(
      fc.asyncProperty(
        httpStatusCodeArbitrary,
        responseBodyArbitrary,
        contentTypeArbitrary,
        async (statusCode, body, contentType) => {
          // Create and secure a response
          const originalResponse = createResponse(body, statusCode, contentType);
          const securedResponse = addSecurityHeaders(originalResponse);
          
          // Parse CSP header
          const cspHeader = securedResponse.headers.get('Content-Security-Policy')!;
          const directives = parseCspHeader(cspHeader);
          
          // Verify script-src exists and doesn't contain 'unsafe-inline'
          expect(directives['script-src']).toBeDefined();
          expect(directives['script-src']).not.toContain("'unsafe-inline'");
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 7.1**
   * 
   * Property: For any response, the CSP header should prohibit external JavaScript
   * by not including http:// or https:// URLs in the script-src directive.
   */
  it('CSP prohibits external JavaScript (no http/https URLs in script-src)', async () => {
    await fc.assert(
      fc.asyncProperty(
        httpStatusCodeArbitrary,
        responseBodyArbitrary,
        contentTypeArbitrary,
        async (statusCode, body, contentType) => {
          // Create and secure a response
          const originalResponse = createResponse(body, statusCode, contentType);
          const securedResponse = addSecurityHeaders(originalResponse);
          
          // Parse CSP header
          const cspHeader = securedResponse.headers.get('Content-Security-Policy')!;
          const directives = parseCspHeader(cspHeader);
          
          // Verify script-src doesn't contain external URLs
          const scriptSrc = directives['script-src'];
          expect(scriptSrc).toBeDefined();
          expect(scriptSrc).not.toMatch(/https?:\/\//);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 7.1**
   * 
   * Property: For any response, the CSP header should prevent frame embedding
   * by setting frame-ancestors to 'none'.
   */
  it('CSP prevents frame embedding (frame-ancestors none)', async () => {
    await fc.assert(
      fc.asyncProperty(
        httpStatusCodeArbitrary,
        responseBodyArbitrary,
        contentTypeArbitrary,
        async (statusCode, body, contentType) => {
          // Create and secure a response
          const originalResponse = createResponse(body, statusCode, contentType);
          const securedResponse = addSecurityHeaders(originalResponse);
          
          // Parse CSP header
          const cspHeader = securedResponse.headers.get('Content-Security-Policy')!;
          const directives = parseCspHeader(cspHeader);
          
          // Verify frame-ancestors is 'none'
          expect(directives['frame-ancestors']).toBeDefined();
          expect(directives['frame-ancestors']).toContain("'none'");
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 7.1**
   * 
   * Property: For any response with custom headers, applying security headers
   * should preserve the original headers while adding CSP.
   */
  it('CSP headers are added while preserving original headers', async () => {
    await fc.assert(
      fc.asyncProperty(
        httpStatusCodeArbitrary,
        responseBodyArbitrary,
        contentTypeArbitrary,
        customHeadersArbitrary,
        async (statusCode, body, contentType, customHeaders) => {
          // Create a response with custom headers
          const originalResponse = createResponse(body, statusCode, contentType, customHeaders);
          
          // Apply security headers
          const securedResponse = addSecurityHeaders(originalResponse);
          
          // Verify CSP header is present
          expect(securedResponse.headers.get('Content-Security-Policy')).not.toBeNull();
          
          // Verify original headers are preserved
          expect(securedResponse.headers.get('Content-Type')).toBe(contentType);
          for (const [name, value] of Object.entries(customHeaders)) {
            expect(securedResponse.headers.get(name)).toBe(value);
          }
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 7.1**
   * 
   * Property: For any request handler wrapped with withSecurityHeaders,
   * all responses should have CSP headers regardless of the handler's behavior.
   */
  it('withSecurityHeaders middleware adds CSP to all handler responses', async () => {
    await fc.assert(
      fc.asyncProperty(
        httpStatusCodeArbitrary,
        responseBodyArbitrary,
        contentTypeArbitrary,
        fc.stringOf(
          fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-_'),
          { minLength: 1, maxLength: 50 }
        ), // URL path
        async (statusCode, body, contentType, urlPath) => {
          // Create a handler that returns various responses
          const handler: RequestHandler = async (_request: Request) => {
            return createResponse(body, statusCode, contentType);
          };
          
          // Wrap with security headers middleware
          const secureHandler = withSecurityHeaders(handler);
          
          // Create a request
          const request = new Request(`https://example.com/${urlPath}`);
          
          // Execute the handler
          const response = await secureHandler(request);
          
          // Verify CSP header is present
          const cspHeader = response.headers.get('Content-Security-Policy');
          expect(cspHeader).not.toBeNull();
          
          // Verify CSP is valid
          const cspValidation = validateCspDirectives(cspHeader!);
          expect(cspValidation.valid).toBe(true);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 7.1**
   * 
   * Property: For any response, the CSP header should contain all required
   * security directives (script-src, frame-ancestors, form-action).
   */
  it('CSP contains all required security directives', async () => {
    await fc.assert(
      fc.asyncProperty(
        httpStatusCodeArbitrary,
        responseBodyArbitrary,
        contentTypeArbitrary,
        async (statusCode, body, contentType) => {
          // Create and secure a response
          const originalResponse = createResponse(body, statusCode, contentType);
          const securedResponse = addSecurityHeaders(originalResponse);
          
          // Parse CSP header
          const cspHeader = securedResponse.headers.get('Content-Security-Policy')!;
          const directives = parseCspHeader(cspHeader);
          
          // Verify all required directives are present
          expect(directives['default-src']).toBeDefined();
          expect(directives['script-src']).toBeDefined();
          expect(directives['frame-ancestors']).toBeDefined();
          expect(directives['form-action']).toBeDefined();
          
          // Verify directives have correct values
          expect(directives['default-src']).toContain("'self'");
          expect(directives['script-src']).toContain("'self'");
          expect(directives['frame-ancestors']).toBe("'none'");
          expect(directives['form-action']).toContain("'self'");
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  /**
   * **Validates: Requirements 7.1**
   * 
   * Property: For any response body (including empty, JSON, or arbitrary text),
   * the response body should be preserved after adding security headers.
   */
  it('response body is preserved after adding CSP headers', async () => {
    await fc.assert(
      fc.asyncProperty(
        httpStatusCodeArbitrary,
        responseBodyArbitrary,
        contentTypeArbitrary,
        async (statusCode, body, contentType) => {
          // Create a response
          const originalResponse = createResponse(body, statusCode, contentType);
          
          // Apply security headers
          const securedResponse = addSecurityHeaders(originalResponse);
          
          // Verify body is preserved
          const securedBody = await securedResponse.text();
          expect(securedBody).toBe(body);
          
          // Verify status is preserved
          expect(securedResponse.status).toBe(statusCode);
          
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });
});
