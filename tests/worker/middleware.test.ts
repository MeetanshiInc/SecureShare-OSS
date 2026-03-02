/**
 * Unit tests for security headers middleware
 * 
 * Tests the CSP and security headers middleware functionality.
 * 
 * Requirements tested:
 * - 7.1: Include Content-Security-Policy headers in all responses
 * - 7.2: Prohibit inline scripts except for the application's own code
 * - 7.3: Prohibit loading external JavaScript resources
 * - 7.4: Restrict form actions to same-origin only
 * - 7.5: Enable frame-ancestors 'none' to prevent clickjacking
 */

import { describe, it, expect } from 'vitest';
import {
  CSP_DIRECTIVES,
  DEFAULT_SECURITY_HEADERS,
  buildCspHeader,
  addSecurityHeaders,
  withSecurityHeaders,
  validateSecurityHeaders,
  parseCspHeader,
  validateCspDirectives,
} from '../../src/worker/middleware';

describe('CSP_DIRECTIVES', () => {
  it('should have default-src set to self', () => {
    expect(CSP_DIRECTIVES['default-src']).toBe("'self'");
  });

  it('should have script-src set to self only (no unsafe-inline)', () => {
    expect(CSP_DIRECTIVES['script-src']).toBe("'self'");
    expect(CSP_DIRECTIVES['script-src']).not.toContain('unsafe-inline');
  });

  it('should have style-src allowing self, unsafe-inline, and Google Fonts', () => {
    expect(CSP_DIRECTIVES['style-src']).toBe("'self' 'unsafe-inline' https://fonts.googleapis.com");
  });

  it('should have font-src allowing self and Google Fonts', () => {
    expect(CSP_DIRECTIVES['font-src']).toBe("'self' https://fonts.gstatic.com");
  });

  it('should have form-action set to self (Requirement 7.4)', () => {
    expect(CSP_DIRECTIVES['form-action']).toBe("'self'");
  });

  it('should have frame-ancestors set to none (Requirement 7.5)', () => {
    expect(CSP_DIRECTIVES['frame-ancestors']).toBe("'none'");
  });

  it('should have base-uri set to self', () => {
    expect(CSP_DIRECTIVES['base-uri']).toBe("'self'");
  });

  it('should have object-src set to none', () => {
    expect(CSP_DIRECTIVES['object-src']).toBe("'none'");
  });
});

describe('buildCspHeader', () => {
  it('should build a valid CSP header string from directives', () => {
    const directives = {
      'default-src': "'self'",
      'script-src': "'self'",
    };
    
    const header = buildCspHeader(directives);
    
    expect(header).toContain("default-src 'self'");
    expect(header).toContain("script-src 'self'");
    expect(header).toContain('; ');
  });

  it('should handle single directive', () => {
    const directives = {
      'default-src': "'self'",
    };
    
    const header = buildCspHeader(directives);
    
    expect(header).toBe("default-src 'self'");
  });

  it('should handle empty directives', () => {
    const header = buildCspHeader({});
    expect(header).toBe('');
  });

  it('should build the default CSP header correctly', () => {
    const header = buildCspHeader(CSP_DIRECTIVES);
    
    // Verify all required directives are present
    expect(header).toContain("default-src 'self'");
    expect(header).toContain("script-src 'self'");
    expect(header).toContain("style-src 'self' 'unsafe-inline' https://fonts.googleapis.com");
    expect(header).toContain("form-action 'self'");
    expect(header).toContain("frame-ancestors 'none'");
    expect(header).toContain("base-uri 'self'");
  });
});

describe('DEFAULT_SECURITY_HEADERS', () => {
  it('should have Content-Security-Policy header', () => {
    expect(DEFAULT_SECURITY_HEADERS['Content-Security-Policy']).toBeDefined();
    expect(DEFAULT_SECURITY_HEADERS['Content-Security-Policy'].length).toBeGreaterThan(0);
  });

  it('should have X-Content-Type-Options set to nosniff', () => {
    expect(DEFAULT_SECURITY_HEADERS['X-Content-Type-Options']).toBe('nosniff');
  });

  it('should have X-Frame-Options set to DENY', () => {
    expect(DEFAULT_SECURITY_HEADERS['X-Frame-Options']).toBe('DENY');
  });

  it('should have Referrer-Policy set to no-referrer', () => {
    expect(DEFAULT_SECURITY_HEADERS['Referrer-Policy']).toBe('no-referrer');
  });

  it('should have Strict-Transport-Security with max-age and includeSubDomains', () => {
    const hsts = DEFAULT_SECURITY_HEADERS['Strict-Transport-Security'];
    expect(hsts).toContain('max-age=31536000');
    expect(hsts).toContain('includeSubDomains');
  });
});

describe('addSecurityHeaders', () => {
  it('should add all security headers to a response', () => {
    const originalResponse = new Response('Hello, World!', {
      status: 200,
      headers: { 'Content-Type': 'text/plain' },
    });
    
    const securedResponse = addSecurityHeaders(originalResponse);
    
    // Check all security headers are present
    expect(securedResponse.headers.get('Content-Security-Policy')).toBeDefined();
    expect(securedResponse.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(securedResponse.headers.get('X-Frame-Options')).toBe('DENY');
    expect(securedResponse.headers.get('Referrer-Policy')).toBe('no-referrer');
    expect(securedResponse.headers.get('Strict-Transport-Security')).toContain('max-age=31536000');
  });

  it('should preserve original headers', () => {
    const originalResponse = new Response('Hello, World!', {
      status: 200,
      headers: { 
        'Content-Type': 'application/json',
        'X-Custom-Header': 'custom-value',
      },
    });
    
    const securedResponse = addSecurityHeaders(originalResponse);
    
    expect(securedResponse.headers.get('Content-Type')).toBe('application/json');
    expect(securedResponse.headers.get('X-Custom-Header')).toBe('custom-value');
  });

  it('should preserve response status', () => {
    const originalResponse = new Response('Not Found', { status: 404 });
    
    const securedResponse = addSecurityHeaders(originalResponse);
    
    expect(securedResponse.status).toBe(404);
  });

  it('should preserve response body', async () => {
    const body = JSON.stringify({ message: 'test' });
    const originalResponse = new Response(body, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
    
    const securedResponse = addSecurityHeaders(originalResponse);
    const responseBody = await securedResponse.text();
    
    expect(responseBody).toBe(body);
  });

  it('should allow custom security headers', () => {
    const customHeaders = {
      'Content-Security-Policy': "default-src 'none'",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'Referrer-Policy': 'strict-origin',
      'Strict-Transport-Security': 'max-age=86400',
    };
    
    const originalResponse = new Response('Hello');
    const securedResponse = addSecurityHeaders(originalResponse, customHeaders);
    
    expect(securedResponse.headers.get('Content-Security-Policy')).toBe("default-src 'none'");
    expect(securedResponse.headers.get('X-Frame-Options')).toBe('SAMEORIGIN');
    expect(securedResponse.headers.get('Referrer-Policy')).toBe('strict-origin');
  });
});

describe('withSecurityHeaders', () => {
  it('should wrap a handler and add security headers to responses', async () => {
    const handler = async (_request: Request): Promise<Response> => {
      return new Response('Hello, World!');
    };
    
    const secureHandler = withSecurityHeaders(handler);
    const request = new Request('https://example.com/test');
    const response = await secureHandler(request);
    
    expect(response.headers.get('Content-Security-Policy')).toBeDefined();
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(response.headers.get('X-Frame-Options')).toBe('DENY');
  });

  it('should pass the request to the wrapped handler', async () => {
    let receivedUrl = '';
    const handler = async (request: Request): Promise<Response> => {
      receivedUrl = request.url;
      return new Response('OK');
    };
    
    const secureHandler = withSecurityHeaders(handler);
    const request = new Request('https://example.com/api/test');
    await secureHandler(request);
    
    expect(receivedUrl).toBe('https://example.com/api/test');
  });

  it('should preserve handler response status and body', async () => {
    const handler = async (_request: Request): Promise<Response> => {
      return new Response(JSON.stringify({ error: 'Not Found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    };
    
    const secureHandler = withSecurityHeaders(handler);
    const request = new Request('https://example.com/test');
    const response = await secureHandler(request);
    
    expect(response.status).toBe(404);
    const body = await response.json();
    expect(body).toEqual({ error: 'Not Found' });
  });
});

describe('validateSecurityHeaders', () => {
  it('should return valid=true when all headers are present', () => {
    const response = new Response('OK', {
      headers: {
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Strict-Transport-Security': 'max-age=31536000',
      },
    });
    
    const result = validateSecurityHeaders(response);
    
    expect(result.valid).toBe(true);
    expect(result.headers['Content-Security-Policy']?.present).toBe(true);
    expect(result.headers['X-Content-Type-Options']?.present).toBe(true);
    expect(result.headers['X-Frame-Options']?.present).toBe(true);
    expect(result.headers['Referrer-Policy']?.present).toBe(true);
    expect(result.headers['Strict-Transport-Security']?.present).toBe(true);
  });

  it('should return valid=false when headers are missing', () => {
    const response = new Response('OK', {
      headers: {
        'Content-Type': 'text/plain',
      },
    });
    
    const result = validateSecurityHeaders(response);
    
    expect(result.valid).toBe(false);
    expect(result.headers['Content-Security-Policy']?.present).toBe(false);
    expect(result.headers['X-Content-Type-Options']?.present).toBe(false);
  });

  it('should return header values when present', () => {
    const response = new Response('OK', {
      headers: {
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Strict-Transport-Security': 'max-age=31536000',
      },
    });
    
    const result = validateSecurityHeaders(response);
    
    expect(result.headers['Content-Security-Policy']?.value).toBe("default-src 'self'");
    expect(result.headers['X-Content-Type-Options']?.value).toBe('nosniff');
  });
});

describe('parseCspHeader', () => {
  it('should parse a simple CSP header', () => {
    const csp = "default-src 'self'";
    const directives = parseCspHeader(csp);
    
    expect(directives['default-src']).toBe("'self'");
  });

  it('should parse multiple directives', () => {
    const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'";
    const directives = parseCspHeader(csp);
    
    expect(directives['default-src']).toBe("'self'");
    expect(directives['script-src']).toBe("'self'");
    expect(directives['style-src']).toBe("'self' 'unsafe-inline'");
  });

  it('should handle directives with no value', () => {
    const csp = "upgrade-insecure-requests; default-src 'self'";
    const directives = parseCspHeader(csp);
    
    expect(directives['upgrade-insecure-requests']).toBe('');
    expect(directives['default-src']).toBe("'self'");
  });

  it('should handle empty string', () => {
    const directives = parseCspHeader('');
    expect(Object.keys(directives).length).toBe(0);
  });

  it('should handle the default CSP header', () => {
    const csp = buildCspHeader(CSP_DIRECTIVES);
    const directives = parseCspHeader(csp);
    
    expect(directives['default-src']).toBe("'self'");
    expect(directives['script-src']).toBe("'self'");
    expect(directives['frame-ancestors']).toBe("'none'");
    expect(directives['form-action']).toBe("'self'");
  });
});

describe('validateCspDirectives', () => {
  it('should validate a correct CSP header', () => {
    const csp = buildCspHeader(CSP_DIRECTIVES);
    const result = validateCspDirectives(csp);
    
    expect(result.valid).toBe(true);
    expect(result.issues).toHaveLength(0);
  });

  it('should detect missing script-src directive', () => {
    const csp = "default-src 'self'; frame-ancestors 'none'; form-action 'self'";
    const result = validateCspDirectives(csp);
    
    expect(result.valid).toBe(false);
    expect(result.issues).toContain("Missing 'script-src' directive");
  });

  it('should detect unsafe-inline in script-src (Requirement 7.2)', () => {
    const csp = "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'";
    const result = validateCspDirectives(csp);
    
    expect(result.valid).toBe(false);
    expect(result.issues).toContain("'script-src' should not allow 'unsafe-inline'");
  });

  it('should detect missing frame-ancestors directive (Requirement 7.5)', () => {
    const csp = "script-src 'self'; form-action 'self'";
    const result = validateCspDirectives(csp);
    
    expect(result.valid).toBe(false);
    expect(result.issues).toContain("Missing 'frame-ancestors' directive");
  });

  it('should detect frame-ancestors not set to none', () => {
    const csp = "script-src 'self'; frame-ancestors 'self'; form-action 'self'";
    const result = validateCspDirectives(csp);
    
    expect(result.valid).toBe(false);
    expect(result.issues).toContain("'frame-ancestors' should be 'none' to prevent clickjacking");
  });

  it('should detect missing form-action directive (Requirement 7.4)', () => {
    const csp = "script-src 'self'; frame-ancestors 'none'";
    const result = validateCspDirectives(csp);
    
    expect(result.valid).toBe(false);
    expect(result.issues).toContain("Missing 'form-action' directive");
  });

  it('should detect external URLs in script-src (Requirement 7.3)', () => {
    const csp = "script-src 'self' https://cdn.example.com; frame-ancestors 'none'; form-action 'self'";
    const result = validateCspDirectives(csp);
    
    expect(result.valid).toBe(false);
    expect(result.issues).toContain("'script-src' should not allow external URLs");
  });

  it('should detect http URLs in script-src', () => {
    const csp = "script-src 'self' http://cdn.example.com; frame-ancestors 'none'; form-action 'self'";
    const result = validateCspDirectives(csp);
    
    expect(result.valid).toBe(false);
    expect(result.issues).toContain("'script-src' should not allow external URLs");
  });
});

describe('Security Headers Integration', () => {
  it('should produce a response that passes all validations', () => {
    const originalResponse = new Response('OK');
    const securedResponse = addSecurityHeaders(originalResponse);
    
    // Validate all headers are present
    const headerValidation = validateSecurityHeaders(securedResponse);
    expect(headerValidation.valid).toBe(true);
    
    // Validate CSP directives
    const csp = securedResponse.headers.get('Content-Security-Policy')!;
    const cspValidation = validateCspDirectives(csp);
    expect(cspValidation.valid).toBe(true);
  });

  it('should satisfy Requirement 7.1: CSP headers in all responses', () => {
    const responses = [
      new Response('OK', { status: 200 }),
      new Response('Created', { status: 201 }),
      new Response('Not Found', { status: 404 }),
      new Response('Error', { status: 500 }),
    ];
    
    for (const response of responses) {
      const secured = addSecurityHeaders(response);
      expect(secured.headers.get('Content-Security-Policy')).toBeDefined();
    }
  });

  it('should satisfy Requirement 7.2: Prohibit inline scripts', () => {
    const response = addSecurityHeaders(new Response('OK'));
    const csp = response.headers.get('Content-Security-Policy')!;
    
    // script-src should not contain 'unsafe-inline'
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(csp).toContain("script-src 'self'");
  });

  it('should satisfy Requirement 7.3: Prohibit external JavaScript', () => {
    const response = addSecurityHeaders(new Response('OK'));
    const csp = response.headers.get('Content-Security-Policy')!;
    const directives = parseCspHeader(csp);
    
    // script-src should only be 'self'
    expect(directives['script-src']).toBe("'self'");
    expect(directives['script-src']).not.toContain('http');
  });

  it('should satisfy Requirement 7.4: Restrict form actions to same-origin', () => {
    const response = addSecurityHeaders(new Response('OK'));
    const csp = response.headers.get('Content-Security-Policy')!;
    const directives = parseCspHeader(csp);
    
    expect(directives['form-action']).toBe("'self'");
  });

  it('should satisfy Requirement 7.5: Prevent clickjacking', () => {
    const response = addSecurityHeaders(new Response('OK'));
    const csp = response.headers.get('Content-Security-Policy')!;
    const directives = parseCspHeader(csp);
    
    // CSP frame-ancestors should be 'none'
    expect(directives['frame-ancestors']).toBe("'none'");
    
    // X-Frame-Options should also be DENY (legacy support)
    expect(response.headers.get('X-Frame-Options')).toBe('DENY');
  });
});
