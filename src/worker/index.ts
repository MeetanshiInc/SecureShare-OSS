/**
 * Cloudflare Worker Entry Point for Secure Secret Sharing
 *
 * Handles the backend API (/api/* routes) and serves view.html for /s/* routes.
 * Other static assets are served automatically by Wrangler's [assets] config.
 */

import type { Env, ExecutionContext } from './env.d';
import { handleRequest } from './handlers';
import { addSecurityHeaders } from './middleware';
import { createSecretStore } from './secret-store';
import { createStubNotificationService } from './notification-service';

async function handleFetch(
  request: Request,
  env: Env,
  _ctx: ExecutionContext
): Promise<Response> {
  const url = new URL(request.url);

  // API routes — apply security headers
  if (url.pathname.startsWith('/api/')) {
    const secretStore = createSecretStore(env.SECRETS_KV);
    const notificationService = createStubNotificationService();
    const apiResponse = await handleRequest(request, secretStore, notificationService);
    if (apiResponse !== null) {
      return addSecurityHeaders(apiResponse);
    }
    return addSecurityHeaders(
      new Response(JSON.stringify({ error: 'Not Found', code: 'NOT_FOUND' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      })
    );
  }

  // /s/* routes serve view.html (the secret viewing page)
  // Fetch it via the ASSETS binding and return the body with 200
  if (url.pathname.startsWith('/s/')) {
    const viewRequest = new Request(new URL('/view.html', request.url).toString());
    const assetResponse = await env.ASSETS.fetch(viewRequest);
    // Follow the redirect if needed
    if (assetResponse.status >= 300 && assetResponse.status < 400) {
      const location = assetResponse.headers.get('Location');
      if (location) {
        const redirectUrl = new URL(location, request.url).toString();
        const redirectResponse = await env.ASSETS.fetch(new Request(redirectUrl));
        return addSecurityHeaders(new Response(redirectResponse.body, {
          status: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
          },
        }));
      }
    }
    return addSecurityHeaders(new Response(assetResponse.body, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
      },
    }));
  }

  // Everything else — serve from static assets with security headers
  const assetResponse = await env.ASSETS.fetch(request);
  return addSecurityHeaders(assetResponse);
}

export default {
  fetch: handleFetch,
};
