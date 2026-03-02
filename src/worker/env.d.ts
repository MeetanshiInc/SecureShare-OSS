/**
 * Cloudflare Worker environment bindings
 * This file defines the types for KV namespaces and other bindings
 */

export interface Env {
  /**
   * KV namespace for storing encrypted secrets
   * Bound in wrangler.toml as SECRETS_KV
   */
  SECRETS_KV: KVNamespace;

  /**
   * Assets binding for serving static files (auto-bound by Wrangler v4 [assets] config)
   */
  ASSETS: { fetch: typeof fetch };
}

/**
 * Execution context for Cloudflare Workers
 */
export interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}
