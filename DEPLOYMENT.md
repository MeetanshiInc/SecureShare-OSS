# Deployment Guide for Secure Secret Sharing

This guide covers deploying the Secure Secret Sharing application to Cloudflare Workers.

## Prerequisites

1. **Cloudflare Account**: Sign up at [cloudflare.com](https://cloudflare.com)
2. **Node.js**: Version 18.0.0 or higher
3. **Wrangler CLI**: Installed via npm (included in devDependencies)

## Initial Setup

### 1. Authenticate with Cloudflare

```bash
npx wrangler login
```

This will open a browser window to authenticate with your Cloudflare account.

### 2. Create KV Namespaces

The application uses Cloudflare KV to store encrypted secrets. You need to create KV namespaces for each environment.

#### Development/Preview Namespace

```bash
# Create the main KV namespace
npm run kv:create

# Create the preview namespace (for local development)
npm run kv:create:preview
```

After running these commands, you'll see output like:

```
{ binding = "SECRETS_KV", id = "abc123def456..." }
```

Copy the `id` values and update `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "SECRETS_KV"
id = "your-actual-kv-namespace-id"
preview_id = "your-actual-preview-kv-namespace-id"
```

#### Production Namespace

```bash
npm run kv:create:production
```

Update the production section in `wrangler.toml`:

```toml
[[env.production.kv_namespaces]]
binding = "SECRETS_KV"
id = "your-actual-production-kv-namespace-id"
```

### 3. Verify KV Namespaces

List all your KV namespaces to verify they were created:

```bash
npm run kv:list
```

## Deployment

### Development Deployment

Deploy to the default (development) environment:

```bash
npm run deploy
```

This will:
1. Build the worker and frontend
2. Deploy to `secure-secret-sharing.<your-subdomain>.workers.dev`

### Production Deployment

Deploy to the production environment:

```bash
npm run deploy:production
```

This will deploy to the production environment with its own KV namespace.

### Staging Deployment (Optional)

If you've configured a staging environment:

```bash
npm run deploy:staging
```

## Custom Domain Setup

### Option 1: Workers Routes (Recommended)

1. Add your domain to Cloudflare (if not already)
2. Update `wrangler.toml` with your route:

```toml
[env.production]
name = "secure-secret-sharing"
routes = [
  { pattern = "secrets.yourdomain.com/*", zone_name = "yourdomain.com" }
]
```

3. Deploy to production:

```bash
npm run deploy:production
```

### Option 2: Custom Domains via Dashboard

1. Go to Cloudflare Dashboard
2. Navigate to **Workers & Pages** > **secure-secret-sharing**
3. Click **Settings** > **Triggers**
4. Under **Custom Domains**, click **Add Custom Domain**
5. Enter your domain (e.g., `secrets.yourdomain.com`)
6. Cloudflare will automatically configure DNS

## Environment Variables

The application doesn't require any secret environment variables. All sensitive data (encryption keys) are handled client-side and never stored on the server.

If you need to add environment variables in the future:

```bash
# Set a secret
wrangler secret put MY_SECRET --env production

# List secrets
wrangler secret list --env production
```

## Monitoring

### View Real-time Logs

```bash
# Development environment
npm run tail

# Production environment
npm run tail:production
```

### Cloudflare Dashboard

1. Go to **Workers & Pages** > **secure-secret-sharing**
2. Click **Logs** to view request logs
3. Click **Analytics** to view traffic metrics

## Troubleshooting

### Common Issues

#### "KV namespace not found"

Ensure you've created the KV namespace and updated `wrangler.toml` with the correct ID:

```bash
npm run kv:list
```

#### "Build failed"

Run the build manually to see detailed errors:

```bash
npm run build
```

#### "Authentication failed"

Re-authenticate with Cloudflare:

```bash
npx wrangler logout
npx wrangler login
```

### Verify Deployment

After deployment, test the application:

1. Open your worker URL (e.g., `https://secure-secret-sharing.<subdomain>.workers.dev`)
2. Create a test secret
3. Open the generated link in a new browser/incognito window
4. Verify the secret is displayed and then deleted

## Security Considerations

### KV Data Retention

- Secrets are automatically deleted after first access
- TTL-based expiration is handled by Cloudflare KV
- No manual cleanup is required

### HTTPS

- Cloudflare Workers automatically serve over HTTPS
- HTTP requests are redirected to HTTPS

### Content Security Policy

- CSP headers are automatically applied by the worker middleware
- No external JavaScript is loaded
- Inline scripts are restricted

## Rollback

To rollback to a previous version:

1. Go to Cloudflare Dashboard
2. Navigate to **Workers & Pages** > **secure-secret-sharing**
3. Click **Deployments**
4. Find the previous deployment and click **Rollback**

## Cost Considerations

### Free Tier Limits

- 100,000 requests/day
- 10ms CPU time per request
- 1GB KV storage
- 100,000 KV reads/day
- 1,000 KV writes/day

### Paid Plans

For higher traffic, consider the Workers Paid plan:
- Unlimited requests
- 30s CPU time per request
- Higher KV limits

## Support

- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
- [Cloudflare KV Documentation](https://developers.cloudflare.com/kv/)
- [Wrangler CLI Documentation](https://developers.cloudflare.com/workers/wrangler/)
