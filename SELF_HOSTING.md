# Self-Hosting SecureShare on Cloudflare

This guide covers:

1. One-click deploy via the Deploy to Cloudflare button
2. Post-deployment configuration
3. Custom domain setup
4. Updating to the latest version

## Deploy

### 1) Deploy from GitHub

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/MeetanshiInc/SecureShare-OSS)

Click the button above, then:

1. Connect your Git provider (GitHub or GitLab).
2. Leave the resource naming fields as default, or customize the Worker and KV namespace names.
3. Click **Create and Deploy**.
4. Wait 1–2 minutes for the build and deployment to finish.

Cloudflare automatically provisions the KV namespace (`SECRETS_KV`) required for storing encrypted secrets. No manual KV setup is needed.

### 2) Verify deployment

1. Open your Worker URL (shown after deployment, e.g. `https://secure-secret-sharing.<your-subdomain>.workers.dev`).
2. Create a test secret.
3. Open the generated link in a new browser or incognito window.
4. Confirm the secret is displayed and then deleted.

## Configuration

All settings have sensible defaults and work out of the box. To customize, go to your Worker in the Cloudflare dashboard:

**Workers & Pages → your Worker → Settings → Variables & Secrets**

| Variable | Default | Description |
|----------|---------|-------------|
| `QR_CODE_ENABLED` | `true` | Show a QR code after creating a secret link |
| `VIEW_SECRET_ENABLED` | `true` | Enable the secret viewing page (`false` returns 404 for all view URLs) |
| `MAX_SECRET_LENGTH` | `10000` | Maximum characters in the secret textarea (`0` = unlimited) |
| `DEFAULT_TTL` | `2592000` | Default expiry in seconds (2592000 = 30 days) |
| `TTL_OPTIONS` | `3600:1 hour,86400:24 hours,604800:7 days,2592000:30 days` | Expiry dropdown options as `value:label` pairs |

Or edit `wrangler.toml` in your forked repo:

```toml
[vars]
QR_CODE_ENABLED = "true"
VIEW_SECRET_ENABLED = "true"
MAX_SECRET_LENGTH = "10000"
DEFAULT_TTL = "2592000"
TTL_OPTIONS = "3600:1 hour,86400:24 hours,604800:7 days,2592000:30 days"
```

## Custom Domain

### Option A: Cloudflare Dashboard

1. Go to **Workers & Pages** → your Worker → **Settings** → **Domains & Routes**.
2. Click **Add** → **Custom Domain**.
3. Enter your domain (e.g. `secrets.yourdomain.com`).
4. Cloudflare configures DNS automatically.

### Option B: wrangler.toml

Add a route to your `wrangler.toml`:

```toml
[env.production]
routes = [
  { pattern = "secrets.yourdomain.com/*", zone_name = "yourdomain.com" }
]
```

Then push to trigger a redeploy.

## Updating to the Latest Version

If your repo was created via the Deploy to Cloudflare button, pull updates from the upstream repo.

### One-time setup

```bash
git clone https://github.com/<your-username>/SecureShare-OSS.git
cd SecureShare-OSS
git remote add upstream https://github.com/MeetanshiInc/SecureShare-OSS.git
```

### Update steps

```bash
git fetch upstream
git checkout main
git merge upstream/main
```

Resolve any conflicts in `wrangler.toml` (keep your KV namespace IDs and custom config), then:

```bash
git push origin main
```

Cloudflare Workers Builds will automatically redeploy.

## Security Notes

- All encryption happens client-side — the server never sees plaintext secrets or the full decryption key.
- Cloudflare Workers serve over HTTPS by default.
- Strict Content Security Policy headers are applied to all responses.
- Secrets are atomically deleted from KV after first access.
- KV TTL handles auto-expiry for unviewed secrets.

## Cost

SecureShare runs comfortably within the Cloudflare free tier:

| Resource | Free Tier Limit |
|----------|----------------|
| Worker requests | 100,000/day |
| KV reads | 100,000/day |
| KV writes | 1,000/day |
| KV storage | 1 GB |

For higher traffic, the Workers Paid plan ($5/month) removes these limits.

## Troubleshooting

**"KV namespace not found"** — The deploy button should auto-provision this. If it didn't, create one manually:
```bash
npx wrangler kv:namespace create SECRETS_KV
```
Then update the `id` in `wrangler.toml`.

**Build fails** — Make sure Node.js 18+ is used. Run `npm run build` locally to see detailed errors.

**Secrets not deleting after view** — Check that your KV namespace binding is named `SECRETS_KV` in `wrangler.toml`.
