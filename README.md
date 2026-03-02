<p align="center">
  <img src="src/frontend/secureshare-logo.svg" alt="SecureShare" width="320" />
</p>

<p align="center">
  <strong>Free, open-source one-time secret sharing with end-to-end encryption.</strong><br>
  Share passwords, API keys, and sensitive data through self-destructing links.
</p>

<p align="center">
  <a href="https://sec.meetanshi.com">Live Demo</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#self-hosting">Self-Hosting</a> &middot;
  <a href="#security-model">Security</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-blue" alt="AES-256-GCM" />
  <img src="https://img.shields.io/badge/runtime-Cloudflare%20Workers-orange" alt="Cloudflare Workers" />
  <img src="https://img.shields.io/badge/tests-484%20passing-brightgreen" alt="484 tests" />
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT" />
  <img src="https://img.shields.io/badge/dependencies-0%20client--side-lightgrey" alt="Zero deps" />
</p>

---

## How It Works

1. **Encrypt** — Your browser generates a 256-bit key, encrypts the secret with AES-256-GCM, and splits the key in half
2. **Store** — One key half goes in the URL fragment (never sent to the server), the other is stored server-side with the encrypted blob
3. **Share** — Send the link to your recipient
4. **Decrypt** — The recipient's browser recombines the key halves and decrypts locally
5. **Delete** — The secret is permanently deleted after one view

> The server never has enough information to decrypt the secret.

## Features

- **End-to-end encryption** — AES-256-GCM via Web Crypto API, entirely in the browser
- **Split-key architecture** — Decryption key split into two halves; server only stores one
- **One-time access** — Secrets atomically retrieved and deleted on first view
- **Password protection** — Optional PBKDF2-derived double encryption (100K iterations)
- **Auto-expiry** — Configurable TTL: 1 hour, 24 hours, 7 days, or 30 days
- **Zero knowledge** — Server never receives the full key, plaintext, or URL fragment
- **Strict CSP** — Blocks inline scripts, external JS, and clickjacking
- **Zero client dependencies** — Pure Web Crypto API

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Vanilla TypeScript, HTML, CSS |
| Backend | Cloudflare Workers |
| Storage | Cloudflare KV (TTL-based auto-expiry) |
| Encryption | Web Crypto API (AES-256-GCM, PBKDF2) |
| Testing | Vitest + fast-check (property-based) |


## Self-Hosting

SecureShare runs on Cloudflare Workers with KV storage. Deploy your own instance in minutes.

### Prerequisites

- Node.js 18+
- A Cloudflare account (free tier works)

### Quick Start

```bash
git clone https://github.com/MeetanshiInc/SecureShare.git
cd SecureShare
npm install
npx wrangler kv:namespace create SECRETS_KV
# Update wrangler.toml with your namespace ID
npm run deploy
```

### Local Development

```bash
npm run dev
```

Runs on http://localhost:8787

### Run Tests

```bash
npm test
```

484 tests including property-based tests for encryption, key splitting, one-time access, and more.


## Security Model

### What the Server Never Sees

| Data | Server Access |
|------|:------------:|
| Full decryption key | No |
| URL fragment (public key half) | No |
| Plaintext secret | No |
| User password | No |

### Encryption Flow

```
Secret -> Generate 256-bit key -> Split key in half
-> Encrypt with AES-256-GCM -> [Optional: PBKDF2 password layer]
-> Send encrypted blob + private key half to server
-> URL contains secret ID + public key half in fragment
```

### Decryption Flow

```
Open link -> Extract public key half from fragment (never sent to server)
-> Fetch encrypted blob + private key half from server
-> Server deletes secret immediately
-> [If password-protected: prompt + PBKDF2 decrypt]
-> Recombine key halves -> AES-256-GCM decrypt -> Display
```

### Security Headers

All responses include CSP (`script-src 'self'`, `frame-ancestors 'none'`), HSTS, X-Frame-Options DENY, no-referrer, and nosniff.

## Project Structure

```
src/
  frontend/    Client-side HTML, TypeScript, assets
  shared/      Crypto utilities (AES-256-GCM, PBKDF2, key splitting)
  worker/      Cloudflare Worker backend (routing, handlers, KV store)
tests/
  frontend/    Frontend unit tests
  property/    Property-based tests (fast-check)
  shared/      Shared utility tests
  worker/      Worker handler tests
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT - Created by [Meetanshi](https://meetanshi.com)
