# Contributing to SecureShare

Thanks for your interest in contributing! SecureShare is open-source and we welcome contributions.

## Getting Started

1. Fork the repo
2. Clone: `git clone https://github.com/YOUR_USERNAME/SecureShare-OSS.git`
3. Install: `npm install`
4. Dev server: `npm run dev` (http://localhost:8787)
5. Tests: `npm test`

## Guidelines

- All encryption/decryption must happen client-side only
- The server must never access the full decryption key or plaintext
- Property-based tests preferred for crypto code
- Zero client-side dependencies (Web Crypto API only)
- All responses must include security headers

## Pull Requests

1. All tests pass: `npm test`
2. Types check: `npm run typecheck`
3. Write tests for new functionality
4. One feature or fix per PR

## Security

If you find a vulnerability, do NOT open a public issue. Email the maintainers directly.

## License

By contributing, you agree your contributions are licensed under MIT.
