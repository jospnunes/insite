severity: medium
title: Content Security Policy allows inline or arbitrary scripts
---
The policy allows `'unsafe-inline'`, `data:` or a source as broad as `https:` or `*` for scripts (or objects), so it does not stop injected scripts, which is the main reason to have a CSP.

## Fix
Move inline scripts to files, or allow them with nonces or hashes (`'nonce-…'`, `'sha256-…'`, with `'strict-dynamic'`), list specific hosts instead of whole schemes, and set `object-src 'none'`.
