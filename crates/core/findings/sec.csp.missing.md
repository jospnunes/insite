severity: medium
title: No Content Security Policy
---
The page sends no `Content-Security-Policy` header (or `<meta>`). A CSP limits where scripts, styles and frames can come from, so an injected script (XSS) has much less it can do.

## Fix
Start with a policy in report-only mode to see what would break, then enforce it. A good first policy: `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'`, adding the hosts the site really uses.
