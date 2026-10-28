severity: high
title: Session cookie without the Secure flag
---
A cookie that looks like a session or login identifier ({value}) is set without `Secure`, so the browser also sends it over plain HTTP, where it can be stolen and used to take over the session.

## Fix
Add `Secure` (and `HttpOnly`, and `SameSite=Lax` or `Strict`) to session cookies, and serve the whole site over HTTPS with HSTS.
