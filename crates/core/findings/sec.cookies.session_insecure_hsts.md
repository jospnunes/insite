severity: low
title: Session cookie without the Secure flag (HSTS mitigates)
---
A cookie that looks like a session identifier ({value}) is set without `Secure`. HSTS keeps the browser on HTTPS for this host, which limits the risk, but not for other hosts that receive the cookie or for a first visit.

## Fix
Add `Secure` to session cookies anyway: it costs nothing and does not depend on HSTS.
