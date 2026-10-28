severity: medium
title: Anti-CSRF cookie without SameSite
---
A cookie that looks like an anti-CSRF token ({value}) has no `SameSite` attribute, which is the browser feature that stops it from being sent with requests started by other sites.

## Fix
Set `SameSite=Strict` (or `Lax`) on the anti-CSRF cookie.
