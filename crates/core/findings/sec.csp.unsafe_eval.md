severity: low
title: Content Security Policy allows eval()
---
The policy allows `'unsafe-eval'`, so scripts can turn text into code with `eval()`, `new Function()` and similar, which makes injected data easier to exploit. Policy: `{value}`.

## Fix
Remove `'unsafe-eval'` and replace the code that needs it; libraries usually offer a CSP-compatible build. If you cannot yet, keep it but restrict the script sources as much as possible.
