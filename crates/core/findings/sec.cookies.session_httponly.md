severity: medium
title: Session cookie readable by scripts
---
A cookie that looks like a session or login identifier ({value}) is set without `HttpOnly`, so any script on the page, including an injected one, can read and steal it.

## Fix
Add `HttpOnly` to session cookies. Only cookies that scripts genuinely need to read should go without it.
