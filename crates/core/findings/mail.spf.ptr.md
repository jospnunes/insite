severity: low
title: SPF uses the deprecated ptr mechanism
---
The SPF record of {domain} relies on `ptr`, which the standard says not to use: it is slow, unreliable and some receivers skip it.

## Fix
Replace `ptr` with `ip4`/`ip6` ranges or the include of the sending service.
