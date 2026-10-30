severity: high
title: SPF of {domain} needs {count} DNS lookups (limit 10)
---
Evaluating the SPF record of {domain} takes {count} DNS lookups counting nested includes, above the limit of 10. Receivers stop and return a permanent error, so SPF fails for legitimate mail too.

## Fix
Remove includes for services you no longer use, replace `a` and `mx` mechanisms with `ip4`/`ip6` ranges where possible, or use a provider that flattens the record.
