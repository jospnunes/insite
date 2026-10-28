severity: low
title: SPF record without an ending policy
---
The SPF record of {domain} has no `all` mechanism, so mail from servers it does not list gets a neutral result instead of failing.

## Fix
End the record with `-all`, or `~all` while you confirm every sending service is listed.
