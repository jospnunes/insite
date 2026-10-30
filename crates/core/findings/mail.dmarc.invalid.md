severity: medium
title: Invalid DMARC record for {domain}
---
The DMARC record of {domain} is not usable: {reason}.

## Fix
Keep a single TXT record on `_dmarc.{domain}` starting with `v=DMARC1;` and containing a `p=` policy (`none`, `quarantine` or `reject`).
