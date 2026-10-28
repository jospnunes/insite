severity: low
title: DMARC only monitors (p=none)
---
The DMARC policy of {domain} is `p=none`: receivers report failures but still deliver forged mail.

## Fix
Once the reports show that all legitimate mail passes, raise the policy to `p=quarantine` and then `p=reject`.
