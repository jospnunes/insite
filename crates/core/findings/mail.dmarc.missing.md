severity: medium
title: No DMARC record for {domain}
---
{domain} receives mail but has no DMARC record. Receivers get no policy for mail that fails SPF and DKIM, and you get no reports about who sends mail in your name. Gmail and Yahoo require DMARC from bulk senders.

## Fix
Start with `v=DMARC1; p=none; rua=mailto:dmarc@{domain}` on `_dmarc.{domain}`, read the reports, then move to `p=quarantine` and `p=reject`.
