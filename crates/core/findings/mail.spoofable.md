severity: low
title: {domain} is open to e-mail spoofing
---
{domain} receives no mail and publishes neither SPF nor DMARC, so receivers have no way to reject mail that falsely claims to come from it.

## Fix
Publish `v=spf1 -all` as a TXT record on {domain} and `v=DMARC1; p=reject` on `_dmarc.{domain}`. Together they say the domain sends no mail at all.
