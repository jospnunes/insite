severity: medium
title: No SPF record for {domain}
---
{domain} receives mail but has no SPF record, so receivers cannot tell which servers may send mail in its name. Mail from it is more likely to land in spam, and forging it is easier.

## Fix
Publish a TXT record on {domain} listing the services that send mail for it, ending in `-all` or `~all`, for example `v=spf1 include:_spf.google.com ~all` for Google Workspace.
