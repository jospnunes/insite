severity: high
title: {count} SPF records
---
{domain} has {count} SPF records. The standard requires exactly one; with more, receivers treat SPF as a permanent error and ignore it.

## Fix
Merge them into a single `v=spf1` record that lists every sending service once.
