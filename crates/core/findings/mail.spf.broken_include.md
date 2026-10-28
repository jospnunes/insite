severity: medium
title: SPF includes {target}, which has no SPF record
---
The SPF record of {domain} includes {target}, but that name has no SPF record. Receivers treat this as a permanent error.

## Fix
Fix or remove the `include:{target}` term; check the exact name in the sending service's documentation.
