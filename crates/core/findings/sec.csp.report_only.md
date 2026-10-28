severity: medium
title: Content Security Policy only in report-only mode
---
The page sends `Content-Security-Policy-Report-Only` ({value}) but no enforced policy. Violations are reported, but nothing is blocked.

## Fix
Once the reports show the policy does not break the site, send the same policy as `Content-Security-Policy`.
