severity: medium
title: Content Security Policy cannot be parsed
---
The Content Security Policy is malformed: a directive is repeated, a policy is too short to mean anything, or `'strict-dynamic'` is used without a nonce or hash. Policy: `{value}`.

## Fix
Write each directive once per policy, separated by `;`, and use `'strict-dynamic'` only together with a `'nonce-…'` or `'sha256-…'` source. A CSP validator (such as the CSP Evaluator) points to the exact problem.
