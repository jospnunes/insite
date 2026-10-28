severity: medium
title: No viewport meta tag
---
Without `<meta name="viewport">`, phones render the page at desktop width and zoom out. Google indexes the mobile version, so this also hurts search.

## Fix
Add `<meta name="viewport" content="width=device-width, initial-scale=1">` to the `<head>`.
