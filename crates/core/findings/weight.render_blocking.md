severity: low
title: Render-blocking scripts in the head ({count})
---
Scripts in the `<head>` ({count}) load without `async` or `defer`. The browser stops building the page until each one downloads and runs, which delays the first paint.

## Fix
Add `defer` to scripts that do not need to run before the page is shown (or `async` to independent ones), or move them to the end of the body.
