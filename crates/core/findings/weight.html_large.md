severity: low
title: Large HTML document ({size})
---
The HTML alone is {size}. Large documents take longer to download and parse, and often carry inlined data or markup that could be loaded later.

## Fix
Look for inlined JSON state, base64 images or repeated markup that can move to separate, cacheable files or load on demand.
