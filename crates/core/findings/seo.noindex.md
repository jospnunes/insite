severity: high
title: Page asks search engines not to index it
---
The page says `noindex` ({source}), so Google and other search engines drop it from results. Correct on staging or private pages; a serious problem if this is a public page.

## Fix
Remove `noindex` from the robots meta tag or the `X-Robots-Tag` header on pages that should appear in search. CMS plugins and "discourage search engines" settings often add it.
