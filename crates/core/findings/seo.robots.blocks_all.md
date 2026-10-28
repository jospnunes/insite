severity: high
title: robots.txt blocks the whole site
---
{url} tells every crawler (`User-agent: *`) not to crawl anything (`Disallow: /`). Search engines will not crawl new or updated pages.

## Fix
Unless the site is meant to stay out of search, replace `Disallow: /` with rules for only the paths that should not be crawled.
