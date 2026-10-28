severity: medium
title: Slow Largest Contentful Paint ({value})
---
The largest element of the page took {value} to appear ({profile}), above the 4 s that Core Web Vitals rate as poor. This is the moment visitors perceive the page as loaded, and Google uses it in search ranking.

## Fix
Find the LCP element (usually the hero image or headline). Serve it early: preload the image, avoid lazy-loading it, compress it, and cut render-blocking CSS and scripts before it.
