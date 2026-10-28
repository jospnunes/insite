severity: medium
title: The main thread is blocked for long (TBT {value})
---
Long JavaScript tasks blocked the page for {value} in total after the first paint ({profile}), above the 600 ms Lighthouse rates as poor. While blocked, the page does not respond to taps and clicks.

## Fix
Find the long tasks in the browser's Performance panel. Split or defer heavy scripts, remove unused JavaScript, and load third-party tags after the page is interactive.
