severity: high
title: TLS configuration rejected modern clients
---
{host} refused the TLS handshake with current protocol versions and cipher suites. It probably only accepts TLS 1.0/1.1 or legacy cipher suites, which current browsers no longer offer.

## Fix
Enable TLS 1.2 and 1.3 with modern AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) and ECDHE key exchange. Mozilla's SSL Configuration Generator gives ready-made settings for each server.
