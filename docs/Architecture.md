# Security.Nonce.Openssl

`PiSubmarine.Security.Nonce.Openssl` implements
`Security.Nonce.Api::IProvider` using a random nonce prefix from OpenSSL and a
monotonic counter suffix.

## Responsibility

This module owns:

- one random prefix per provider instance
- big-endian counter formatting
- nonce exhaustion detection

It does not own:

- AEAD primitives
- key management
- packet framing
