# Security policy

Marque is a signing/verification library — treat any bug in `verify()`, `canon()`, or the SSRF guard as potentially security-relevant.

## Reporting

Use GitHub's private vulnerability reporting on this repo, or email **contact@jackmorgan.xyz**. Please don't open a public issue for anything exploitable.

## Scope

The threat model, hard caller requirements, and accepted residual risks (stolen key before rotation, subdomain takeover, TLS/CA compromise, DNS rebinding on the key fetch) are documented in the [README](README.md)'s "Security — read before shipping" section. Reports that reduce to a documented residual are still welcome, but may be closed as by-design.
