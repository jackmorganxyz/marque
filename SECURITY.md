# Security policy

Marque verifies message signatures, recipient binding, freshness and replay protection through caller-provided storage. Bugs in signature recovery, JSON canonicalization or these checks are security-relevant.

Use GitHub's private vulnerability reporting on this repository, or email **contact@jackmorgan.xyz**. Please do not open a public issue for anything exploitable.

The caller owns key custody, identity mapping, address trust, action permissions, input size limits and atomic replay storage. A valid signature proves key possession, not that the message is safe or authorised. See the [README](README.md#security-boundaries) for the caller contract.
