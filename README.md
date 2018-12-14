# Hierarchical secret derivation with Blake2b

`secret-tree` allows to derive multiple secrets from a single seed value in a secure and forward-compatible way.
The derivation procedure is hierarchical: a seed can be used to derive child seeds, which have the same functionality
as the original.

## Features

- **Compact:** the seed takes 32 bytes regardless of the number and the size of derived secrets.
- **Forward-compatible:** it's possible to add new and/or remove existing derived secrets without regenerating the seed
  or littering the codebase.
- **Versatile:** the crate provides API to derive a virtually unbounded number of secrets (via indexing) and
  secrets with complex internal structure (thanks to a cryptographically secure pseudo-random number generator
  that can be derived from the seed).

## Usage

See crate documentation for more details how to use the crate.

## Implementation

Blake2b is used to derive secrets in a similar (and mostly compatible) way it is used for key derivation
in [libsodium]. Derived CSPRNGs are based on the [ChaCha cipher], which has been extensively studied and has
much smaller state size that alternatives (~160 bytes vs several kilobytes), limiting the threat of state leakage.

Crate documentation provides more implementation details.

[libsodium]: https://download.libsodium.org/doc/key_derivation
[ChaCha cipher]: https://tools.ietf.org/html/rfc7539
