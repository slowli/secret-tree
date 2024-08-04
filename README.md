# Hierarchical secret derivation with Blake2b

[![Build Status](https://github.com/slowli/secret-tree/workflows/CI/badge.svg?branch=master)](https://github.com/slowli/secret-tree/actions)
[![License: Apache-2.0](https://img.shields.io/github/license/slowli/secret-tree.svg)](https://github.com/slowli/secret-tree/blob/master/LICENSE)
![rust 1.70+ required](https://img.shields.io/badge/rust-1.70+-blue.svg)
![no_std supported](https://img.shields.io/badge/no__std-tested-green.svg)

**Documentation:** [![Docs.rs](https://docs.rs/secret-tree/badge.svg)](https://docs.rs/secret-tree/)
[![crate docs (master)](https://img.shields.io/badge/master-yellow.svg?label=docs)](https://slowli.github.io/secret-tree/secret_tree/) 

`secret-tree` allows deriving multiple secrets from a single seed value
in a secure and forward-compatible way.
The derivation procedure is hierarchical: a seed can be used to derive child seeds,
which have the same functionality as the original.

## Features

- **Compact:** the seed takes 32 bytes regardless of the number and size
  of derived secrets.
- **Forward-compatible:** it's possible to add new and/or remove
  existing derived secrets without regenerating the seed
  or littering the codebase.
- **Versatile:** the crate provides API to derive a virtually unbounded
  number of secrets (via indexing) and secrets with complex internal structure
  (thanks to a cryptographically secure pseudo-random number generator
  that can be derived from the seed).

## Usage

Add this to your `Crate.toml`:

```toml
[dependencies]
secret-tree = "0.5.0"
```

Basic usage:

```rust
use secret_tree::{SecretTree, Name};
use rand::{Rng, thread_rng};
use secrecy::Secret;

let tree = SecretTree::new(&mut thread_rng());
// Create 2 children from the tree: an ordinary secret
// and a CSPRNG with a fixed seed.
let secret: Secret<[u8; 32]> = tree
    .child(Name::new("secret"))
    .create_secret();
let other_secret_rng = tree
    .child(Name::new("other_secret"))
    .rng();
```

See crate documentation for more details how to use the crate.

## Implementation

Blake2b is used to derive secrets in a similar (and mostly compatible) way
it is used for key derivation in [libsodium]. Derived CSPRNGs are based
on the [ChaCha cipher], which has been extensively studied and has
much smaller state size that alternatives (~160 bytes vs several kilobytes),
limiting the threat of state leakage.

Crate documentation provides more implementation details.

## Contributing

All contributions are welcome! See [the contributing guide](CONTRIBUTING.md) to help
you get involved.

## License

Licensed under the [Apache-2.0 license](LICENSE).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `secret-tree` by you, as defined in the Apache-2.0 license,
shall be licensed as above, without any additional terms or conditions.

[libsodium]: https://download.libsodium.org/doc/key_derivation
[ChaCha cipher]: https://tools.ietf.org/html/rfc7539
