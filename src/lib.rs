// Copyright 2018 Alex Ostrovski
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Hierarchical secret derivation with Blake2b and random number generators.
//!
//! # How it works
//!
//! This crate provides [`SecretTree`] – a structure produced from a 32-byte seed that
//! may be converted into a secret key or a cryptographically secure
//! pseudo-random number generator (CSPRNG).
//! Besides that, an `SecretTree` can produce child trees, which are
//! identified by a string [`Name`] or an integer index. This enables creating
//! *hierarchies* of secrets (like `some_secret/0`, `some_secret/1` and `other_secret/foo/1/bar`),
//! which are ultimately derived from a single `SecretTree`. It’s enough to securely store
//! the seed of this root tree (e.g., in a passphrase-encrypted form) to recreate all secrets.
//!
//! The derived secrets cannot be linked; leakage of a derived secret does not compromise
//! sibling secrets or the parent `SecretTree`.
//!
//! # Implementation details
//!
//! `SecretTree` uses the [Blake2b] keyed hash function to derive the following kinds of data:
//!
//! - secret key
//! - CSPRNG seed (the RNG used is [`ChaChaRng`])
//! - seeds for child `SecretTree`s
//!
//! The procedure is similar to the use of Blake2b for key derivation in [libsodium]\:
//!
//! - Blake2b is used with a custom initialization block. The block has two
//!   customizable parameters of interest: *salt* and *personalization* (each is 16 bytes).
//!   See the table below for information how these two parameters are set for each type
//!   of derived data.
//! - The key is the seed of the `SecretTree` instance used for derivation.
//! - The message is an empty bit string.
//!
//! The length of derived data is 32 bytes in all cases.
//!
//! ## Salt and personalization
//!
//! | Data type | Salt | Personalization |
//! |:----------|:-----|:----------------|
//! | Secret key | `[0; 16]` | `b"bytes\0\0...\0"` |
//! | CSPRNG seed | `[0; 16]` | `b"rng\0\0...\0"` |
//! | Seed for a named child | `name.as_bytes()` (zero-padded) | `b"name\0\0...\0"` |
//! | Seed for an indexed child | `LittleEndian(index)` | `b"index\0\0...\0"` |
//!
//! Derivation of a secret key, CSPRNG seed and seeds for indexed children are
//! all fully compatible with libsodium.
//! libsodium uses the salt section in the Blake2b initialization block to store
//! the *index* of a child key, and the personalization section to store its *context*.
//!
//! For example, the CSPRNG seed can be computed as follows (if we translate libsodium API
//! from C to Rust):
//!
//! ```
//! # extern crate rand;
//! use rand::{ChaChaRng, SeedableRng};
//! # fn crypto_kdf_derive_from_key(_: &mut [u8], _: u64, _: &[u8; 8], _: &[u8; 32]) {}
//!
//! let parent_seed: [u8; 32] = // ...
//! #   [0; 32];
//! let mut rng_seed = [0; 32];
//! crypto_kdf_derive_from_key(
//!     &mut rng_seed,
//!     /* index */ 0,
//!     /* context */ b"rng\0\0\0\0\0",
//!     /* master_key */ &parent_seed,
//! );
//! let rng = ChaChaRng::from_seed(rng_seed);
//! ```
//!
//! In case of named children, we utilize the entire salt section, while libsodium
//! only uses the first 8 bytes.
//!
//! # Design motivations
//!
//! - We allow to derive RNGs besides keys in order to allow a richer variety of applications.
//!   RNGs can be used in more complex use cases than fixed-size byte arrays,
//!   e.g., when the length of the secret depends on previous RNG output, or RNG is used to sample
//!   a complex distribution.
//! - Derivation in general (instead of using a single `SeedableRng` to create all secrets)
//!   allows to add new secrets or remove old ones without worrying about compatibility.
//! - Child RNGs identified by an index can be used to derive secrets of the same type,
//!   the quantity of which is unbounded. As an example, they can be used to produce
//!   blinding factors for [Pedersen commitments] (e.g., in a privacy-focused cryptocurrency).
//! - Some steps are taken to make it difficult to use `SecretTree` incorrectly. For example,
//!   `rng()` and `fill()` methods consume the tree instance, which makes it harder to reuse
//!   the same RNG for multiple purposes (which is not intended).
//!
//! [libsodium]: https://download.libsodium.org/doc/key_derivation
//! [Blake2b]: https://tools.ietf.org/html/rfc7693
//! [Pedersen commitments]: https://en.wikipedia.org/wiki/Commitment_scheme
//! [`ChaChaRng`]: https://docs.rs/rand_chacha/0.1.0/rand_chacha/
//! [`SecretTree`]: struct.SecretTree.html
//! [`Name`]: struct.Name.html

#![deny(missing_docs, missing_debug_implementations)]

extern crate blake2_rfc;
extern crate byteorder;
extern crate clear_on_drop;
extern crate rand;

#[cfg(test)]
extern crate hex;

use clear_on_drop::ClearOnDrop;
use rand::{AsByteSliceMut, ChaChaRng, CryptoRng, RngCore, SeedableRng};

use std::fmt;

mod kdf;

pub use kdf::SEED_LEN;
use kdf::{derive_key, Index, CONTEXT_LEN, SALT_LEN};

/// Maximum byte length of a `Name` (16).
pub const MAX_NAME_LEN: usize = SALT_LEN;

/// Seeded structure that can be used to produce secrets and child `SecretTree`s.
///
/// # Usage
///
/// During the program lifecycle, a root `SecretTree` should be restored from
/// a secure persistent form (e.g., a passphrase-encrypted file) and then used to derive
/// child trees and secrets. On the first use, the root should be initialized from a CSPRNG, such
/// as `rand::thread_rng()`. The tree is not needed during the program execution and can
/// be safely dropped after deriving necessary secrets (which zeroes out the tree seed).
///
/// It is possible to modify the derivation hierarchy over the course of program evolution
/// by adding new secrets or abandoning the existing ones.
/// However, the purpose of any given tree path should be fixed; that is, if some version
/// of a program used path `foo/bar` to derive an Ed25519 keypair, a newer version
/// shouldn’t use `foo/bar` to derive an AES-128 key. Violating this rule may lead
/// to leaking the secret.
///
/// # Examples
///
/// ```
/// # extern crate rand;
/// # extern crate secret_tree;
/// use secret_tree::{SecretTree, Name};
/// use rand::{Rng, thread_rng};
///
/// let tree = SecretTree::new(&mut thread_rng());
/// let mut first_secret = [0_u8; 32];
/// tree.child(Name::new("first")).fill(&mut first_secret);
///
/// // We can derive hierarchical secrets. The secrets below
/// // follow logical paths `sequence/0`, `sequence/1`, .., `sequence/4`
/// // relative to the `tree`.
/// let child_store = tree.child(Name::new("sequence"));
/// let more_secrets: Vec<[u64; 4]> = (0..5)
///     .map(|i| child_store.index(i).rng().gen())
///     .collect();
///
/// // The tree is compactly stored as a single 32-byte seed.
/// let seed = *tree.seed();
/// drop(tree);
///
/// // If we restore the tree from the seed, we can restore all derived secrets.
/// let tree = SecretTree::from_seed(&seed).unwrap();
/// let mut restored_secret = [0_u8; 32];
/// tree.child(Name::new("first")).fill(&mut restored_secret);
/// assert_eq!(first_secret, restored_secret);
/// ```
pub struct SecretTree {
    seed: [u8; SEED_LEN],
}

impl fmt::Debug for SecretTree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SecretTree").field(&"_").finish()
    }
}

impl SecretTree {
    const FILL_BYTES_CONTEXT: [u8; CONTEXT_LEN] = *b"bytes\0\0\0";
    const RNG_CONTEXT: [u8; CONTEXT_LEN] = *b"rng\0\0\0\0\0";
    const NAME_CONTEXT: [u8; CONTEXT_LEN] = *b"name\0\0\0\0";
    const INDEX_CONTEXT: [u8; CONTEXT_LEN] = *b"index\0\0\0";

    /// Generates a tree by sampling its seed from the supplied RNG.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut secret_tree = SecretTree { seed: [0; 32] };
        rng.fill_bytes(&mut secret_tree.seed);
        secret_tree
    }

    /// Restores a tree from the seed.
    pub fn from_seed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SEED_LEN {
            return None;
        }
        let mut secret_tree = SecretTree { seed: [0; 32] };
        secret_tree.seed.copy_from_slice(bytes);
        Some(secret_tree)
    }

    /// Returns the tree seed.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// Converts this tree into a cryptographically secure pseudo-random number generator
    /// (CSPRNG). This RNG can then be used to reproducibly create secrets (e.g., secret keys).
    ///
    /// # Security
    ///
    /// [`fill()`]  should be preferred if the secret allows it. While using a CSPRNG to generate
    /// secrets is theoretically sound, it introduces a new entity that may leak information.
    /// `fill()` is especially useful if the filled buffer implements zeroing on drop;
    /// the state of a CSPRNG generator returned by `rng()` **is not** zeroed on drop and thus
    /// creates a potential attack vector. (However theoretical it may be; `ChaChaRng`
    /// has a notably small state size - ~160 bytes, so it may be better localized
    /// and have lower risk to be accessed by the adversary than other CSPRNG implementations.)
    ///
    /// [`fill()`]: #method.fill
    pub fn rng(self) -> ChaChaRng {
        let mut seed = <ChaChaRng as SeedableRng>::Seed::default();
        derive_key(seed.as_mut(), Index::None, Self::RNG_CONTEXT, &self.seed);
        ChaChaRng::from_seed(seed)
    }

    /// Fills the specified buffer with a key derived from the seed of this tree.
    ///
    /// The buffer must be equivalent to `16..=64` bytes; the method panics otherwise.
    /// Use [`rng()`] if the buffer size may be outside these bounds,
    /// or if the secret must be derived in a more complex way.
    ///
    /// [`rng()`]: #method.rng
    pub fn fill<T: AsByteSliceMut + ?Sized>(self, dest: &mut T) {
        derive_key(
            dest.as_byte_slice_mut(),
            Index::None,
            Self::FILL_BYTES_CONTEXT,
            &self.seed,
        );
        dest.to_le();
    }

    /// Produces a child with the specified string identifier.
    pub fn child(&self, name: Name) -> Self {
        let mut secret_tree = SecretTree { seed: [0; 32] };
        derive_key(
            &mut secret_tree.seed,
            Index::Bytes(name.0),
            Self::NAME_CONTEXT,
            &self.seed,
        );
        secret_tree
    }

    /// Produces a child with the specified integer index.
    pub fn index(&self, index: u64) -> Self {
        let mut secret_tree = SecretTree { seed: [0; 32] };
        derive_key(
            &mut secret_tree.seed,
            Index::Number(index),
            Self::INDEX_CONTEXT,
            &self.seed,
        );
        secret_tree
    }
}

impl Drop for SecretTree {
    fn drop(&mut self) {
        let handle = ClearOnDrop::new(&mut self.seed);
        drop(handle);
    }
}

/// Name of a `SecretTree`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name([u8; SALT_LEN]);

impl Name {
    /// Creates a new `Name`.
    ///
    /// The supplied string should be no more than [`MAX_NAME_LEN`] bytes in length
    /// and should not contain zero bytes.
    ///
    /// [`MAX_NAME_LEN`]: constant.MAX_NAME_LEN.html
    pub fn new(name: &str) -> Self {
        let byte_len = name.as_bytes().len();
        assert!(byte_len <= SALT_LEN, "name too long, 0..=16 bytes expected");
        assert!(!name.as_bytes().contains(&0), "string contains null chars");

        let mut bytes = [0; SALT_LEN];
        bytes[..byte_len].copy_from_slice(name.as_bytes());
        Name(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn children_with_same_bytes_in_key() {
        let name = Name::new("A");
        let index = 0x41;
        let tree = SecretTree::new(&mut thread_rng());
        let named_child = tree.child(name);
        let indexed_child = tree.index(index);
        assert_ne!(named_child.seed, indexed_child.seed);
    }

    #[test]
    fn fill_and_rng_result_in_different_data() {
        let tree = SecretTree::new(&mut thread_rng());
        let mut buffer = [0_u64; 8];
        tree.child(Name::new("foo")).fill(&mut buffer);
        let other_buffer: [u64; 8] = tree.child(Name::new("foo")).rng().gen();
        assert_ne!(buffer, other_buffer);
    }

    #[test]
    #[should_panic(expected = "invalid output length")]
    fn filling_undersized_key() {
        let tree = SecretTree::new(&mut thread_rng());
        let mut buffer = [0_u8; 12];
        tree.fill(&mut buffer);
    }

    #[test]
    #[should_panic(expected = "invalid output length")]
    fn filling_oversized_key() {
        let tree = SecretTree::new(&mut thread_rng());
        let mut buffer = [0_u64; 10];
        tree.fill(&mut buffer);
    }

    #[test]
    fn filling_acceptable_buffers() {
        let mut u8_buffer = [0_u8; 40];
        let mut i32_buffer = [0_i32; 16];
        let mut u128_buffer = [0_u128];
        // Using `Vec` to store secrets is usually a bad idea because of its placement in heap;
        // here it is used just to test capabilities.
        let mut vec_buffer: Vec<u16> = vec![0; 24];

        let tree = SecretTree::new(&mut thread_rng());
        tree.child(Name::new("u8")).fill(&mut u8_buffer[..]);
        tree.child(Name::new("i32")).fill(&mut i32_buffer);
        tree.child(Name::new("u128")).fill(&mut u128_buffer);
        tree.child(Name::new("vec")).fill(&mut vec_buffer[..]);
    }

    #[test]
    #[should_panic(expected = "string contains null chars")]
    fn name_with_null_chars_cannot_be_created() {
        let tree = SecretTree::new(&mut thread_rng());
        let name = Name::new("some\0name");
        let mut bytes = [0_u8; 32];
        tree.child(name).fill(&mut bytes);
    }
}
