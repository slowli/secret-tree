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
//! # Crate features
//!
//! The crate is `no_std`-compatible. There is optional `std` support enabled via the `std` feature,
//! which is on by default.
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
//! | Seed for a [named child](SecretTree::child()) | `name.as_bytes()` (zero-padded) | `b"name\0\0...\0"` |
//! | Seed for an [indexed child](SecretTree::index()) | `LittleEndian(index)` | `b"index\0\0...\0"` |
//! | Seed for a [digest child](SecretTree::digest()) (1st iter) | `digest[..16]` | `b"digest0\0\0...\0"` |
//! | Seed for a digest child (2nd iter) | `digest[16..]` | `b"digest1\0\0...\0"` |
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
//! use rand::SeedableRng;
//! use rand_chacha::ChaChaRng;
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
//! In case of named and digest children, we utilize the entire salt section, while libsodium
//! only uses the first 8 bytes.
//!
//! For digest children, the derivation procedure is applied 2 times, taking the first 16 bytes
//! and the remaining 16 bytes of the digest respectively. The 32-byte key derived on the first
//! iteration is used as the master key input for the second iteration. Such a procedure
//! is necessary because Blake2b only supports 16-byte salts.
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

#![cfg_attr(not(feature = "std"), no_std)]
// Documentation settings
#![doc(html_root_url = "https://docs.rs/secret-tree/0.5.0")]
// Linter settings
#![warn(missing_docs, missing_debug_implementations)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions
)]

#[cfg(all(not(feature = "std"), test))]
extern crate std;

use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use secrecy::{zeroize::Zeroize, ExposeSecret, Secret};

use core::{
    array::TryFromSliceError,
    convert::TryInto,
    fmt,
    str::{self, FromStr},
};

mod byte_slice;
mod kdf;

pub use crate::{byte_slice::AsByteSliceMut, kdf::SEED_LEN};

use crate::kdf::{derive_key, try_derive_key, Index, CONTEXT_LEN, SALT_LEN};

/// Maximum byte length of a [`Name`] (16).
pub const MAX_NAME_LEN: usize = SALT_LEN;

/// Alias for a [`Secret`] array that contains seed bytes.
pub type Seed = Secret<[u8; SEED_LEN]>;

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
/// use secret_tree::{SecretTree, Name};
/// use rand::{Rng, thread_rng};
/// use secrecy::{ExposeSecret, Secret};
///
/// let tree = SecretTree::new(&mut thread_rng());
/// // Don't forget to securely store secrets! Here, we wrap them
/// // in a container that automatically zeroes the secret on drop.
/// let first_secret: Secret<[u8; 32]> = tree
///     .child(Name::new("first"))
///     .create_secret();
///
/// // We can derive hierarchical secrets. The secrets below
/// // follow logical paths `sequence/0`, `sequence/1`, .., `sequence/4`
/// // relative to the `tree`.
/// let child_store = tree.child(Name::new("sequence"));
/// let more_secrets: Vec<Secret<[u64; 4]>> = (0..5)
///     .map(|i| Secret::new(child_store.index(i).rng().gen()))
///     .collect();
///
/// // The tree is compactly stored as a single 32-byte seed.
/// let seed = tree.seed().to_owned();
/// drop(tree);
///
/// // If we restore the tree from the seed, we can restore all derived secrets.
/// let tree = SecretTree::from_seed(seed);
/// let restored_secret: Secret<[u8; 32]> = tree
///     .child(Name::new("first"))
///     .create_secret();
/// assert_eq!(
///     first_secret.expose_secret(),
///     restored_secret.expose_secret()
/// );
/// ```
#[derive(Debug)]
#[must_use = "A tree should generate a secret or child tree"]
pub struct SecretTree {
    seed: Seed,
}

impl SecretTree {
    const FILL_BYTES_CONTEXT: [u8; CONTEXT_LEN] = *b"bytes\0\0\0";
    const RNG_CONTEXT: [u8; CONTEXT_LEN] = *b"rng\0\0\0\0\0";
    const NAME_CONTEXT: [u8; CONTEXT_LEN] = *b"name\0\0\0\0";
    const INDEX_CONTEXT: [u8; CONTEXT_LEN] = *b"index\0\0\0";
    const DIGEST_START_CONTEXT: [u8; CONTEXT_LEN] = *b"digest0\0";
    const DIGEST_END_CONTEXT: [u8; CONTEXT_LEN] = *b"digest1\0";

    /// Generates a tree by sampling its seed from the supplied RNG.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        Self {
            seed: Secret::new(seed),
        }
    }

    /// Creates a tree from the seed.
    pub fn from_seed(seed: Seed) -> Self {
        Self { seed }
    }

    /// Restores a tree from the seed specified as a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` has an invalid length (not [`SEED_LEN`]).
    pub fn from_slice(bytes: &[u8]) -> Result<Self, TryFromSliceError> {
        let seed: [u8; 32] = bytes.try_into()?;
        Ok(Self {
            seed: Secret::new(seed),
        })
    }

    /// Returns the tree seed.
    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    /// Converts this tree into a cryptographically secure pseudo-random number generator
    /// (CSPRNG). This RNG can then be used to reproducibly create secrets (e.g., secret keys).
    ///
    /// # Security
    ///
    /// [`Self::fill()`] should be preferred if the secret allows it. While using a CSPRNG
    /// to generate secrets is theoretically sound, it introduces a new entity that
    /// may leak information.
    /// `fill()` is especially useful if the filled buffer implements zeroing on drop;
    /// the state of a CSPRNG generator returned by `rng()` **is not** zeroed on drop and thus
    /// creates a potential attack vector. (However theoretical it may be; `ChaChaRng`
    /// has a notably small state size - ~160 bytes, so it may be better localized
    /// and have lower risk to be accessed by the adversary than other CSPRNG implementations.)
    pub fn rng(self) -> ChaChaRng {
        let mut seed = <ChaChaRng as SeedableRng>::Seed::default();
        derive_key(
            seed.as_mut(),
            Index::None,
            Self::RNG_CONTEXT,
            self.seed.expose_secret(),
        );
        ChaChaRng::from_seed(seed)
    }

    /// Tries to fill the specified buffer with a key derived from the seed of this tree.
    ///
    /// # Errors
    ///
    /// Errors if the buffer does not have length `16..=64` bytes. Use [`Self::rng()`]
    /// if the buffer size may be outside these bounds, or if the secret must be derived
    /// in a more complex way.
    pub fn try_fill<T: AsByteSliceMut + ?Sized>(self, dest: &mut T) -> Result<(), FillError> {
        try_derive_key(
            dest.as_byte_slice_mut(),
            Index::None,
            Self::FILL_BYTES_CONTEXT,
            self.seed.expose_secret(),
        )?;
        dest.convert_to_le();
        Ok(())
    }

    /// Fills the specified buffer with a key derived from the seed of this tree.
    ///
    /// # Panics
    ///
    /// Panics in the same cases when [`Self::try_fill()`] returns an error.
    pub fn fill<T: AsByteSliceMut + ?Sized>(self, dest: &mut T) {
        self.try_fill(dest).unwrap_or_else(|err| {
            panic!("Failed filling a buffer from `SecretTree`: {err}");
        });
    }

    /// Tries to create a secret by instantiating a buffer and filling it with a key derived from
    /// the seed of this tree. Essentially, this is a more high-level wrapper around
    /// [`Self::try_fill()`].
    ///
    /// # Errors
    ///
    /// Returns an error if `T` does not have length `16..=64` bytes. Use [`Self::rng()`]
    /// if the buffer size may be outside these bounds, or if the secret must be derived
    /// in a more complex way.
    pub fn try_create_secret<T>(self) -> Result<Secret<T>, FillError>
    where
        T: AsByteSliceMut + Default + Zeroize,
    {
        let mut secret_value = T::default();
        self.try_fill(&mut secret_value)?;
        Ok(Secret::new(secret_value))
    }

    /// Creates a secret by instantiating a buffer and filling it with a key derived from
    /// the seed of this tree.
    ///
    /// # Panics
    ///
    /// Panics in the same cases when [`Self::try_create_secret()`] returns an error.
    pub fn create_secret<T>(self) -> Secret<T>
    where
        T: AsByteSliceMut + Default + Zeroize,
    {
        self.try_create_secret().unwrap_or_else(|err| {
            panic!("Failed creating a secret from `SecretTree`: {err}");
        })
    }

    /// Produces a child with the specified string identifier.
    pub fn child(&self, name: Name) -> Self {
        let mut child_seed = [0_u8; 32];
        derive_key(
            &mut child_seed,
            Index::Bytes(name.0),
            Self::NAME_CONTEXT,
            self.seed.expose_secret(),
        );
        Self::from_seed(Secret::new(child_seed))
    }

    /// Produces a child with the specified integer index.
    pub fn index(&self, index: u64) -> Self {
        let mut child_seed = [0_u8; 32];
        derive_key(
            &mut child_seed,
            Index::Number(index),
            Self::INDEX_CONTEXT,
            self.seed.expose_secret(),
        );
        Self::from_seed(Secret::new(child_seed))
    }

    /// Produces a child with the specified 32-byte digest (e.g., an output of SHA-256,
    /// SHA3-256 or Keccak256 hash functions).
    ///
    /// This method can be used for arbitrarily-sized keys by first digesting them
    /// with a collision-resistant hash function.
    pub fn digest(&self, digest: &[u8; 32]) -> Self {
        let mut first_half_of_digest = [0_u8; SALT_LEN];
        first_half_of_digest.copy_from_slice(&digest[0..SALT_LEN]);
        let mut second_half_of_digest = [0_u8; SALT_LEN];
        second_half_of_digest.copy_from_slice(&digest[SALT_LEN..]);

        let mut intermediate_seed = [0_u8; 32];
        derive_key(
            &mut intermediate_seed,
            Index::Bytes(first_half_of_digest),
            Self::DIGEST_START_CONTEXT,
            self.seed.expose_secret(),
        );
        let intermediate_seed = Secret::new(intermediate_seed);

        let mut child_seed = [0_u8; 32];
        derive_key(
            &mut child_seed,
            Index::Bytes(second_half_of_digest),
            Self::DIGEST_END_CONTEXT,
            intermediate_seed.expose_secret(),
        );
        Self::from_seed(Secret::new(child_seed))
    }
}

/// Errors that can occur when calling [`SecretTree::try_fill()`].
#[derive(Debug)]
#[non_exhaustive]
pub enum FillError {
    /// The supplied buffer is too small to be filled.
    BufferTooSmall {
        /// Byte size of the supplied buffer.
        size: usize,
        /// Minimum byte size for supported buffers.
        min_supported_size: usize,
    },
    /// The supplied buffer is too large to be filled.
    BufferTooLarge {
        /// Byte size of the supplied buffer.
        size: usize,
        /// Maximum byte size for supported buffers.
        max_supported_size: usize,
    },
}

impl fmt::Display for FillError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall {
                size,
                min_supported_size,
            } => {
                write!(
                    formatter,
                    "supplied buffer ({size} bytes) is too small to be filled; \
                     min supported size is {min_supported_size} bytes"
                )
            }

            Self::BufferTooLarge {
                size,
                max_supported_size,
            } => {
                write!(
                    formatter,
                    "supplied buffer ({size} bytes) is too large to be filled; \
                     max supported size is {max_supported_size} bytes"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FillError {}

/// Name of a child [`SecretTree`].
///
/// Used in [`SecretTree::child()`]; see its documentation for more context.
///
/// An original `str` can be extracted from `Name` using [`AsRef`] / [`Display`](fmt::Display)
/// implementations:
///
/// ```
/// # use secret_tree::Name;
/// const NAME: Name = Name::new("test_name");
/// assert_eq!(NAME.as_ref(), "test_name");
/// assert_eq!(NAME.to_string(), "test_name");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Name([u8; SALT_LEN]);

impl Name {
    /// Creates a new `Name`.
    ///
    /// The supplied string must be no more than [`MAX_NAME_LEN`] bytes in length
    /// and must not contain null chars `'\0'`.
    ///
    /// This is a constant method, which perform all relevant checks during compilation in
    /// a constant context:
    ///
    /// ```
    /// # use secret_tree::Name;
    /// const NAME: Name = Name::new("some_name");
    /// ```
    ///
    /// For example, this won't compile since the name is too long (17 chars):
    ///
    /// ```compile_fail
    /// # use secret_tree::Name;
    /// const OVERLY_LONG_NAME: Name = Name::new("Overly long name!");
    /// ```
    ///
    /// ...And this won't compile because the name contains a `\0` char:
    ///
    /// ```compile_fail
    /// # use secret_tree::Name;
    /// const NAME_WITH_ZERO_CHARS: Name = Name::new("12\03");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `name` is overly long or contains null chars.
    /// Use the [`FromStr`] implementation for a fallible / non-panicking alternative.
    pub const fn new(name: &str) -> Self {
        let bytes = name.as_bytes();
        assert!(
            bytes.len() <= SALT_LEN,
            "name is too long (should be <=16 bytes)"
        );

        let mut i = 0;
        let mut buffer = [0_u8; SALT_LEN];
        while i < name.len() {
            assert!(bytes[i] != 0, "name contains a null char");
            buffer[i] = bytes[i];
            i += 1;
        }
        Name(buffer)
    }
}

impl FromStr for Name {
    type Err = NameError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let byte_len = name.as_bytes().len();
        if byte_len > SALT_LEN {
            return Err(NameError::TooLong);
        }
        if name.as_bytes().contains(&0) {
            return Err(NameError::NullChar);
        }

        let mut bytes = [0; SALT_LEN];
        bytes[..byte_len].copy_from_slice(name.as_bytes());
        Ok(Self(bytes))
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        let str_len = self.0.iter().position(|&ch| ch == 0).unwrap_or(SALT_LEN);
        unsafe {
            // SAFETY: safe by construction; we only ever create `Name`s from valid UTF-8 sequences.
            str::from_utf8_unchecked(&self.0[..str_len])
        }
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Name").field(&self.as_ref()).finish()
    }
}

impl fmt::Display for Name {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_ref())
    }
}

/// Errors that can occur when converting a `&str` into [`Name`].
#[derive(Debug)]
#[non_exhaustive]
pub enum NameError {
    /// The string is too long. `Name`s should be 0..=16 bytes.
    TooLong,
    /// Name contains a null char `\0`.
    NullChar,
}

impl fmt::Display for NameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLong => "name is too long, 0..=16 bytes expected",
            Self::NullChar => "name contains a null char",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NameError {}

#[cfg(doctest)]
doc_comment::doctest!("../README.md");

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{Rng, SeedableRng};

    #[test]
    fn children_with_same_bytes_in_key() {
        let name = Name::new("A");
        let index = u64::from(b'A');
        let tree = SecretTree::new(&mut ChaChaRng::seed_from_u64(123));
        let named_child = tree.child(name);
        let indexed_child = tree.index(index);
        assert_ne!(
            named_child.seed.expose_secret(),
            indexed_child.seed.expose_secret()
        );
    }

    #[test]
    fn fill_and_rng_result_in_different_data() {
        let tree = SecretTree::new(&mut ChaChaRng::seed_from_u64(123));
        let mut buffer = [0_u64; 8];
        tree.child(Name::new("foo")).fill(&mut buffer);
        let other_buffer: [u64; 8] = tree.child(Name::new("foo")).rng().gen();
        assert_ne!(buffer, other_buffer);
    }

    #[test]
    #[should_panic(expected = "supplied buffer (12 bytes) is too small to be filled")]
    fn filling_undersized_key() {
        let tree = SecretTree::new(&mut ChaChaRng::seed_from_u64(123));
        let mut buffer = [0_u8; 12];
        tree.fill(&mut buffer);
    }

    #[test]
    fn error_filling_undersized_key() {
        let tree = SecretTree::new(&mut ChaChaRng::seed_from_u64(123));
        let mut buffer = [0_u8; 12];
        let err = tree.try_fill(&mut buffer).unwrap_err();

        assert!(matches!(
            err,
            FillError::BufferTooSmall {
                size: 12,
                min_supported_size: 16,
            }
        ));
        let err = err.to_string();
        assert!(
            err.contains("supplied buffer (12 bytes) is too small to be filled"),
            "{err}"
        );
        assert!(err.contains("min supported size is 16 bytes"), "{err}");
    }

    #[test]
    #[should_panic(expected = "supplied buffer (80 bytes) is too large to be filled")]
    fn filling_oversized_key() {
        let tree = SecretTree::new(&mut ChaChaRng::seed_from_u64(123));
        let mut buffer = [0_u64; 10];
        tree.fill(&mut buffer);
    }

    #[test]
    fn error_filling_oversized_key() {
        let tree = SecretTree::new(&mut ChaChaRng::seed_from_u64(123));
        let mut buffer = [0_u64; 10];
        let err = tree.try_fill(&mut buffer).unwrap_err();

        assert!(matches!(
            err,
            FillError::BufferTooLarge {
                size: 80,
                max_supported_size: 64,
            }
        ));
        let err = err.to_string();
        assert!(
            err.contains("supplied buffer (80 bytes) is too large to be filled"),
            "{err}"
        );
        assert!(err.contains("max supported size is 64 bytes"), "{err}");
    }

    #[test]
    fn filling_acceptable_buffers() {
        let mut u8_buffer = [0_u8; 40];
        let mut i32_buffer = [0_i32; 16];
        let mut u128_buffer = [0_u128];
        // Using `Vec` to store secrets is usually a bad idea because of its placement in heap;
        // here it is used just to test capabilities.
        let mut vec_buffer = [0_u16; 24];

        let tree = SecretTree::new(&mut ChaChaRng::seed_from_u64(123));
        tree.child(Name::new("u8")).fill(&mut u8_buffer[..]);
        tree.child(Name::new("i32")).fill(&mut i32_buffer);
        tree.child(Name::new("u128")).fill(&mut u128_buffer);
        tree.child(Name::new("vec")).fill(&mut vec_buffer[..]);
    }

    #[test]
    #[should_panic(expected = "name contains a null char")]
    fn name_with_null_chars_cannot_be_created() {
        let _name = Name::new("some\0name");
    }

    #[test]
    fn name_with_null_chars_error() {
        let err = Name::from_str("some\0name").unwrap_err();
        assert!(matches!(err, NameError::NullChar));
    }

    #[test]
    #[should_panic(expected = "name is too long")]
    fn overly_long_name_cannot_be_created() {
        let _name = Name::new("Overly long name?");
    }

    #[test]
    fn overly_long_name_error() {
        let err = Name::from_str("Overly long name?").unwrap_err();
        assert!(matches!(err, NameError::TooLong));
    }

    #[test]
    fn name_new_pads_input_with_zeros() {
        const SAMPLES: &[(Name, &[u8; MAX_NAME_LEN])] = &[
            (Name::new(""), b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
            (Name::new("O"), b"O\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
            (Name::new("Ov"), b"Ov\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
            (Name::new("Ove"), b"Ove\0\0\0\0\0\0\0\0\0\0\0\0\0"),
            (Name::new("Over"), b"Over\0\0\0\0\0\0\0\0\0\0\0\0"),
            (Name::new("Overl"), b"Overl\0\0\0\0\0\0\0\0\0\0\0"),
            (Name::new("Overly"), b"Overly\0\0\0\0\0\0\0\0\0\0"),
            (Name::new("Overly "), b"Overly \0\0\0\0\0\0\0\0\0"),
            (Name::new("Overly l"), b"Overly l\0\0\0\0\0\0\0\0"),
            (Name::new("Overly lo"), b"Overly lo\0\0\0\0\0\0\0"),
            (Name::new("Overly lon"), b"Overly lon\0\0\0\0\0\0"),
            (Name::new("Overly long"), b"Overly long\0\0\0\0\0"),
            (Name::new("Overly long "), b"Overly long \0\0\0\0"),
            (Name::new("Overly long n"), b"Overly long n\0\0\0"),
            (Name::new("Overly long na"), b"Overly long na\0\0"),
            (Name::new("Overly long nam"), b"Overly long nam\0"),
            (Name::new("Overly long name"), b"Overly long name"),
        ];

        for (i, &(name, expected_bytes)) in SAMPLES.iter().enumerate() {
            assert_eq!(name.0, *expected_bytes);
            let expected_str = &"Overly long name"[..i];
            assert_eq!(name.to_string(), expected_str);
            assert_eq!(name.as_ref(), expected_str);
            assert!(format!("{name:?}").contains(expected_str));
        }
    }

    #[test]
    fn buffers_with_different_size_should_be_unrelated() {
        let tree = SecretTree::new(&mut ChaChaRng::seed_from_u64(123));
        let mut bytes = [0_u8; 16];
        tree.child(Name::new("foo")).fill(&mut bytes);
        let mut other_bytes = [0_u8; 32];
        tree.child(Name::new("foo")).fill(&mut other_bytes);
        assert!(bytes.iter().zip(&other_bytes).any(|(&x, &y)| x != y));
    }

    #[test]
    fn digest_derivation_depends_on_all_bits_of_digest() {
        const RNG_SEED: u64 = 12345;

        let mut rng = ChaChaRng::seed_from_u64(RNG_SEED);
        let tree = SecretTree::new(&mut rng);
        let mut digest = [0_u8; 32];
        rng.fill_bytes(&mut digest);

        let child_seed = tree.digest(&digest).seed;
        for byte_idx in 0..32 {
            for bit_idx in 0..8 {
                let mut mutated_digest = digest;
                mutated_digest[byte_idx] ^= 1 << bit_idx;
                assert_ne!(mutated_digest, digest);

                let mutated_child_seed = tree.digest(&mutated_digest).seed;
                assert_ne!(
                    child_seed.expose_secret(),
                    mutated_child_seed.expose_secret()
                );
            }
        }
    }
}
