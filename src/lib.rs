//! Hierarchical key derivation using Blake2b hash function.

#![deny(missing_docs, missing_debug_implementations)]

extern crate blake2_rfc;
extern crate byteorder;
extern crate clear_on_drop;
extern crate rand_chacha;
extern crate rand_core;

#[cfg(test)]
extern crate hex;
#[cfg(test)]
extern crate rand;

use clear_on_drop::ClearOnDrop;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use std::fmt;

mod kdf;

pub use kdf::KEY_LEN;
use kdf::{derive_key, Index, CONTEXT_LEN, SALT_LEN};

/// Maximum byte length of a `Name`.
pub const MAX_NAME_LEN: usize = SALT_LEN;

/// RNG tree that can be used to produce secrets and child `RngTree`s.
///
/// # Examples
///
/// ```
/// # extern crate rand;
/// # extern crate rng_tree;
/// use rng_tree::{RngTree, Name};
/// use rand::{Rng, thread_rng};
///
/// let tree = RngTree::new(&mut thread_rng());
/// let first_secret: [u8; 32] = tree.child(Name::new("first")).rng().gen();
///
/// // We can derive hierarchical secrets. The secret below
/// // follow logical paths `sequence/0`, `sequence/1`, .., `sequence/4`
/// // relative to the `tree`.
/// let child_store = tree.child(Name::new("sequence"));
/// let more_secrets: Vec<[u64; 4]> = (0..5)
///     .map(|i| child_store.index(i).rng().gen())
///     .collect();
///
/// // The restore is compactly serialized as a single seed.
/// let seed = *tree.seed();
/// drop(tree);
///
/// // If we restore the store from the seed, we can restore all derived secrets.
/// let tree = RngTree::from_seed(seed);
/// let restored_secret: [u8; 32] = tree.child(Name::new("first")).rng().gen();
/// assert_eq!(first_secret, restored_secret);
/// ```
#[derive(Default)]
pub struct RngTree {
    master_key: [u8; KEY_LEN],
}

impl fmt::Debug for RngTree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("RngTree").field(&"_").finish()
    }
}

impl RngTree {
    const RNG_CONTEXT: &'static [u8; CONTEXT_LEN] = b"rng\0\0\0\0\0";
    const NAME_CONTEXT: &'static [u8; CONTEXT_LEN] = b"name\0\0\0\0";
    const INDEX_CONTEXT: &'static [u8; CONTEXT_LEN] = b"index\0\0\0";

    /// Generates an RNG tree by reading its seed from the supplied RNG.
    pub fn new<R: RngCore + CryptoRng>(csrng: &mut R) -> Self {
        let mut rng_tree = RngTree::default();
        csrng.fill_bytes(rng_tree.seed_mut());
        rng_tree
    }

    /// Restores a tree from the seed.
    pub fn from_seed(bytes: [u8; KEY_LEN]) -> Self {
        RngTree { master_key: bytes }
    }

    /// Returns the tree seed.
    pub fn seed(&self) -> &[u8; KEY_LEN] {
        &self.master_key
    }

    /// Returns a mutable reference to the tree seed.
    /// This is useful when restoring the seed from the external source.
    pub fn seed_mut(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.master_key
    }

    /// Converts this tree into a cryptographically secure pseudo-random number generator
    /// (CSPRNG). This RNG can then be used to reproducibly create secrets (e.g., secret keys).
    pub fn rng(self) -> ChaChaRng {
        let mut seed = <ChaChaRng as SeedableRng>::Seed::default();
        derive_key(
            seed.as_mut(),
            &self.master_key,
            Self::RNG_CONTEXT,
            Index::None,
        );
        ChaChaRng::from_seed(seed)
    }

    /// Produces a child with the specified identifier.
    pub fn child(&self, name: Name) -> Self {
        let mut rng_tree = RngTree::default();
        derive_key(
            rng_tree.seed_mut(),
            &self.master_key,
            Self::NAME_CONTEXT,
            Index::Bytes(name.0),
        );
        rng_tree
    }

    /// Produces a child with the specified integer index.
    pub fn index(&self, index: u64) -> Self {
        let mut rng_tree = RngTree::default();
        derive_key(
            rng_tree.seed_mut(),
            &self.master_key,
            Self::INDEX_CONTEXT,
            Index::Number(index),
        );
        rng_tree
    }
}

impl Drop for RngTree {
    fn drop(&mut self) {
        let handle = ClearOnDrop::new(&mut self.master_key);
        drop(handle);
    }
}

/// Name of an `RngTree`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name([u8; SALT_LEN]);

impl Name {
    /// Creates a new `Name`.
    ///
    /// The supplied string should be no more than `MAX_NAME_LEN` bytes in length
    /// and should not contain zero bytes.
    // This should become a `const fn` once the corresponding feature stabilizes.
    pub fn new(name: &str) -> Self {
        let byte_len = name.as_bytes().len();
        assert!(byte_len <= SALT_LEN, "name too long, 0..=16 bytes expected");
        assert!(
            name.as_bytes().iter().all(|&byte| byte > 0),
            "string contains null chars"
        );

        let mut bytes = [0; SALT_LEN];
        bytes[..byte_len].copy_from_slice(name.as_bytes());
        Name(bytes)
    }
}
