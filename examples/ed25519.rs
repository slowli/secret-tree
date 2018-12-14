extern crate ed25519_dalek as ed25519;
extern crate hex;
extern crate pwbox;
extern crate rand;
extern crate secret_tree;
extern crate sha2;
extern crate toml;

use ed25519::Keypair;
use pwbox::{
    rcrypto::{RustCrypto, Scrypt},
    Eraser, Suite,
};
use rand::thread_rng;
use secret_tree::{Name, SecretTree};
use sha2::Sha512;

use std::fmt;

struct Keys {
    consensus_keys: Keypair,
    service_keys: Keypair,
    other_secrets: Vec<u128>,
}

impl Keys {
    pub fn new(tree: &SecretTree) -> Self {
        let consensus = tree.child(Name::new("consensus"));
        let service = tree.child(Name::new("service"));
        let other = tree.child(Name::new("other"));

        Keys {
            consensus_keys: Keypair::generate::<Sha512, _>(&mut consensus.rng()),
            service_keys: Keypair::generate::<Sha512, _>(&mut service.rng()),
            other_secrets: (0..5)
                .map(|i| {
                    let mut buffer = [0_u128];
                    other.index(i).fill(&mut buffer);
                    buffer[0]
                }).collect(),
        }
    }
}

impl fmt::Display for Keys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_struct = f.debug_struct("Keys");
        debug_struct.field(
            "consensus",
            &hex::encode(self.consensus_keys.public.as_bytes()),
        );
        debug_struct.field("service", &hex::encode(self.service_keys.public.as_bytes()));
        for (i, secret) in self.other_secrets.iter().enumerate() {
            debug_struct.field(&format!("other/{}", i), secret);
        }
        debug_struct.finish()
    }
}

fn main() {
    // Generate a RNG tree randomly.
    let mut rng = thread_rng();
    let tree = SecretTree::new(&mut rng);
    let keys = Keys::new(&tree);
    println!("Original keys: {:#}\n", keys);
    let public_keys = (keys.consensus_keys.public, keys.service_keys.public);

    // Assume that we have securely persisted the RNG tree (e.g., with passphrase encryption).
    let passphrase = "correct horse battery staple";
    let secured_store = RustCrypto::build_box(&mut rng)
        .kdf(if cfg!(debug_assertions) {
            // Ultra-light parameters to get the test run fast in the debug mode.
            Scrypt::custom(6, 16)
        } else {
            Scrypt::default()
        }).seal(passphrase, tree.seed())
        .unwrap();
    drop(tree);

    let mut eraser = Eraser::new();
    eraser.add_suite::<RustCrypto>();
    let secured_store = eraser.erase(&secured_store).unwrap();
    println!(
        "Passphrase-encrypted RNG tree (TOML):\n{}",
        toml::to_string(&secured_store).unwrap()
    );

    // ...Then, we can restore all keys by deserializing the RNG tree.
    let seed = eraser
        .restore(&secured_store)
        .unwrap()
        .open(passphrase)
        .unwrap();
    let tree = SecretTree::from_seed(&seed).unwrap();

    let keys = Keys::new(&tree);
    assert_eq!(
        public_keys,
        (keys.consensus_keys.public, keys.service_keys.public)
    );
    println!("Restored keys: {:#}", keys);
}
