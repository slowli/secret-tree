//! Example how to store a `SecretTree` seed in the passphrase-encrypted form and use it
//! to derive heterogeneous keys.

use ed25519::{Keypair, SecretKey};
use pwbox::{
    rcrypto::{RustCrypto, Scrypt},
    Eraser, ScryptParams, Suite,
};
use rand::thread_rng;
use secrecy::{ExposeSecret, Secret};
use secret_tree::{Name, SecretTree};

use std::fmt;

struct Keys {
    consensus_keys: Keypair,
    service_keys: Keypair,
    other_secrets: Vec<Secret<u128>>,
}

impl Keys {
    pub fn new(tree: &SecretTree) -> Self {
        let consensus = tree.child(Name::new("consensus"));
        let service = tree.child(Name::new("service"));
        let other = tree.child(Name::new("other"));

        Keys {
            consensus_keys: Self::generate_keypair(consensus),
            service_keys: Self::generate_keypair(service),
            other_secrets: (0..5).map(|i| other.index(i).create_secret()).collect(),
        }
    }

    fn generate_keypair(tree: SecretTree) -> Keypair {
        // Secret keys in Ed25519 are just random bytes, so generating them in this way is safe.
        let secret_key = tree.create_secret::<[u8; 32]>();
        let secret_key = SecretKey::from_bytes(secret_key.expose_secret()).unwrap();

        Keypair {
            public: (&secret_key).into(),
            secret: secret_key,
        }
    }
}

impl fmt::Display for Keys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug_struct = formatter.debug_struct("Keys");
        debug_struct.field(
            "consensus",
            &hex::encode(self.consensus_keys.public.as_bytes()),
        );
        debug_struct.field("service", &hex::encode(self.service_keys.public.as_bytes()));
        for (i, secret) in self.other_secrets.iter().enumerate() {
            debug_struct.field(&format!("other/{}", i), secret.expose_secret());
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
            Scrypt(ScryptParams::custom(6, 16))
        } else {
            Scrypt::default()
        })
        .seal(passphrase, tree.seed().expose_secret())
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
    let tree = SecretTree::from_slice(&seed).unwrap();

    let keys = Keys::new(&tree);
    assert_eq!(
        public_keys,
        (keys.consensus_keys.public, keys.service_keys.public)
    );
    println!("Restored keys: {:#}", keys);
}
