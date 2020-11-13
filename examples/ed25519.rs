// Copyright 2019 Alex Ostrovski
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

//! Example how to store a `SecretTree` seed in the passphrase-encrypted form and use it
//! to derive heterogeneous keys.

use ed25519::Keypair;
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
    other_secrets: Vec<Secret<[u128; 1]>>,
}

impl Keys {
    pub fn new(tree: &SecretTree) -> Self {
        let consensus = tree.child(Name::new("consensus"));
        let service = tree.child(Name::new("service"));
        let other = tree.child(Name::new("other"));

        Keys {
            consensus_keys: Keypair::generate(&mut consensus.rng()),
            service_keys: Keypair::generate(&mut service.rng()),
            other_secrets: (0..5).map(|i| other.index(i).create_secret()).collect(),
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
            debug_struct.field(&format!("other/{}", i), &secret.expose_secret()[0]);
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
