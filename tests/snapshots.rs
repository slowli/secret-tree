//! Snapshot tests to ensure that the secrets derived from the tree remain usable across
//! crate updates.

use insta::assert_yaml_snapshot;
use rand::Rng;
use secrecy::ExposeSecret;
use serde::Serialize;

use std::collections::BTreeMap;

use secret_tree::{Name, SecretTree, Seed};

#[derive(Debug, Serialize)]
struct TreeOutput {
    indexed_values: Vec<u128>,
    named_values: BTreeMap<&'static str, i128>,
    digest_values: Vec<u128>,
    rng_output: [u32; 4],
}

impl TreeOutput {
    fn new(tree: SecretTree) -> Self {
        const NAMES: &[Name] = &[Name::new("test"), Name::new("other"), Name::new("third")];

        Self {
            indexed_values: (0..5)
                .map(|i| *tree.index(i).create_secret().expose_secret())
                .collect(),
            named_values: NAMES
                .iter()
                .map(|name| {
                    let mut value = 0_i128;
                    tree.child(*name).fill(&mut value);
                    (name.as_ref(), value)
                })
                .collect(),
            digest_values: (0..5)
                .map(|i| *tree.digest(&[i; 32]).create_secret().expose_secret())
                .collect(),
            rng_output: tree.rng().gen(),
        }
    }
}

#[test]
fn secret_derivation_snapshot() {
    let tree = SecretTree::from_seed(Seed::from(&[7; 32]));
    let tree_output = TreeOutput::new(tree);
    assert_yaml_snapshot!("tree-output", tree_output);
}
