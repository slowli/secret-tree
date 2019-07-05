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

//! `libsodium`-compatible generic key derivation.

use blake2_rfc::blake2b::Blake2b;
use byteorder::{ByteOrder, LittleEndian};
use clear_on_drop::clear_stack_on_return;

/// Byte length of a `RngTree` seed (32).
// Blake2b specification states that it produces outputs in range 1..=64 bytes;
// libsodium supports 16..=64 byte outputs. We only use 32-byte outputs; this
// is the size of the `ChaChaRng` seed.
pub const SEED_LEN: usize = 32;

/// Byte length of a context variable.
// This length is half of what is supported by Blake2b (16 bytes),
// but is compatible with the key derivation in `libsodium`. We don’t
// need more internally and do not expose context to users.
pub const CONTEXT_LEN: usize = 8;

/// Byte length of salt in the Blake2b initialization block.
pub const SALT_LEN: usize = 16;

struct Blake2bParams([u64; 8]);

impl Blake2bParams {
    fn new() -> Self {
        let mut block = Blake2bParams([0; 8]);
        block.0[0] = 0x0101_0000; // encode fanout and max depth
        block
    }

    fn digest_len(&mut self, digest_len: u8) -> &mut Self {
        self.0[0] &= !0xff;
        self.0[0] |= u64::from(digest_len);
        self
    }

    fn key_len(&mut self, key_len: u8) -> &mut Self {
        self.0[0] &= !0xff00;
        self.0[0] |= u64::from(key_len) << 8;
        self
    }

    fn salt(&mut self, salt: [u64; 2]) -> &mut Self {
        self.0[4] = salt[0];
        self.0[5] = salt[1];
        self
    }

    fn personalization(&mut self, personalization: [u8; 8]) -> &mut Self {
        self.0[6] = LittleEndian::read_u64(&personalization);
        self
    }

    fn build(&self) -> [u64; 8] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Index {
    None,
    Number(u64),
    Bytes([u8; SALT_LEN]),
}

impl Index {
    fn to_salt(self) -> [u64; 2] {
        match self {
            Index::None => [0, 0],
            Index::Number(i) => [i, 0],
            Index::Bytes(bytes) => [
                LittleEndian::read_u64(&bytes[..8]),
                LittleEndian::read_u64(&bytes[8..]),
            ],
        }
    }
}

pub fn derive_key(
    output: &mut [u8],
    index: Index,
    context: [u8; CONTEXT_LEN],
    key: &[u8; SEED_LEN],
) {
    assert!(
        output.len() >= 16 && output.len() <= 64,
        "invalid output length, 16..=64 bytes expected"
    );

    let params = Blake2bParams::new()
        .digest_len(output.len() as u8)
        .key_len(SEED_LEN as u8)
        .salt(index.to_salt())
        .personalization(context)
        .build();

    // Overwriting a few pages of stack should be enough: the local vars
    // (`Blake2b` and `Blake2bResult`) have sizes < 500 bytes in total.
    clear_stack_on_return(4, || {
        let mut digest = Blake2b::with_parameter_block(&params);
        digest.update(key);
        digest.update(&[0_u8; 96]); // key padding: 3 * 32 bytes
        let digest = digest.finalize();
        assert_eq!(digest.len(), output.len());
        output.copy_from_slice(digest.as_bytes());
    });
}

#[test]
fn sodium_test_vectors_64byte_output() {
    use hex;

    const CTX: [u8; CONTEXT_LEN] = *b"KDF test";
    const EXP: &[&str] = &[
        "a0c724404728c8bb95e5433eb6a9716171144d61efb23e74b873fcbeda51d807\
         1b5d70aae12066dfc94ce943f145aa176c055040c3dd73b0a15e36254d450614",
        "02507f144fa9bf19010bf7c70b235b4c2663cc00e074f929602a5e2c10a78075\
         7d2a3993d06debc378a90efdac196dd841817b977d67b786804f6d3cd585bab5",
        "1944da61ff18dc2028c3578ac85be904931b83860896598f62468f1cb5471c6a\
         344c945dbc62c9aaf70feb62472d17775ea5db6ed5494c68b7a9a59761f39614",
        "131c0ca1633ed074986215b264f6e0474f362c52b029effc7b0f75977ee89cc9\
         5d85c3db87f7e399197a25411592beeeb7e5128a74646a460ecd6deb4994b71e",
        "a7023a0bf9be245d078aed26bcde0465ff0cc0961196a5482a0ff4ff8b401597\
         1e13611f50529cb408f5776b14a90e7c3dd9160a22211db64ff4b5c0b9953680",
        "50f49313f3a05b2e565c13feedb44daa675cafd42c2b2cf9edbce9c949fbfc3f\
         175dcb738671509ae2ea66fb85e552394d479afa7fa3affe8791744796b94176",
        "13b58d6d69780089293862cd59a1a8a4ef79bb850e3f3ba41fb22446a7dd1dc4\
         da4667d37b33bf1225dcf8173c4c349a5d911c5bd2db9c5905ed70c11e809e3b",
        "15d44b4b44ffa006eeceeb508c98a970aaa573d65905687b9e15854dec6d49c6\
         12757e149f78268f727660dedf9abce22a9691feb20a01b0525f4b47a3cf19db",
        "9aebba11c5428ae8225716369e30a48943be39159a899f804e9963ef78822e18\
         6c21fe95bb0b85e60ef03a6f58d0b9d06e91f79d0ab998450b8810c73ca935b4",
        "70f9b83e463fb441e7a4c43275125cd5b19d8e2e4a5d179a39f5db10bbce745a\
         199104563d308cf8d4c6b27bbb759ded232f5bdb7c367dd632a9677320dfe416",
    ];

    let mut key = [0_u8; SEED_LEN];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = i as u8;
    }

    let mut output = [0_u8; 64];
    for (i, &exp) in EXP.iter().enumerate() {
        derive_key(&mut output, Index::Number(i as u64), CTX, &key);
        assert_eq!(hex::encode(&output.as_ref()), exp);
    }
}

#[test]
fn sodium_test_vectors_varying_len_output() {
    use std::vec;
    use hex;

    const CTX: [u8; CONTEXT_LEN] = *b"KDF test";
    const EXP: &[&str] = &[
        "a529216624ef9161e4cf117272aafff2",
        "268214dc9477a2e3c1022829f934ab992a5a3d84",
        "94d678717625e011995c7355f2092267dee47bf0722dd380",
        "22c134b9d664e1bdb14dc309a936bf1512b19e4f5175642efb1a0df7",
        "154b291f11196737f8b7f491e4ca11764e0227d34f94295408a869f007aa8618",
        "20790290347b9b0f413a954f40e52e270b3b45417e96c8733161672188701c08dd76cc3d",
        "66efa5dfe3efd4cc8ca25f2d622c97a20a192d7add965f26b002b7eb81aae4203c0e5f07fd945845",
    ];

    let mut key = [0_u8; SEED_LEN];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = i as u8;
    }

    for &exp in EXP.iter() {
        let byte_size = exp.len() / 2;
        let mut output = vec![0; byte_size];
        derive_key(&mut output, Index::Number(byte_size as u64), CTX, &key);
        assert_eq!(hex::encode(&output), exp);
    }
}
