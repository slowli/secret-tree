//! `libsodium`-compatible generic key derivation.

use blake2::{
    digest::{
        core_api::{Buffer, UpdateCore, VariableOutputCore},
        Output,
    },
    Blake2bVarCore,
};

use crate::FillError;

/// Byte length of a [`Seed`](crate::Seed) (32).
// Blake2b specification states that it produces outputs in range 1..=64 bytes;
// libsodium supports 16..=64 byte outputs. We only use 32-byte outputs; this
// is the size of the `ChaChaRng` seed.
pub const SEED_LEN: usize = 32;

/// Byte length of a context variable.
// This length is half of what is supported by Blake2b (16 bytes),
// but is compatible with the key derivation in `libsodium`. We don’t
// need more internally and do not expose context to users.
pub(crate) const CONTEXT_LEN: usize = 8;

/// Byte length of salt in the Blake2b initialization block.
pub(crate) const SALT_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Index {
    None,
    Number(u64),
    Bytes([u8; SALT_LEN]),
}

impl Index {
    fn to_salt(self) -> [u8; 16] {
        match self {
            Index::None => [0; 16],
            Index::Number(i) => {
                let mut bytes = [0_u8; 16];
                bytes[..8].copy_from_slice(&i.to_le_bytes());
                bytes
            }
            Index::Bytes(bytes) => bytes,
        }
    }
}

pub(crate) fn try_derive_key(
    output: &mut [u8],
    index: Index,
    context: [u8; CONTEXT_LEN],
    key: &[u8; SEED_LEN],
) -> Result<(), FillError> {
    const MIN_SUPPORTED_SIZE: usize = 16;
    const MAX_SUPPORTED_SIZE: usize = 64;

    if output.len() < MIN_SUPPORTED_SIZE {
        return Err(FillError::BufferTooSmall {
            size: output.len(),
            min_supported_size: MIN_SUPPORTED_SIZE,
        });
    }
    if output.len() > MAX_SUPPORTED_SIZE {
        return Err(FillError::BufferTooLarge {
            size: output.len(),
            max_supported_size: MAX_SUPPORTED_SIZE,
        });
    }

    let mut buffer = Buffer::<Blake2bVarCore>::default();
    let mut core =
        Blake2bVarCore::new_with_params(&index.to_salt(), &context, SEED_LEN, output.len());
    buffer.digest_blocks(key, |blocks| core.update_blocks(blocks));
    // Pad the key with 3 * 32 = 96 bytes so that it occupies 2 entire blocks
    buffer.digest_blocks(&[0; 3 * SEED_LEN], |blocks| core.update_blocks(blocks));

    let mut full_output = Output::<Blake2bVarCore>::default();
    core.finalize_variable_core(&mut buffer, &mut full_output);
    output.copy_from_slice(&full_output[..output.len()]);
    Ok(())
}

pub(crate) fn derive_key(
    output: &mut [u8],
    index: Index,
    context: [u8; CONTEXT_LEN],
    key: &[u8; SEED_LEN],
) {
    try_derive_key(output, index, context, key).unwrap();
}

#[test]
fn sodium_test_vectors_64byte_output() {
    use const_decoder::Decoder::Hex;
    use std::convert::TryFrom;

    const CTX: [u8; CONTEXT_LEN] = *b"KDF test";
    const EXP: &[[u8; 64]] = &[
        Hex.decode(
            b"a0c724404728c8bb95e5433eb6a9716171144d61efb23e74b873fcbeda51d807\
              1b5d70aae12066dfc94ce943f145aa176c055040c3dd73b0a15e36254d450614",
        ),
        Hex.decode(
            b"02507f144fa9bf19010bf7c70b235b4c2663cc00e074f929602a5e2c10a78075\
              7d2a3993d06debc378a90efdac196dd841817b977d67b786804f6d3cd585bab5",
        ),
        Hex.decode(
            b"1944da61ff18dc2028c3578ac85be904931b83860896598f62468f1cb5471c6a\
              344c945dbc62c9aaf70feb62472d17775ea5db6ed5494c68b7a9a59761f39614",
        ),
        Hex.decode(
            b"131c0ca1633ed074986215b264f6e0474f362c52b029effc7b0f75977ee89cc9\
              5d85c3db87f7e399197a25411592beeeb7e5128a74646a460ecd6deb4994b71e",
        ),
        Hex.decode(
            b"a7023a0bf9be245d078aed26bcde0465ff0cc0961196a5482a0ff4ff8b401597\
              1e13611f50529cb408f5776b14a90e7c3dd9160a22211db64ff4b5c0b9953680",
        ),
        Hex.decode(
            b"50f49313f3a05b2e565c13feedb44daa675cafd42c2b2cf9edbce9c949fbfc3f\
              175dcb738671509ae2ea66fb85e552394d479afa7fa3affe8791744796b94176",
        ),
        Hex.decode(
            b"13b58d6d69780089293862cd59a1a8a4ef79bb850e3f3ba41fb22446a7dd1dc4\
              da4667d37b33bf1225dcf8173c4c349a5d911c5bd2db9c5905ed70c11e809e3b",
        ),
        Hex.decode(
            b"15d44b4b44ffa006eeceeb508c98a970aaa573d65905687b9e15854dec6d49c6\
              12757e149f78268f727660dedf9abce22a9691feb20a01b0525f4b47a3cf19db",
        ),
        Hex.decode(
            b"9aebba11c5428ae8225716369e30a48943be39159a899f804e9963ef78822e18\
             6c21fe95bb0b85e60ef03a6f58d0b9d06e91f79d0ab998450b8810c73ca935b4",
        ),
        Hex.decode(
            b"70f9b83e463fb441e7a4c43275125cd5b19d8e2e4a5d179a39f5db10bbce745a\
              199104563d308cf8d4c6b27bbb759ded232f5bdb7c367dd632a9677320dfe416",
        ),
    ];

    let mut key = [0_u8; SEED_LEN];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::try_from(i).unwrap();
    }

    let mut output = [0_u8; 64];
    for (i, exp) in EXP.iter().enumerate() {
        derive_key(&mut output, Index::Number(i as u64), CTX, &key);
        assert_eq!(&output as &[u8], exp as &[u8]);
    }
}

#[test]
fn sodium_test_vectors_varying_len_output() {
    use const_decoder::Decoder::Hex;
    use std::{convert::TryFrom, vec};

    const CTX: [u8; CONTEXT_LEN] = *b"KDF test";
    const EXP: &[&[u8]] = &[
        &Hex.decode::<16>(b"a529216624ef9161e4cf117272aafff2"),
        &Hex.decode::<20>(b"268214dc9477a2e3c1022829f934ab992a5a3d84"),
        &Hex.decode::<24>(b"94d678717625e011995c7355f2092267dee47bf0722dd380"),
        &Hex.decode::<28>(b"22c134b9d664e1bdb14dc309a936bf1512b19e4f5175642efb1a0df7"),
        &Hex.decode::<32>(b"154b291f11196737f8b7f491e4ca11764e0227d34f94295408a869f007aa8618"),
        &Hex.decode::<36>(
            b"20790290347b9b0f413a954f40e52e270b3b45417e96c8733161672188701c08dd76cc3d",
        ),
        &Hex.decode::<40>(
            b"66efa5dfe3efd4cc8ca25f2d622c97a20a192d7add965f26b002b7eb81aae4203c0e5f07fd945845",
        ),
    ];

    let mut key = [0_u8; SEED_LEN];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::try_from(i).unwrap();
    }

    for &exp in EXP {
        let byte_size = exp.len();
        let mut output = vec![0; byte_size];
        derive_key(&mut output, Index::Number(byte_size as u64), CTX, &key);
        assert_eq!(output.as_slice(), exp);
    }
}
