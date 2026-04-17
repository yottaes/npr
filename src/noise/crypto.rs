//! Cryptographic building blocks for the WireGuard Noise IKpsk2 handshake.
//!
//! This module intentionally keeps the API small and explicit:
//! - BLAKE2s hashing for transcript evolution
//! - HMAC-BLAKE2s based HKDF (`kdf1`, `kdf2`, `kdf3`)
//! - keyed BLAKE2s-128 for `MAC1`
//! - ChaCha20-Poly1305 wrappers with WireGuard nonce construction
//! - TAI64N helpers for replay protection

use aead::{Aead, Payload};
use blake2::{
    Blake2s256, Blake2sMac,
    digest::{Digest, KeyInit as BlakeKeyInit, Mac as BlakeMac, consts::U16},
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use tai64::Tai64N;
use thiserror::Error;

/// Length in bytes of BLAKE2s and HKDF outputs used by Noise.
pub const HASH_LEN: usize = 32;

/// Length in bytes of the MAC fields in WireGuard handshake messages.
pub const MAC_LEN: usize = 16;

/// Length in bytes of a serialized TAI64N timestamp.
pub const TIMESTAMP_LEN: usize = Tai64N::BYTE_SIZE;

type Blake2sMac128 = Blake2sMac<U16>;
const BLAKE2S_BLOCK_LEN: usize = 64;

/// Errors produced by the cryptographic helper functions.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("keyed BLAKE2s accepts keys up to 32 bytes")]
    InvalidMacKeyLength,

    #[error("AEAD authentication failed")]
    AeadAuthenticationFailed,

    #[error("invalid TAI64N timestamp")]
    InvalidTimestamp(#[from] tai64::Error),
}

/// `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` construction string.
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// WireGuard protocol identifier.
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// `mac1----` label used to derive the `MAC1` key.
pub const LABEL_MAC1: &[u8] = b"mac1----";

/// `cookie--` label used later for the cookie subsystem.
pub const LABEL_COOKIE: &[u8] = b"cookie--";

/// Hash arbitrary bytes with BLAKE2s-256.
pub fn blake2s256(data: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute keyed BLAKE2s with a 16-byte output, matching WireGuard's `Mac()`.
pub fn mac_blake2s(key: &[u8], data: &[u8]) -> Result<[u8; MAC_LEN], CryptoError> {
    let mut hasher = <Blake2sMac128 as BlakeKeyInit>::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidMacKeyLength)?;
    hasher.update(data);
    Ok(hasher.finalize().into_bytes().into())
}

/// Compute HMAC-BLAKE2s-256, matching WireGuard's `Hmac()`.
pub fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    let mut normalized_key = [0u8; BLAKE2S_BLOCK_LEN];
    if key.len() > BLAKE2S_BLOCK_LEN {
        normalized_key[..HASH_LEN].copy_from_slice(&blake2s256(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLAKE2S_BLOCK_LEN];
    let mut outer_pad = [0x5cu8; BLAKE2S_BLOCK_LEN];
    for (pad, key_byte) in inner_pad.iter_mut().zip(normalized_key.iter()) {
        *pad ^= key_byte;
    }
    for (pad, key_byte) in outer_pad.iter_mut().zip(normalized_key.iter()) {
        *pad ^= key_byte;
    }

    let mut inner_hasher = Blake2s256::new();
    inner_hasher.update(inner_pad);
    inner_hasher.update(data);
    let inner_hash: [u8; HASH_LEN] = inner_hasher.finalize().into();

    let mut outer_hasher = Blake2s256::new();
    outer_hasher.update(outer_pad);
    outer_hasher.update(inner_hash);
    outer_hasher.finalize().into()
}

/// Derive a single 32-byte output using WireGuard's HKDF construction.
pub fn kdf1(key: &[u8; HASH_LEN], input: &[u8]) -> [u8; HASH_LEN] {
    let prk = hmac_blake2s(key, input);
    hmac_blake2s(&prk, &[0x01])
}

/// Derive two 32-byte outputs using WireGuard's HKDF construction.
pub fn kdf2(key: &[u8; HASH_LEN], input: &[u8]) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
    let prk = hmac_blake2s(key, input);
    let t1 = hmac_blake2s(&prk, &[0x01]);

    let mut second_input = [0u8; HASH_LEN + 1];
    second_input[..HASH_LEN].copy_from_slice(&t1);
    second_input[HASH_LEN] = 0x02;
    let t2 = hmac_blake2s(&prk, &second_input);

    (t1, t2)
}

/// Derive three 32-byte outputs using WireGuard's HKDF construction.
pub fn kdf3(
    key: &[u8; HASH_LEN],
    input: &[u8],
) -> ([u8; HASH_LEN], [u8; HASH_LEN], [u8; HASH_LEN]) {
    let prk = hmac_blake2s(key, input);
    let t1 = hmac_blake2s(&prk, &[0x01]);

    let mut second_input = [0u8; HASH_LEN + 1];
    second_input[..HASH_LEN].copy_from_slice(&t1);
    second_input[HASH_LEN] = 0x02;
    let t2 = hmac_blake2s(&prk, &second_input);

    let mut third_input = [0u8; HASH_LEN + 1];
    third_input[..HASH_LEN].copy_from_slice(&t2);
    third_input[HASH_LEN] = 0x03;
    let t3 = hmac_blake2s(&prk, &third_input);

    (t1, t2, t3)
}

/// Update the running handshake hash with the next transcript fragment.
pub fn mix_hash(hash: &[u8; HASH_LEN], data: &[u8]) -> [u8; HASH_LEN] {
    let mut input = Vec::with_capacity(HASH_LEN + data.len());
    input.extend_from_slice(hash);
    input.extend_from_slice(data);
    blake2s256(&input)
}

/// Update the chaining key with new input key material and return a temp key.
pub fn mix_key(
    chain_key: &[u8; HASH_LEN],
    input_key_material: &[u8],
) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
    kdf2(chain_key, input_key_material)
}

/// Compute the initial chaining key `Hash(Construction)`.
pub fn initial_chain_key() -> [u8; HASH_LEN] {
    blake2s256(CONSTRUCTION)
}

/// Compute the initial transcript hash `Hash(Hash(Construction) || Identifier)`.
pub fn initial_hash() -> [u8; HASH_LEN] {
    let chain_key = initial_chain_key();
    mix_hash(&chain_key, IDENTIFIER)
}

/// Build the 96-bit ChaCha20-Poly1305 nonce from a 64-bit packet counter.
pub fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Encrypt with ChaCha20-Poly1305 using WireGuard's fixed nonce layout.
pub fn aead_encrypt(
    key: &[u8; HASH_LEN],
    counter: u64,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = nonce_from_counter(counter);

    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::AeadAuthenticationFailed)
}

/// Decrypt with ChaCha20-Poly1305 using WireGuard's fixed nonce layout.
pub fn aead_decrypt(
    key: &[u8; HASH_LEN],
    counter: u64,
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = nonce_from_counter(counter);

    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::AeadAuthenticationFailed)
}

/// Generate a current TAI64N timestamp as 12 bytes.
pub fn tai64n_now() -> [u8; TIMESTAMP_LEN] {
    Tai64N::now().to_bytes()
}

/// Parse a serialized TAI64N timestamp.
pub fn parse_tai64n(bytes: &[u8; TIMESTAMP_LEN]) -> Result<Tai64N, CryptoError> {
    Ok(Tai64N::from_slice(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::{
        aead_decrypt, aead_encrypt, blake2s256, hmac_blake2s, initial_chain_key, initial_hash,
        kdf1, kdf2, kdf3, mac_blake2s, mix_hash, nonce_from_counter, parse_tai64n, tai64n_now,
    };

    #[test]
    fn blake2s256_matches_known_vector() {
        let expected =
            hex::decode("716748cce97a0abc942e1d491bc25102f5b6ff71ee62a86abd605a6c40120169")
                .unwrap();

        assert_eq!(blake2s256(b"abcd").as_slice(), expected.as_slice());
    }

    #[test]
    fn keyed_blake2s_mac_matches_known_vector() {
        let actual = mac_blake2s(b"0123456789abcdef", b"hello mac1").unwrap();
        let expected = hex::decode("4f6a895b2d1a5ee1f7112aae3f2cb618").unwrap();

        assert_eq!(actual.as_slice(), expected.as_slice());
    }

    #[test]
    fn keyed_blake2s_rejects_too_long_key() {
        assert!(mac_blake2s(&[1u8; 33], b"hello").is_err());
    }

    #[test]
    fn hmac_blake2s_matches_known_vector() {
        let expected =
            hex::decode("750fd5a6f6d0d915f3a67537105d4dcb5e6377ac83113c56db3a808538db8da2")
                .unwrap();
        let actual = hmac_blake2s(b"super secret key", b"hello noise");

        assert_eq!(actual.as_slice(), expected.as_slice());
    }

    #[test]
    fn kdfs_match_known_vectors() {
        let key = hex::decode("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36")
            .unwrap();
        let input = hex::decode("0102030405060708090a").unwrap();
        let key: [u8; 32] = key.try_into().unwrap();

        let k1 = kdf1(&key, &input);
        let (k2_a, k2_b) = kdf2(&key, &input);
        let (k3_a, k3_b, k3_c) = kdf3(&key, &input);

        assert_eq!(
            k1.as_slice(),
            hex::decode("7b9e91f1ba1955019211909ea96be3f7dd912c34dd5b7d2fb7635b3131bbbee8")
                .unwrap()
                .as_slice()
        );
        assert_eq!(k2_a, k1);
        assert_eq!(
            k2_b.as_slice(),
            hex::decode("c8ebb4faa815ad7d55641b12092db89cdb96b207936b0097b85566c353dd2f9b")
                .unwrap()
                .as_slice()
        );
        assert_eq!(k3_a, k1);
        assert_eq!(k3_b, k2_b);
        assert_eq!(
            k3_c.as_slice(),
            hex::decode("faee76cb2abbc110ae7e53278b430cb3d2dd633624f655044a5214dac17cec72")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn initial_noise_values_match_spec_vectors() {
        let expected_chain_key =
            hex::decode("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36")
                .unwrap();
        let expected_hash =
            hex::decode("2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3")
                .unwrap();

        assert_eq!(
            initial_chain_key().as_slice(),
            expected_chain_key.as_slice()
        );
        assert_eq!(initial_hash().as_slice(), expected_hash.as_slice());
    }

    #[test]
    fn mix_hash_appends_to_the_transcript() {
        let current_hash = initial_hash();
        let mixed = mix_hash(&current_hash, b"next frame");

        assert_ne!(mixed, current_hash);
        assert_eq!(mixed, mix_hash(&current_hash, b"next frame"));
    }

    #[test]
    fn nonce_layout_matches_wireguard() {
        assert_eq!(
            nonce_from_counter(0x0102_0304_0506_0708),
            [0, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn aead_round_trip_succeeds() {
        let key = [7u8; 32];
        let ciphertext = aead_encrypt(&key, 3, b"handshake payload", b"aad").unwrap();
        let plaintext = aead_decrypt(&key, 3, &ciphertext, b"aad").unwrap();

        assert_eq!(plaintext, b"handshake payload");
    }

    #[test]
    fn aead_rejects_tampered_ciphertext() {
        let key = [9u8; 32];
        let mut ciphertext = aead_encrypt(&key, 9, b"sealed", b"transcript").unwrap();
        ciphertext[0] ^= 0x01;

        assert!(aead_decrypt(&key, 9, &ciphertext, b"transcript").is_err());
    }

    #[test]
    fn tai64n_helpers_round_trip() {
        let bytes = tai64n_now();
        let parsed = parse_tai64n(&bytes).unwrap();

        assert_eq!(parsed.to_bytes(), bytes);
    }
}
