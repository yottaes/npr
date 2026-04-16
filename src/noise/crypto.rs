//! Cryptographic primitives for the Noise IKpsk2 handshake.
//!
//! Milestone 1 — to implement here:
//! - BLAKE2s hash wrappers
//! - KDF1 / KDF2 / KDF3 (HKDF over BLAKE2s)
//! - mix_key / mix_hash (Noise handshake state evolution)
//! - AEAD encrypt/decrypt (ChaCha20-Poly1305)
//! - TAI64N timestamp

use blake2::{Blake2s256, Blake2sMac256, Digest, digest::Mac};

/// `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` construction string.
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// WireGuard protocol identifier.
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// MAC1 label.
pub const LABEL_MAC1: &[u8] = b"mac1----";

/// Cookie label.
pub const LABEL_COOKIE: &[u8] = b"cookie--";

pub fn blake2s256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize().into()
}

///Store result only privately! exposing raw [u8; 32], contant time comparison functionality required.
pub fn hmac_blake2s(key: &[u8], data: &[u8]) -> Result<[u8; 32], anyhow::Error> {
    let mut hasher = Blake2sMac256::new_from_slice(key)?;
    hasher.update(data);

    //potentially unsafe. need to wrap into unified struct, with CtEq comparison.
    //and make it fully private.
    Ok(hasher.finalize().into_bytes().into())
}

#[cfg(test)]
mod test {
    use crate::noise::crypto::blake2s256;

    #[test]
    fn hashing_blake256() {
        let expected =
            hex::decode("716748cce97a0abc942e1d491bc25102f5b6ff71ee62a86abd605a6c40120169")
                .unwrap();
        assert_eq!(blake2s256(b"abcd").as_slice(), expected.as_slice());
    }
}
