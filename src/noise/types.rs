use std::fmt;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("Invalid hex format")]
    InvalidHexFormat,

    #[error("Key must be exactly 32 bytes")]
    InvalidKeyLength,

    #[error("Invalid key value")]
    InvalidKeyValue,
}

#[derive(ZeroizeOnDrop, Zeroize)]
pub struct NoisePrivateKey(StaticSecret);

impl NoisePrivateKey {
    pub fn generate() -> Self {
        Self(StaticSecret::random())
    }

    /// From config/uapi.
    pub fn from_hex(hex_str: &str) -> Result<Self, NoiseError> {
        let bytes = hex::decode(hex_str).map_err(|_| NoiseError::InvalidHexFormat)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NoiseError> {
        if bytes.len() != 32 {
            return Err(NoiseError::InvalidKeyLength);
        }
        let arr: [u8; 32] = bytes.try_into().map_err(|_| NoiseError::InvalidKeyLength)?;
        Ok(Self(StaticSecret::from(arr)))
    }

    pub fn public_key(&self) -> NoisePublicKey {
        NoisePublicKey(DalekPublicKey::from(&self.0))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub(crate) fn diffie_hellman(&self, their_public: &NoisePublicKey) -> [u8; 32] {
        self.0.diffie_hellman(&their_public.0).to_bytes()
    }
}

impl ConstantTimeEq for NoisePrivateKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.as_bytes().ct_eq(other.0.as_bytes())
    }
}

#[derive(Copy, Clone)]
pub struct NoisePublicKey(DalekPublicKey);

impl PartialEq for NoisePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for NoisePublicKey {}

impl NoisePublicKey {
    pub fn from_hex(hex_str: &str) -> Result<Self, NoiseError> {
        let bytes = hex::decode(hex_str).map_err(|_| NoiseError::InvalidHexFormat)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NoiseError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| NoiseError::InvalidKeyLength)?;
        Ok(Self(DalekPublicKey::from(arr)))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl ConstantTimeEq for NoisePublicKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.as_bytes().ct_eq(other.0.as_bytes())
    }
}

/// One-time ephemeral key for a single handshake session.
/// Generated fresh on every handshake and zeroized immediately after.
#[derive(ZeroizeOnDrop, Zeroize)]
pub struct NoiseEphemeralKey(StaticSecret);

impl NoiseEphemeralKey {
    pub fn generate() -> Self {
        Self(StaticSecret::random())
    }

    #[cfg(test)]
    pub(crate) fn new(secret: StaticSecret) -> Self {
        Self(secret)
    }

    pub fn public_key(&self) -> NoisePublicKey {
        NoisePublicKey(DalekPublicKey::from(&self.0))
    }

    pub(crate) fn diffie_hellman(&self, their_public: &NoisePublicKey) -> [u8; 32] {
        self.0.diffie_hellman(&their_public.0).to_bytes()
    }
}

impl fmt::Debug for NoiseEphemeralKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NoiseEphemeralKey")
            .field(&"***REDACTED***")
            .finish()
    }
}

#[derive(ZeroizeOnDrop, Zeroize)]
pub struct NoisePresharedKey([u8; 32]);

impl NoisePresharedKey {
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, NoiseError> {
        let bytes = hex::decode(hex_str).map_err(|_| NoiseError::InvalidHexFormat)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NoiseError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| NoiseError::InvalidKeyLength)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl ConstantTimeEq for NoisePresharedKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Default for NoisePresharedKey {
    fn default() -> Self {
        Self::zero()
    }
}

impl fmt::Debug for NoisePrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NoisePrivateKey")
            .field(&"***REDACTED***")
            .finish()
    }
}

impl fmt::Debug for NoisePresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NoisePresharedKey")
            .field(&"***REDACTED***")
            .finish()
    }
}

impl fmt::Debug for NoisePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NoisePublicKey")
            .field(&hex::encode(self.as_bytes()))
            .finish()
    }
}
