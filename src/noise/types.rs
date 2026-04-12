use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("Invalid hex format")]
    InvalidHexFormat,
    #[error("Key must be 32 bytes")]
    InvalidKeyLength,
    #[error("Invalid key value")]
    InvalidKeyValue,
}

#[derive(ZeroizeOnDrop, Zeroize)]
pub struct NoisePrivateKey([u8; 32]);

impl NoisePrivateKey {
    pub fn from_hex(hex_str: &str) -> Result<Self, NoiseError> {
        Ok(Self(parse_hex(hex_str)?))
    }
}

impl ConstantTimeEq for NoisePrivateKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

#[derive(ZeroizeOnDrop, Zeroize)]
pub struct NoisePresharedKey([u8; 32]);

impl NoisePresharedKey {
    pub fn from_hex(hex_str: &str) -> Result<Self, NoiseError> {
        Ok(Self(parse_hex(hex_str)?))
    }
}

impl ConstantTimeEq for NoisePresharedKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct NoisePublicKey([u8; 32]);

impl ConstantTimeEq for NoisePublicKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl NoisePublicKey {
    pub fn from_hex(hex_str: &str) -> Result<Self, NoiseError> {
        Ok(Self(parse_hex(hex_str)?))
    }
}

fn parse_hex(hex_str: &str) -> Result<[u8; 32], NoiseError> {
    let bytes = hex::decode(hex_str).map_err(|_| NoiseError::InvalidHexFormat)?;
    if bytes.len() != 32 {
        return Err(NoiseError::InvalidKeyLength);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
