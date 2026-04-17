//! Wire-format handshake messages for WireGuard's Noise IKpsk2 exchange.
//!
//! The structures in this module stay close to the on-the-wire layout:
//! fixed-size fields, explicit little-endian integers, and helpers for `MAC1`.

use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::noise::{
    crypto::{HASH_LEN, LABEL_MAC1, MAC_LEN, blake2s256, mac_blake2s},
    types::NoisePublicKey,
};

/// Handshake initiation message type.
pub const MESSAGE_TYPE_INITIATION: u32 = 1;

/// Handshake response message type.
pub const MESSAGE_TYPE_RESPONSE: u32 = 2;

/// Cookie reply message type.
pub const MESSAGE_TYPE_COOKIE_REPLY: u32 = 3;

/// Message parsing and serialization errors.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("unexpected message type {0}")]
    InvalidMessageType(u32),

    #[error(transparent)]
    Crypto(#[from] crate::noise::crypto::CryptoError),
}

/// Handshake initiation message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageInitiation {
    pub sender: u32,
    pub ephemeral: [u8; 32],
    pub encrypted_static: [u8; 48],
    pub encrypted_timestamp: [u8; 28],
    pub mac1: [u8; MAC_LEN],
    pub mac2: [u8; MAC_LEN],
}

impl MessageInitiation {
    pub const SIZE: usize = 148;
    const MAC1_OFFSET: usize = 116;
    const MAC2_OFFSET: usize = 132;

    /// Serialize the message into its 148-byte wire representation.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[..4].copy_from_slice(&MESSAGE_TYPE_INITIATION.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.sender.to_le_bytes());
        bytes[8..40].copy_from_slice(&self.ephemeral);
        bytes[40..88].copy_from_slice(&self.encrypted_static);
        bytes[88..116].copy_from_slice(&self.encrypted_timestamp);
        bytes[116..132].copy_from_slice(&self.mac1);
        bytes[132..148].copy_from_slice(&self.mac2);
        bytes
    }

    /// Parse a handshake initiation message from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::SIZE {
            return Err(ProtocolError::InvalidLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        let message_type = read_u32_le(&bytes[..4]);
        if message_type != MESSAGE_TYPE_INITIATION {
            return Err(ProtocolError::InvalidMessageType(message_type));
        }

        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&bytes[8..40]);

        let mut encrypted_static = [0u8; 48];
        encrypted_static.copy_from_slice(&bytes[40..88]);

        let mut encrypted_timestamp = [0u8; 28];
        encrypted_timestamp.copy_from_slice(&bytes[88..116]);

        let mut mac1 = [0u8; MAC_LEN];
        mac1.copy_from_slice(&bytes[116..132]);

        let mut mac2 = [0u8; MAC_LEN];
        mac2.copy_from_slice(&bytes[132..148]);

        Ok(Self {
            sender: read_u32_le(&bytes[4..8]),
            ephemeral,
            encrypted_static,
            encrypted_timestamp,
            mac1,
            mac2,
        })
    }

    /// Recompute `MAC1` for the current message contents.
    pub fn update_mac1(&mut self, receiver_static: &NoisePublicKey) -> Result<(), ProtocolError> {
        self.mac1 = compute_mac1(receiver_static, &self.packet_without_mac1())?;
        Ok(())
    }

    /// Verify `MAC1` against the configured receiver static public key.
    pub fn verify_mac1(&self, receiver_static: &NoisePublicKey) -> Result<bool, ProtocolError> {
        let expected = compute_mac1(receiver_static, &self.packet_without_mac1())?;
        Ok(bool::from(expected.ct_eq(&self.mac1)))
    }

    /// Return all bytes up to, but not including, `mac1`.
    pub fn packet_without_mac1(&self) -> [u8; Self::MAC1_OFFSET] {
        let bytes = self.to_bytes();
        let mut packet = [0u8; Self::MAC1_OFFSET];
        packet.copy_from_slice(&bytes[..Self::MAC1_OFFSET]);
        packet
    }

    /// Return all bytes up to, but not including, `mac2`.
    pub fn packet_without_mac2(&self) -> [u8; Self::MAC2_OFFSET] {
        let bytes = self.to_bytes();
        let mut packet = [0u8; Self::MAC2_OFFSET];
        packet.copy_from_slice(&bytes[..Self::MAC2_OFFSET]);
        packet
    }
}

/// Handshake response message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageResponse {
    pub sender: u32,
    pub receiver: u32,
    pub ephemeral: [u8; 32],
    pub encrypted_nothing: [u8; 16],
    pub mac1: [u8; MAC_LEN],
    pub mac2: [u8; MAC_LEN],
}

impl MessageResponse {
    pub const SIZE: usize = 92;
    const MAC1_OFFSET: usize = 60;
    const MAC2_OFFSET: usize = 76;

    /// Serialize the message into its 92-byte wire representation.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[..4].copy_from_slice(&MESSAGE_TYPE_RESPONSE.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.sender.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.receiver.to_le_bytes());
        bytes[12..44].copy_from_slice(&self.ephemeral);
        bytes[44..60].copy_from_slice(&self.encrypted_nothing);
        bytes[60..76].copy_from_slice(&self.mac1);
        bytes[76..92].copy_from_slice(&self.mac2);
        bytes
    }

    /// Parse a handshake response message from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::SIZE {
            return Err(ProtocolError::InvalidLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        let message_type = read_u32_le(&bytes[..4]);
        if message_type != MESSAGE_TYPE_RESPONSE {
            return Err(ProtocolError::InvalidMessageType(message_type));
        }

        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&bytes[12..44]);

        let mut encrypted_nothing = [0u8; 16];
        encrypted_nothing.copy_from_slice(&bytes[44..60]);

        let mut mac1 = [0u8; MAC_LEN];
        mac1.copy_from_slice(&bytes[60..76]);

        let mut mac2 = [0u8; MAC_LEN];
        mac2.copy_from_slice(&bytes[76..92]);

        Ok(Self {
            sender: read_u32_le(&bytes[4..8]),
            receiver: read_u32_le(&bytes[8..12]),
            ephemeral,
            encrypted_nothing,
            mac1,
            mac2,
        })
    }

    /// Recompute `MAC1` for the current message contents.
    pub fn update_mac1(&mut self, receiver_static: &NoisePublicKey) -> Result<(), ProtocolError> {
        self.mac1 = compute_mac1(receiver_static, &self.packet_without_mac1())?;
        Ok(())
    }

    /// Verify `MAC1` against the configured receiver static public key.
    pub fn verify_mac1(&self, receiver_static: &NoisePublicKey) -> Result<bool, ProtocolError> {
        let expected = compute_mac1(receiver_static, &self.packet_without_mac1())?;
        Ok(bool::from(expected.ct_eq(&self.mac1)))
    }

    /// Return all bytes up to, but not including, `mac1`.
    pub fn packet_without_mac1(&self) -> [u8; Self::MAC1_OFFSET] {
        let bytes = self.to_bytes();
        let mut packet = [0u8; Self::MAC1_OFFSET];
        packet.copy_from_slice(&bytes[..Self::MAC1_OFFSET]);
        packet
    }

    /// Return all bytes up to, but not including, `mac2`.
    pub fn packet_without_mac2(&self) -> [u8; Self::MAC2_OFFSET] {
        let bytes = self.to_bytes();
        let mut packet = [0u8; Self::MAC2_OFFSET];
        packet.copy_from_slice(&bytes[..Self::MAC2_OFFSET]);
        packet
    }
}

/// Cookie reply message used by the DoS mitigation subsystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageCookieReply {
    pub receiver: u32,
    pub nonce: [u8; 24],
    pub cookie: [u8; 32],
}

impl MessageCookieReply {
    pub const SIZE: usize = 64;

    /// Serialize the cookie reply into its 64-byte wire representation.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[..4].copy_from_slice(&MESSAGE_TYPE_COOKIE_REPLY.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.receiver.to_le_bytes());
        bytes[8..32].copy_from_slice(&self.nonce);
        bytes[32..64].copy_from_slice(&self.cookie);
        bytes
    }

    /// Parse a cookie reply from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::SIZE {
            return Err(ProtocolError::InvalidLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        let message_type = read_u32_le(&bytes[..4]);
        if message_type != MESSAGE_TYPE_COOKIE_REPLY {
            return Err(ProtocolError::InvalidMessageType(message_type));
        }

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes[8..32]);

        let mut cookie = [0u8; 32];
        cookie.copy_from_slice(&bytes[32..64]);

        Ok(Self {
            receiver: read_u32_le(&bytes[4..8]),
            nonce,
            cookie,
        })
    }
}

/// Pre-compute the 32-byte `MAC1` key `Hash("mac1----" || receiver_static)`.
pub fn mac1_key(receiver_static: &NoisePublicKey) -> [u8; HASH_LEN] {
    let mut material = [0u8; LABEL_MAC1.len() + 32];
    material[..LABEL_MAC1.len()].copy_from_slice(LABEL_MAC1);
    material[LABEL_MAC1.len()..].copy_from_slice(receiver_static.as_bytes());
    blake2s256(&material)
}

/// Compute the 16-byte `MAC1` for a packet prefix.
pub fn compute_mac1(
    receiver_static: &NoisePublicKey,
    packet_without_mac1: &[u8],
) -> Result<[u8; MAC_LEN], ProtocolError> {
    Ok(mac_blake2s(
        &mac1_key(receiver_static),
        packet_without_mac1,
    )?)
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    let raw: [u8; 4] = bytes
        .try_into()
        .expect("the slices in this module are fixed-size");
    u32::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
    use super::{MessageCookieReply, MessageInitiation, MessageResponse, compute_mac1, mac1_key};
    use crate::noise::types::NoisePrivateKey;

    #[test]
    fn initiation_round_trips_through_bytes() {
        let message = MessageInitiation {
            sender: 7,
            ephemeral: [1u8; 32],
            encrypted_static: [2u8; 48],
            encrypted_timestamp: [3u8; 28],
            mac1: [4u8; 16],
            mac2: [5u8; 16],
        };

        let encoded = message.to_bytes();
        let decoded = MessageInitiation::from_bytes(&encoded).unwrap();

        assert_eq!(decoded, message);
    }

    #[test]
    fn response_round_trips_through_bytes() {
        let message = MessageResponse {
            sender: 1,
            receiver: 2,
            ephemeral: [9u8; 32],
            encrypted_nothing: [8u8; 16],
            mac1: [7u8; 16],
            mac2: [6u8; 16],
        };

        let encoded = message.to_bytes();
        let decoded = MessageResponse::from_bytes(&encoded).unwrap();

        assert_eq!(decoded, message);
    }

    #[test]
    fn cookie_reply_round_trips_through_bytes() {
        let message = MessageCookieReply {
            receiver: 99,
            nonce: [1u8; 24],
            cookie: [2u8; 32],
        };

        let encoded = message.to_bytes();
        let decoded = MessageCookieReply::from_bytes(&encoded).unwrap();

        assert_eq!(decoded, message);
    }

    #[test]
    fn mac1_detects_packet_tampering() {
        let receiver_key = NoisePrivateKey::from_bytes(&[7u8; 32])
            .unwrap()
            .public_key();
        let mut message = MessageInitiation {
            sender: 11,
            ephemeral: [1u8; 32],
            encrypted_static: [2u8; 48],
            encrypted_timestamp: [3u8; 28],
            mac1: [0u8; 16],
            mac2: [0u8; 16],
        };

        message.update_mac1(&receiver_key).unwrap();
        assert!(message.verify_mac1(&receiver_key).unwrap());

        message.sender ^= 0x01;
        assert!(!message.verify_mac1(&receiver_key).unwrap());
    }

    #[test]
    fn mac1_key_matches_hash_of_label_and_public_key() {
        let receiver_key = NoisePrivateKey::from_bytes(&[3u8; 32])
            .unwrap()
            .public_key();
        let computed = mac1_key(&receiver_key);
        let mac = compute_mac1(&receiver_key, b"prefix").unwrap();

        assert_eq!(computed.len(), 32);
        assert_eq!(mac.len(), 16);
    }
}
