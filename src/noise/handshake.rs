//! Noise IKpsk2 handshake state machine for WireGuard-compatible sessions.
//!
//! The state machine is intentionally explicit and mirrors the whitepaper:
//! create or consume the initiation, create or consume the response, then
//! derive transport keys with `begin_symmetric_session`.

use rand_core::{OsRng, RngCore};
use tai64::Tai64N;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::noise::{
    crypto::{
        HASH_LEN, TIMESTAMP_LEN, aead_decrypt, aead_encrypt, initial_chain_key, initial_hash, kdf1,
        kdf2, kdf3, mix_hash, parse_tai64n, tai64n_now,
    },
    protocol::{MessageInitiation, MessageResponse},
    types::{NoiseEphemeralKey, NoisePresharedKey, NoisePrivateKey, NoisePublicKey},
};

/// High-level handshake state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakePhase {
    Zeroed,
    InitiationCreated,
    InitiationConsumed,
    ResponseCreated,
    ResponseConsumed,
    SessionEstablished,
}

/// Information recovered when the responder consumes an initiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumedInitiation {
    pub sender_index: u32,
    pub remote_static: NoisePublicKey,
    pub timestamp: Tai64N,
}

/// Symmetric transport keys derived from a completed handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportSession {
    pub local_index: u32,
    pub remote_index: u32,
    pub send_key: [u8; HASH_LEN],
    pub receive_key: [u8; HASH_LEN],
    pub handshake_hash: [u8; HASH_LEN],
    pub is_initiator: bool,
}

impl Drop for TransportSession {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.receive_key.zeroize();
    }
}

impl ZeroizeOnDrop for TransportSession {}

/// Errors produced while building or consuming handshake messages.
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("invalid handshake phase: expected {expected}, found {actual:?}")]
    InvalidPhase {
        expected: &'static str,
        actual: HandshakePhase,
    },

    #[error("the incoming message has an invalid MAC1")]
    InvalidMac1,

    #[error("the decrypted remote static public key does not match the configured peer")]
    UnexpectedRemoteStatic,

    #[error("the response receiver index does not match the local sender index")]
    UnexpectedReceiverIndex,

    #[error("the initiation timestamp is not newer than the last accepted timestamp")]
    ReplayedTimestamp,

    #[error("failed to decrypt the initiator static public key")]
    StaticDecryptFailed(#[source] crate::noise::crypto::CryptoError),

    #[error("failed to decrypt the initiation timestamp")]
    TimestampDecryptFailed(#[source] crate::noise::crypto::CryptoError),

    #[error("failed to decrypt the response confirmation payload")]
    ResponseDecryptFailed(#[source] crate::noise::crypto::CryptoError),

    #[error("missing local ephemeral key")]
    MissingLocalEphemeral,

    #[error("missing remote ephemeral public key")]
    MissingRemoteEphemeral,

    #[error("missing local sender index")]
    MissingLocalSenderIndex,

    #[error("missing remote sender index")]
    MissingRemoteSenderIndex,

    #[error("the response payload must decrypt to an empty message")]
    InvalidResponsePayload,

    #[error(transparent)]
    Crypto(#[from] crate::noise::crypto::CryptoError),

    #[error(transparent)]
    Protocol(#[from] crate::noise::protocol::ProtocolError),
}

/// Handshake state for one peer pair.
///
/// The local static private key and the configured peer public key are fixed
/// inputs. The remaining fields evolve as handshake messages are created and
/// consumed.
pub struct HandshakeState {
    local_static: NoisePrivateKey,
    peer_static: NoisePublicKey,
    preshared_key: NoisePresharedKey,
    precomputed_static_static: [u8; HASH_LEN],
    phase: HandshakePhase,
    is_initiator: bool,
    chain_key: [u8; HASH_LEN],
    hash: [u8; HASH_LEN],
    local_ephemeral: Option<NoiseEphemeralKey>,
    remote_ephemeral: Option<NoisePublicKey>,
    local_sender_index: Option<u32>,
    remote_sender_index: Option<u32>,
    last_remote_timestamp: Option<Tai64N>,
}

impl HandshakeState {
    /// Create a state machine for the initiator role.
    pub fn new_initiator(
        local_static: NoisePrivateKey,
        peer_static: NoisePublicKey,
        preshared_key: NoisePresharedKey,
    ) -> Self {
        let precomputed_static_static = local_static.diffie_hellman(&peer_static);

        Self {
            local_static,
            peer_static,
            preshared_key,
            precomputed_static_static,
            phase: HandshakePhase::Zeroed,
            is_initiator: true,
            chain_key: initial_chain_key(),
            hash: initial_hash(),
            local_ephemeral: None,
            remote_ephemeral: None,
            local_sender_index: None,
            remote_sender_index: None,
            last_remote_timestamp: None,
        }
    }

    /// Create a state machine for the responder role.
    pub fn new_responder(
        local_static: NoisePrivateKey,
        peer_static: NoisePublicKey,
        preshared_key: NoisePresharedKey,
    ) -> Self {
        let precomputed_static_static = local_static.diffie_hellman(&peer_static);

        Self {
            local_static,
            peer_static,
            preshared_key,
            precomputed_static_static,
            phase: HandshakePhase::Zeroed,
            is_initiator: false,
            chain_key: initial_chain_key(),
            hash: initial_hash(),
            local_ephemeral: None,
            remote_ephemeral: None,
            local_sender_index: None,
            remote_sender_index: None,
            last_remote_timestamp: None,
        }
    }

    /// Return the current handshake phase.
    pub fn phase(&self) -> HandshakePhase {
        self.phase
    }

    /// Return the current transcript hash.
    pub fn handshake_hash(&self) -> [u8; HASH_LEN] {
        self.hash
    }

    /// Create the initiator's first handshake message.
    pub fn create_message_initiation(&mut self) -> Result<MessageInitiation, HandshakeError> {
        self.reset_for_outgoing_initiation();

        let sender_index = random_u32();
        let ephemeral = NoiseEphemeralKey::generate();
        let timestamp = tai64n_now();

        self.create_message_initiation_inner(sender_index, ephemeral, timestamp)
    }

    /// Consume the initiator's first handshake message as the responder.
    pub fn consume_message_initiation(
        &mut self,
        message: &MessageInitiation,
    ) -> Result<ConsumedInitiation, HandshakeError> {
        self.reset_for_incoming_initiation();

        if !message.verify_mac1(&self.local_static.public_key())? {
            return Err(HandshakeError::InvalidMac1);
        }

        self.chain_key = kdf1(&self.chain_key, &message.ephemeral);
        self.hash = mix_hash(&self.hash, &message.ephemeral);
        self.remote_ephemeral = Some(NoisePublicKey::from_bytes(&message.ephemeral).unwrap());

        let ephemeral_shared = self.local_static.diffie_hellman(
            self.remote_ephemeral
                .as_ref()
                .ok_or(HandshakeError::MissingRemoteEphemeral)?,
        );
        let (new_chain_key, temp_key) = kdf2(&self.chain_key, &ephemeral_shared);
        self.chain_key = new_chain_key;

        let decrypted_static = aead_decrypt(&temp_key, 0, &message.encrypted_static, &self.hash)
            .map_err(HandshakeError::StaticDecryptFailed)?;
        let remote_static = NoisePublicKey::from_bytes(&decrypted_static)
            .map_err(|_| HandshakeError::UnexpectedRemoteStatic)?;
        if remote_static != self.peer_static {
            return Err(HandshakeError::UnexpectedRemoteStatic);
        }

        self.hash = mix_hash(&self.hash, &message.encrypted_static);

        let (new_chain_key, temp_key) = kdf2(&self.chain_key, &self.precomputed_static_static);
        self.chain_key = new_chain_key;
        let decrypted_timestamp =
            aead_decrypt(&temp_key, 0, &message.encrypted_timestamp, &self.hash)
                .map_err(HandshakeError::TimestampDecryptFailed)?;
        let decrypted_timestamp: [u8; TIMESTAMP_LEN] = decrypted_timestamp
            .try_into()
            .map_err(|_| HandshakeError::ReplayedTimestamp)?;
        let timestamp = parse_tai64n(&decrypted_timestamp)?;

        if self
            .last_remote_timestamp
            .as_ref()
            .is_some_and(|previous| timestamp <= *previous)
        {
            return Err(HandshakeError::ReplayedTimestamp);
        }

        self.last_remote_timestamp = Some(timestamp);
        self.hash = mix_hash(&self.hash, &message.encrypted_timestamp);
        self.remote_sender_index = Some(message.sender);
        self.phase = HandshakePhase::InitiationConsumed;

        Ok(ConsumedInitiation {
            sender_index: message.sender,
            remote_static,
            timestamp,
        })
    }

    /// Create the responder's handshake response.
    pub fn create_message_response(&mut self) -> Result<MessageResponse, HandshakeError> {
        if self.phase != HandshakePhase::InitiationConsumed {
            return Err(HandshakeError::InvalidPhase {
                expected: "InitiationConsumed",
                actual: self.phase,
            });
        }

        let sender_index = random_u32();
        let ephemeral = NoiseEphemeralKey::generate();
        self.create_message_response_inner(sender_index, ephemeral)
    }

    /// Consume the responder's handshake response as the initiator.
    pub fn consume_message_response(
        &mut self,
        message: &MessageResponse,
    ) -> Result<(), HandshakeError> {
        if self.phase != HandshakePhase::InitiationCreated {
            return Err(HandshakeError::InvalidPhase {
                expected: "InitiationCreated",
                actual: self.phase,
            });
        }

        if !message.verify_mac1(&self.local_static.public_key())? {
            return Err(HandshakeError::InvalidMac1);
        }

        let local_sender_index = self
            .local_sender_index
            .ok_or(HandshakeError::MissingLocalSenderIndex)?;
        if message.receiver != local_sender_index {
            return Err(HandshakeError::UnexpectedReceiverIndex);
        }

        self.chain_key = kdf1(&self.chain_key, &message.ephemeral);
        self.hash = mix_hash(&self.hash, &message.ephemeral);
        self.remote_ephemeral = Some(NoisePublicKey::from_bytes(&message.ephemeral).unwrap());

        let local_ephemeral = self
            .local_ephemeral
            .as_ref()
            .ok_or(HandshakeError::MissingLocalEphemeral)?;
        let remote_ephemeral = self
            .remote_ephemeral
            .as_ref()
            .ok_or(HandshakeError::MissingRemoteEphemeral)?;

        let ephemeral_shared = local_ephemeral.diffie_hellman(remote_ephemeral);
        self.chain_key = kdf1(&self.chain_key, &ephemeral_shared);

        let static_shared = self.local_static.diffie_hellman(remote_ephemeral);
        self.chain_key = kdf1(&self.chain_key, &static_shared);

        let (new_chain_key, tau, temp_key) = kdf3(&self.chain_key, self.preshared_key.as_bytes());
        self.chain_key = new_chain_key;
        self.hash = mix_hash(&self.hash, &tau);

        let decrypted_payload = aead_decrypt(&temp_key, 0, &message.encrypted_nothing, &self.hash)
            .map_err(HandshakeError::ResponseDecryptFailed)?;
        if !decrypted_payload.is_empty() {
            return Err(HandshakeError::InvalidResponsePayload);
        }

        self.hash = mix_hash(&self.hash, &message.encrypted_nothing);
        self.remote_sender_index = Some(message.sender);
        self.phase = HandshakePhase::ResponseConsumed;
        Ok(())
    }

    /// Derive transport send/receive keys once the handshake is complete.
    pub fn begin_symmetric_session(&mut self) -> Result<TransportSession, HandshakeError> {
        let phase = self.phase;
        let can_derive = (self.is_initiator && phase == HandshakePhase::ResponseConsumed)
            || (!self.is_initiator && phase == HandshakePhase::ResponseCreated);
        if !can_derive {
            return Err(HandshakeError::InvalidPhase {
                expected: "ResponseConsumed (initiator) or ResponseCreated (responder)",
                actual: phase,
            });
        }

        let local_index = self
            .local_sender_index
            .ok_or(HandshakeError::MissingLocalSenderIndex)?;
        let remote_index = self
            .remote_sender_index
            .ok_or(HandshakeError::MissingRemoteSenderIndex)?;

        let (first_key, second_key) = kdf2(&self.chain_key, &[]);
        let (send_key, receive_key) = if self.is_initiator {
            (first_key, second_key)
        } else {
            (second_key, first_key)
        };

        let session = TransportSession {
            local_index,
            remote_index,
            send_key,
            receive_key,
            handshake_hash: self.hash,
            is_initiator: self.is_initiator,
        };

        self.clear_ephemeral_state();
        self.phase = HandshakePhase::SessionEstablished;

        Ok(session)
    }

    fn create_message_initiation_inner(
        &mut self,
        sender_index: u32,
        ephemeral: NoiseEphemeralKey,
        timestamp: [u8; TIMESTAMP_LEN],
    ) -> Result<MessageInitiation, HandshakeError> {
        let ephemeral_public = ephemeral.public_key();
        self.local_sender_index = Some(sender_index);
        self.local_ephemeral = Some(ephemeral);

        self.chain_key = kdf1(&self.chain_key, ephemeral_public.as_bytes());
        self.hash = mix_hash(&self.hash, ephemeral_public.as_bytes());

        let local_ephemeral = self
            .local_ephemeral
            .as_ref()
            .ok_or(HandshakeError::MissingLocalEphemeral)?;
        let ephemeral_shared = local_ephemeral.diffie_hellman(&self.peer_static);
        let (new_chain_key, temp_key) = kdf2(&self.chain_key, &ephemeral_shared);
        self.chain_key = new_chain_key;

        let local_static_public = self.local_static.public_key();
        let encrypted_static =
            aead_encrypt(&temp_key, 0, local_static_public.as_bytes(), &self.hash)?;
        let encrypted_static: [u8; 48] = encrypted_static.try_into().unwrap();
        self.hash = mix_hash(&self.hash, &encrypted_static);

        let (new_chain_key, temp_key) = kdf2(&self.chain_key, &self.precomputed_static_static);
        self.chain_key = new_chain_key;
        let encrypted_timestamp = aead_encrypt(&temp_key, 0, &timestamp, &self.hash)?;
        let encrypted_timestamp: [u8; 28] = encrypted_timestamp.try_into().unwrap();
        self.hash = mix_hash(&self.hash, &encrypted_timestamp);

        let mut message = MessageInitiation {
            sender: sender_index,
            ephemeral: *ephemeral_public.as_bytes(),
            encrypted_static,
            encrypted_timestamp,
            mac1: [0u8; 16],
            mac2: [0u8; 16],
        };
        message.update_mac1(&self.peer_static)?;
        self.phase = HandshakePhase::InitiationCreated;

        Ok(message)
    }

    fn create_message_response_inner(
        &mut self,
        sender_index: u32,
        ephemeral: NoiseEphemeralKey,
    ) -> Result<MessageResponse, HandshakeError> {
        let remote_ephemeral = *self
            .remote_ephemeral
            .as_ref()
            .ok_or(HandshakeError::MissingRemoteEphemeral)?;
        let remote_sender_index = self
            .remote_sender_index
            .ok_or(HandshakeError::MissingRemoteSenderIndex)?;

        let ephemeral_public = ephemeral.public_key();
        self.local_sender_index = Some(sender_index);
        self.local_ephemeral = Some(ephemeral);

        self.chain_key = kdf1(&self.chain_key, ephemeral_public.as_bytes());
        self.hash = mix_hash(&self.hash, ephemeral_public.as_bytes());

        let local_ephemeral = self
            .local_ephemeral
            .as_ref()
            .ok_or(HandshakeError::MissingLocalEphemeral)?;
        let ephemeral_shared = local_ephemeral.diffie_hellman(&remote_ephemeral);
        self.chain_key = kdf1(&self.chain_key, &ephemeral_shared);

        let static_shared = local_ephemeral.diffie_hellman(&self.peer_static);
        self.chain_key = kdf1(&self.chain_key, &static_shared);

        let (new_chain_key, tau, temp_key) = kdf3(&self.chain_key, self.preshared_key.as_bytes());
        self.chain_key = new_chain_key;
        self.hash = mix_hash(&self.hash, &tau);

        let encrypted_nothing = aead_encrypt(&temp_key, 0, &[], &self.hash)?;
        let encrypted_nothing: [u8; 16] = encrypted_nothing.try_into().unwrap();
        self.hash = mix_hash(&self.hash, &encrypted_nothing);

        let mut message = MessageResponse {
            sender: sender_index,
            receiver: remote_sender_index,
            ephemeral: *ephemeral_public.as_bytes(),
            encrypted_nothing,
            mac1: [0u8; 16],
            mac2: [0u8; 16],
        };
        message.update_mac1(&self.peer_static)?;
        self.phase = HandshakePhase::ResponseCreated;

        Ok(message)
    }

    fn reset_for_outgoing_initiation(&mut self) {
        self.clear_ephemeral_state();
        self.chain_key = initial_chain_key();
        self.hash = mix_hash(&initial_hash(), self.peer_static.as_bytes());
        self.phase = HandshakePhase::Zeroed;
    }

    fn reset_for_incoming_initiation(&mut self) {
        self.clear_ephemeral_state();
        self.chain_key = initial_chain_key();
        self.hash = mix_hash(&initial_hash(), self.local_static.public_key().as_bytes());
        self.phase = HandshakePhase::Zeroed;
    }

    fn clear_ephemeral_state(&mut self) {
        self.chain_key.zeroize();
        self.local_ephemeral = None;
        self.remote_ephemeral = None;
        self.local_sender_index = None;
        self.remote_sender_index = None;
    }
}

impl Drop for HandshakeState {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        self.precomputed_static_static.zeroize();
    }
}

impl ZeroizeOnDrop for HandshakeState {}

fn random_u32() -> u32 {
    OsRng.next_u32()
}

#[cfg(test)]
mod tests {
    use super::{ConsumedInitiation, HandshakeError, HandshakePhase, HandshakeState};
    use crate::noise::{
        crypto::{TIMESTAMP_LEN, kdf1, kdf2, mix_hash},
        types::{NoiseEphemeralKey, NoisePresharedKey, NoisePrivateKey},
    };
    use tai64::Tai64N;
    use x25519_dalek::StaticSecret;

    fn fixed_ephemeral(seed: u8) -> NoiseEphemeralKey {
        NoiseEphemeralKey::new(StaticSecret::from([seed; 32]))
    }

    fn fixed_timestamp(seconds_offset: u64) -> [u8; TIMESTAMP_LEN] {
        (Tai64N::UNIX_EPOCH + std::time::Duration::from_secs(seconds_offset)).to_bytes()
    }

    #[test]
    fn initiation_intermediate_state_matches_on_both_sides() {
        let initiator_static = NoisePrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let responder_static = NoisePrivateKey::from_bytes(&[2u8; 32]).unwrap();
        let initiator_public = initiator_static.public_key();
        let responder_public = responder_static.public_key();

        let mut initiator = HandshakeState::new_initiator(
            initiator_static,
            responder_public,
            NoisePresharedKey::zero(),
        );
        let mut responder = HandshakeState::new_responder(
            responder_static,
            initiator_public,
            NoisePresharedKey::zero(),
        );

        let ephemeral = fixed_ephemeral(3);
        let ephemeral_public = ephemeral.public_key();

        initiator.reset_for_outgoing_initiation();
        initiator.chain_key = kdf1(&initiator.chain_key, ephemeral_public.as_bytes());
        initiator.hash = mix_hash(&initiator.hash, ephemeral_public.as_bytes());
        let initiator_shared = ephemeral.diffie_hellman(&initiator.peer_static);
        let (initiator_chain_key, initiator_temp_key) =
            kdf2(&initiator.chain_key, &initiator_shared);

        responder.reset_for_incoming_initiation();
        responder.chain_key = kdf1(&responder.chain_key, ephemeral_public.as_bytes());
        responder.hash = mix_hash(&responder.hash, ephemeral_public.as_bytes());
        let responder_shared = responder.local_static.diffie_hellman(&ephemeral_public);
        let (responder_chain_key, responder_temp_key) =
            kdf2(&responder.chain_key, &responder_shared);

        assert_eq!(initiator.hash, responder.hash);
        assert_eq!(initiator_chain_key, responder_chain_key);
        assert_eq!(initiator_temp_key, responder_temp_key);
    }

    #[test]
    fn full_handshake_derives_matching_transport_keys() {
        let initiator_static = NoisePrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let responder_static = NoisePrivateKey::from_bytes(&[2u8; 32]).unwrap();
        let initiator_public = initiator_static.public_key();
        let responder_public = responder_static.public_key();

        let mut initiator = HandshakeState::new_initiator(
            initiator_static,
            responder_public,
            NoisePresharedKey::zero(),
        );
        let mut responder = HandshakeState::new_responder(
            responder_static,
            initiator_public,
            NoisePresharedKey::zero(),
        );

        initiator.reset_for_outgoing_initiation();
        let initiation = initiator
            .create_message_initiation_inner(11, fixed_ephemeral(3), fixed_timestamp(10))
            .unwrap();
        let consumed = responder.consume_message_initiation(&initiation).unwrap();
        assert_eq!(
            consumed,
            ConsumedInitiation {
                sender_index: 11,
                remote_static: initiator_public,
                timestamp: Tai64N::from_slice(&fixed_timestamp(10)).unwrap(),
            }
        );

        let response = responder
            .create_message_response_inner(22, fixed_ephemeral(4))
            .unwrap();
        initiator.consume_message_response(&response).unwrap();

        let initiator_session = initiator.begin_symmetric_session().unwrap();
        let responder_session = responder.begin_symmetric_session().unwrap();

        assert_eq!(initiator_session.send_key, responder_session.receive_key);
        assert_eq!(initiator_session.receive_key, responder_session.send_key);
        assert_eq!(initiator_session.local_index, 11);
        assert_eq!(initiator_session.remote_index, 22);
        assert_eq!(responder_session.local_index, 22);
        assert_eq!(responder_session.remote_index, 11);
        assert_eq!(initiator.phase(), HandshakePhase::SessionEstablished);
        assert_eq!(responder.phase(), HandshakePhase::SessionEstablished);
    }

    #[test]
    fn responder_rejects_replayed_timestamp() {
        let initiator_static = NoisePrivateKey::from_bytes(&[9u8; 32]).unwrap();
        let responder_static = NoisePrivateKey::from_bytes(&[8u8; 32]).unwrap();
        let initiator_public = initiator_static.public_key();
        let responder_public = responder_static.public_key();

        let mut initiator = HandshakeState::new_initiator(
            initiator_static,
            responder_public,
            NoisePresharedKey::zero(),
        );
        let mut responder = HandshakeState::new_responder(
            responder_static,
            initiator_public,
            NoisePresharedKey::zero(),
        );

        initiator.reset_for_outgoing_initiation();
        let first = initiator
            .create_message_initiation_inner(1, fixed_ephemeral(5), fixed_timestamp(20))
            .unwrap();
        responder.consume_message_initiation(&first).unwrap();

        initiator.reset_for_outgoing_initiation();
        let replay = initiator
            .create_message_initiation_inner(2, fixed_ephemeral(6), fixed_timestamp(20))
            .unwrap();
        let err = responder.consume_message_initiation(&replay).unwrap_err();

        assert!(matches!(err, HandshakeError::ReplayedTimestamp));
    }

    #[test]
    fn initiator_rejects_response_for_another_receiver_index() {
        let initiator_static = NoisePrivateKey::from_bytes(&[4u8; 32]).unwrap();
        let responder_static = NoisePrivateKey::from_bytes(&[5u8; 32]).unwrap();
        let initiator_public = initiator_static.public_key();
        let responder_public = responder_static.public_key();

        let mut initiator = HandshakeState::new_initiator(
            initiator_static,
            responder_public,
            NoisePresharedKey::zero(),
        );
        let mut responder = HandshakeState::new_responder(
            responder_static,
            initiator_public,
            NoisePresharedKey::zero(),
        );

        initiator.reset_for_outgoing_initiation();
        let initiation = initiator
            .create_message_initiation_inner(77, fixed_ephemeral(10), fixed_timestamp(30))
            .unwrap();
        responder.consume_message_initiation(&initiation).unwrap();

        let mut response = responder
            .create_message_response_inner(88, fixed_ephemeral(11))
            .unwrap();
        response.receiver ^= 1;
        response.update_mac1(&initiator_public).unwrap();

        let err = initiator.consume_message_response(&response).unwrap_err();
        assert!(matches!(err, HandshakeError::UnexpectedReceiverIndex));
    }
}
