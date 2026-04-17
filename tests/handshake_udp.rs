use npr::noise::{
    handshake::HandshakeState,
    protocol::{MessageInitiation, MessageResponse},
    types::{NoisePresharedKey, NoisePrivateKey},
};
use std::io::ErrorKind;
use tokio::net::UdpSocket;

#[tokio::test]
async fn handshake_round_trips_over_udp() {
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

    let initiator_socket = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(socket) => socket,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind initiator UDP socket: {error}"),
    };
    let responder_socket = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(socket) => socket,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind responder UDP socket: {error}"),
    };
    let initiator_addr = initiator_socket.local_addr().unwrap();
    let responder_addr = responder_socket.local_addr().unwrap();

    let initiation = initiator.create_message_initiation().unwrap();
    initiator_socket
        .send_to(&initiation.to_bytes(), responder_addr)
        .await
        .unwrap();

    let mut init_buf = [0u8; MessageInitiation::SIZE];
    let (init_len, init_peer) = responder_socket.recv_from(&mut init_buf).await.unwrap();
    assert_eq!(init_peer, initiator_addr);

    let received_initiation = MessageInitiation::from_bytes(&init_buf[..init_len]).unwrap();
    responder
        .consume_message_initiation(&received_initiation)
        .unwrap();

    let response = responder.create_message_response().unwrap();
    responder_socket
        .send_to(&response.to_bytes(), initiator_addr)
        .await
        .unwrap();

    let mut response_buf = [0u8; MessageResponse::SIZE];
    let (response_len, response_peer) =
        initiator_socket.recv_from(&mut response_buf).await.unwrap();
    assert_eq!(response_peer, responder_addr);

    let received_response = MessageResponse::from_bytes(&response_buf[..response_len]).unwrap();
    initiator
        .consume_message_response(&received_response)
        .unwrap();

    let initiator_session = initiator.begin_symmetric_session().unwrap();
    let responder_session = responder.begin_symmetric_session().unwrap();

    assert_eq!(initiator_session.send_key, responder_session.receive_key);
    assert_eq!(initiator_session.receive_key, responder_session.send_key);
    assert_eq!(
        initiator_session.remote_index,
        responder_session.local_index
    );
    assert_eq!(
        initiator_session.local_index,
        responder_session.remote_index
    );
}
