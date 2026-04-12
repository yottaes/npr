use std::io::Read;
use tokio::net::UdpSocket;
use tun::Configuration;

#[tokio::main]
async fn main() {
    println!("starting the client...");

    let mut config = Configuration::default();
    config
        .address((10, 0, 0, 2))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .up();

    #[cfg(target_os = "macos")]
    let mut dev = tun::create(&config).expect("failed to lunch TUN. run with again `sudo`");

    let udp_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind the port");
    let server_addr = "127.0.0.1:5000";

    println!("enter: ping -c 1 10.0.0.1");

    let mut buf = [0; 4096];
    loop {
        let amount = dev.read(&mut buf).unwrap();
        println!("client: got ({} bytes). sending to the server...", amount);
        udp_socket
            .send_to(&buf[..amount], server_addr)
            .await
            .expect("UDP failure");
    }
}
