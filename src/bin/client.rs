use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    println!("starting the client...");

    let mut config = tun::Configuration::default();
    config
        .address((10, 0, 0, 2))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .up();

    #[cfg(target_os = "macos")]
    let mut dev = tun::create_as_async(&config).expect("failed to create TUN device, try running with `sudo`");

    let udp_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("failed to bind the port");
    let server_addr = "127.0.0.1:5000";

    println!("enter: ping -c 1 10.0.0.1");

    let mut buf = [0u8; 4096];
    loop {
        let amount = dev.read(&mut buf).await.unwrap();
        println!("client: got ({} bytes). sending to the server...", amount);
        udp_socket
            .send_to(&buf[..amount], server_addr)
            .await
            .expect("UDP failure");
    }
}
