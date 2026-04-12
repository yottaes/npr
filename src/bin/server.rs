use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    println!("starting the server...");
    let socket = UdpSocket::bind("0.0.0.0:5000")
        .await
        .expect("unable to bind a port");
    println!("listening for UDP on 0.0.0.0:5000");

    let mut buf = [0; 4096];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((amount, src_addr)) => {
                println!("Got {} bytes via UDP from {}!", amount, src_addr);
            }
            Err(e) => eprintln!("Receiving error: {}", e),
        }
    }
}
