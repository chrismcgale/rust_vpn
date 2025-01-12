use rust_vpn::error::Result;
use rust_vpn::{
    error::VpnError, protocol::VpnPacket, vpn_client::VpnClient, vpn_service::VpnConfig,
    vpn_service::VpnService,
};
//use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

fn run_server(bind_addr: &str, encryption_key: [u8; 32], config: VpnConfig) -> Result<VpnService> {
    let mut vpn = VpnService::new(bind_addr, encryption_key, Some(config))?;

    vpn.start()?;

    Ok(vpn)
}

fn run_client(server_addr: &str, encryption_key: [u8; 32], config: VpnConfig) -> Result<()> {
    match std::net::TcpStream::connect(server_addr) {
        Ok(_) => println!("Client: Test connection successful"),
        Err(e) => {
            eprintln!("Client: Test connection failed: {}", e);
            return Err(VpnError::Io(e));
        }
    }

    let mut client = match VpnClient::new(server_addr, encryption_key, Some(config)) {
        Ok(client) => {
            println!("Client: VPN client created successfully");
            client
        }
        Err(e) => {
            eprintln!("Client: Failed to create VPN client: {:?}", e);
            return Err(e);
        }
    };

    // Test packet
    let test_packet = VpnPacket::new_data(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        b"Hello, VPN Server!".to_vec(),
    );

    match client.send_packet(test_packet) {
        Ok(response) => {
            println!("Client: Received response:");
            println!("  Type: {:?}", response.packet_type);
            println!("  Source IP: {:?}", response.source_ip);
            println!("  Dest IP: {:?}", response.dest_ip);
            println!("  Payload: {}", String::from_utf8_lossy(&response.payload));
            Ok(())
        }
        Err(e) => {
            eprintln!("Client: Failed to send/receive packet: {:?}", e);
            Err(e)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let server_addr = "127.0.0.1:8080";
    let _peer_addr = "10.0.0.2:51820";
    let encryption_key = [0u8; 32]; // Generate proper key in production
    let config = VpnConfig {
        mtu: 1500,
        keepalive_interval: Duration::from_secs(30),
        reconnect_attempts: 3,
    };

    let mut vpn = run_server(&server_addr.to_string(), encryption_key, config.clone())?;

    println!("Waiting for server to start...");
    thread::sleep(Duration::from_secs(2));

    // Run client
    println!("Starting client...");
    match run_client(server_addr, encryption_key, config) {
        Ok(_) => println!("Client test completed successfully!"),
        Err(e) => eprintln!("Client error: {:?}", e),
    }

    // Wait a bit before shutting down
    thread::sleep(Duration::from_secs(2));

    vpn.shutdown()?;

    Ok(())
}
