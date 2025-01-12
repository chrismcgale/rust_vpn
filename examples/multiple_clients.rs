use rust_vpn::error::Result;
use rust_vpn::{
    error::VpnError, protocol::VpnPacket, vpn_client::VpnClient, vpn_service::VpnConfig,
    vpn_service::VpnService,
};
//use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

fn run_server(bind_addr: &str, encryption_key: [u8; 32], config: VpnConfig) -> Result<VpnService> {
    println!("\n=== SERVER STARTING ===");
    println!("Binding to address: {}", bind_addr);
    println!(
        "Config: MTU={}, Keepalive={}s, Reconnect attempts={}",
        config.mtu,
        config.keepalive_interval.as_secs(),
        config.reconnect_attempts
    );

    let mut vpn = VpnService::new(bind_addr, encryption_key, Some(config))?;

    vpn.start()?;

    Ok(vpn)
}

fn run_client(
    server_addr: &str,
    encryption_key: [u8; 32],
    config: VpnConfig,
    id: i32,
) -> Result<()> {
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

    let res1 = match client.send_packet(test_packet) {
        Ok(response) => {
            println!("Client: Received response:");
            println!("  Type: {:?}", response.packet_type);
            println!("  Source IP: {:?}", response.source_ip);
            println!("  Dest IP: {:?}", response.dest_ip);
            println!("  Payload: {}", String::from_utf8_lossy(&response.payload));
            Ok(())
        }
        Err(e) => {
            eprintln!("Client {} : Failed to send/receive packet: {:?}", id, e);
            Err(e)
        }
    };

    let res2 = client.disconnect();
    res1.and(res2)
}

#[tokio::main]
async fn main() -> Result<()> {
    let server_addr = "127.0.0.1:8080";
    let encryption_key = [1u8; 32]; // Using a simple key for testing

    // Create VPN configuration
    let config = VpnConfig {
        mtu: 1500,
        keepalive_interval: Duration::from_secs(30),
        reconnect_attempts: 3,
    };

    // Start server in a separate thread
    let server_addr = server_addr;
    let server_config = config.clone();
    let mut vpn = run_server(&server_addr.to_string(), encryption_key, server_config)?;

    println!("Waiting for server to start...");
    thread::sleep(Duration::from_secs(2));

    // Run client
    println!("Starting client...");
    for i in 0..3 {
        match run_client(server_addr, encryption_key, config.clone(), i) {
            Ok(_) => println!("Client test {} completed successfully!", i),
            Err(e) => eprintln!("Client error: {:?}", e),
        }
    }

    // Wait a bit before shutting down
    thread::sleep(Duration::from_secs(2));
    println!("Shutdown");
    vpn.shutdown()?;
    println!("Server thread joined, exiting");

    Ok(())
}
