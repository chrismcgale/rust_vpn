use rust_vpn::error::Result;
use rust_vpn::{
    protocol::VpnPacket, vpn_client::VpnClient, vpn_service::VpnConfig, vpn_service::VpnService,
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
    println!("VPN service created successfully");

    println!("Starting VPN service");
    vpn.start()?;

    Ok(vpn)
}

fn run_client(server_addr: &str, encryption_key: [u8; 32], config: VpnConfig) -> Result<()> {
    println!("\n=== CLIENT STARTING ===");
    println!("Connecting to server: {}", server_addr);

    let mut client = VpnClient::new(server_addr, encryption_key, Some(config))?;
    println!("VPN client created successfully");

    // Test each packet size
    for (size_desc, packet, should_suceed) in create_test_packets() {
        println!("\n=== Testing {} Packet ===", size_desc);
        println!("Sending packet of size {} bytes", packet.payload.len());
        println!(
            "First 20 bytes: {:?}",
            &packet.payload[..20.min(packet.payload.len())]
        );

        match (client.send_packet(packet), should_suceed) {
            (Ok(response), true) => {
                println!("\nReceived {} response:", size_desc);
                println!("Response size: {} bytes", response.payload.len());
                println!(
                    "First 20 bytes: {:?}",
                    &response.payload[..20.min(response.payload.len())]
                );
                println!("✅ {} packet test successful!", size_desc);
            }
            (Err(_e), false) => {
                println!("✅ {} packet test failed as expected!", size_desc);
            }
            (Ok(response), false) => {
                println!("\nReceived {} response:", size_desc);
                println!("Response size: {} bytes", response.payload.len());
                println!(
                    "First 20 bytes: {:?}",
                    &response.payload[..20.min(response.payload.len())]
                );
                println!("❌ {} packet test unexpected success", size_desc);
            }
            (Err(e), true) => {
                println!("❌ {} packet test failed: {:?}", size_desc, e);
                return Err(e);
            }
        }

        // Short delay between packets
        thread::sleep(Duration::from_millis(500));
    }

    println!("\nAll packet tests completed");
    Ok(())
}

fn create_test_packets() -> Vec<(String, VpnPacket, bool)> {
    vec![
        // Small packet (< 100 bytes)
        (
            "Small".to_string(),
            VpnPacket::new_data(
                [192, 168, 1, 1],
                [192, 168, 1, 2],
                "Hello, VPN Server!".as_bytes().to_vec(),
            ),
            true,
        ),
        // Medium packet (~1KB)
        (
            "Medium".to_string(),
            VpnPacket::new_data(
                [192, 168, 1, 1],
                [192, 168, 1, 2],
                vec![b'M'; 1024], // 1KB of 'M' characters
            ),
            true,
        ),
        // Large packet (~64KB)
        (
            "Large".to_string(),
            VpnPacket::new_data(
                [192, 168, 1, 1],
                [192, 168, 1, 2],
                vec![b'L'; 64 * 1024], // 64KB of 'L' characters
            ),
            false,
        ),
    ]
}

fn main() -> Result<()> {
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

    // Give the server time to start
    println!("Waiting for server to initialize (2s)...");
    thread::sleep(Duration::from_secs(2));

    // Run client test
    println!("Starting client test...");
    match run_client(server_addr, encryption_key, config) {
        Ok(_) => println!("\nAll packet size tests completed successfully!"),
        Err(e) => eprintln!("\nPacket size tests failed: {:?}", e),
    }

    // Clean up
    println!("\nTest complete, cleaning up...");
    vpn.shutdown()?;
    println!("Server thread joined, exiting");

    Ok(())
}
