use std::thread;

use crate::protocol::packet::VpnPacket;
use crate::protocol::ControlType;
use crate::protocol::PacketType;
use crate::vpn::vpn_service::VpnConfig;
use crate::{
    crypto::EncryptionManager, network::tcp_client::TcpClient, protocol::ProtocolHandler, VpnError,
};

use std::sync::{atomic::AtomicBool, Arc};

pub struct VpnClient {
    client: TcpClient,
    protocol_handler: ProtocolHandler,
    config: VpnConfig,
    connected: bool,
    client_thread: Option<thread::JoinHandle<()>>,
    shutdown_flag: Arc<AtomicBool>,
}

impl VpnClient {
    pub fn new(
        server_addr: &str,
        encryption_key: [u8; 32],
        config: Option<VpnConfig>,
    ) -> Result<Self, VpnError> {
        let client = TcpClient::connect(server_addr)?;

        let encryption = EncryptionManager::new(&encryption_key);
        let protocol_handler = ProtocolHandler::new(encryption);
        let config = config.unwrap_or_default();

        let mut vpn_client = Self {
            client,
            protocol_handler,
            config,
            connected: false,
            client_thread: None,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        };

        // Perform initial handshake
        vpn_client.handshake()?;

        Ok(vpn_client)
    }

    fn handshake(&mut self) -> Result<(), VpnError> {
        // Create config request packet
        let config_request: VpnPacket = VpnPacket::new_control(ControlType::ConfigRequest);
        println!("config_request: {:?}", config_request);
        let encrypted_request = self.protocol_handler.pack(config_request)?;

        // Send config request
        self.client.write_packet(&encrypted_request)?;

        // Read response
        let encrypted_response = self.client.client_read_packet()?;

        let response = self.protocol_handler.unpack(&encrypted_response)?;

        // Verify response type
        if response.packet_type != PacketType::Control
            || response.control_type != Some(ControlType::ConfigResponse)
        {
            return Err(VpnError::Protocol("Invalid handshake response".into()));
        }

        // Apply received configuration
        self.apply_config(&response.payload)?;
        self.connected = true;

        // Start keepalive thread
        self.start_keepalive()?;

        Ok(())
    }

    pub fn send_packet(&mut self, packet: VpnPacket) -> Result<VpnPacket, VpnError> {
        if !self.connected {
            return Err(VpnError::Protocol("Not connected".into()));
        }

        // Pack and encrypt the packet
        let encrypted = self.protocol_handler.pack(packet)?;

        // Send packet
        self.client.write_packet(&encrypted)?;

        // Read response
        let encrypted_response = self.client.client_read_packet()?;

        // Decrypt and unpack response
        self.protocol_handler.unpack(&encrypted_response)
    }

    fn apply_config(&mut self, config_data: &[u8]) -> Result<(), VpnError> {
        // Parse and apply configuration from server
        let config = VpnConfig::from_bytes(config_data)?;
        self.config = config;
        Ok(())
    }

    fn start_keepalive(&mut self) -> Result<(), VpnError> {
        let mut client = self.client.clone();
        let protocol_handler = self.protocol_handler.clone();
        let interval = self.config.keepalive_interval;
        let shutdown_flag = self.shutdown_flag.clone();

        self.client_thread = Some(std::thread::spawn(move || {
            while !shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
                let keepalive = VpnPacket::new_keepalive();
                if let Ok(encrypted) = protocol_handler.pack(keepalive) {
                    if client.write_packet(&encrypted).is_err() {
                        break;
                    }
                }
                std::thread::sleep(interval);
            }
        }));

        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<(), VpnError> {
        if self.connected {
            let disconnect_packet = VpnPacket::new_control(ControlType::Disconnect);
            let encrypted = self.protocol_handler.pack(disconnect_packet)?;
            self.client.write_packet(&encrypted)?;
            self.connected = false;
            if let Some(handle) = std::mem::take(&mut self.client_thread) {
                handle.join().unwrap();
            };
        }
        Ok(())
    }
}

impl Drop for VpnClient {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}
