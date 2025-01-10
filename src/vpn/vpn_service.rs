use crate::protocol::packet::VpnPacket;
use crate::{
    crypto::EncryptionManager,
    error::VpnError,
    network::tcp_server::TcpServer,
    protocol::{ControlType, PacketType, ProtocolHandler},
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

pub struct VpnService {
    server: TcpServer,
    routes: Arc<Mutex<HashMap<String, Vec<RouteEntry>>>>,
    protocol_handler: ProtocolHandler,
    server_config: VpnConfig,
    client_configs: Arc<Mutex<HashMap<String, VpnConfig>>>,
}

#[derive(Clone, Debug)]
pub struct VpnConfig {
    pub mtu: usize,
    pub keepalive_interval: Duration,
    pub reconnect_attempts: u32,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            keepalive_interval: Duration::from_secs(30),
            reconnect_attempts: 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub target_network: [u8; 4],
    pub network_mask: [u8; 4],
    pub next_hop: [u8; 4],
    pub metric: u32,
}

impl VpnService {
    pub fn new(
        bind_addr: &str,
        encryption_key: [u8; 32],
        config: Option<VpnConfig>,
    ) -> Result<Self, VpnError> {
        // Initialize TCP server
        let server = TcpServer::new(bind_addr)?;

        // Initialize encryption and protocol handler
        let encryption = EncryptionManager::new(&encryption_key);
        let protocol_handler = ProtocolHandler::new(encryption);

        // Initialize shared data structures
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let client_configs = Arc::new(Mutex::new(HashMap::new()));

        // Use provided config or default
        let server_config = config.unwrap_or_default();

        Ok(Self {
            server,
            protocol_handler,
            routes,
            client_configs,
            server_config,
        })
    }

    pub fn start(&self) -> Result<(), VpnError> {
        // Start accepting connections
        self.server.start_accept_loop()?;

        // Start keepalive monitoring
        let keepalive_interval = self.server_config.keepalive_interval;
        let server = self.server.clone();
        thread::spawn(move || loop {
            Self::check_client_keepalive(&server);
            thread::sleep(keepalive_interval);
        });

        // Main service loop
        self.main_loop()
    }

    fn main_loop(&self) -> Result<(), VpnError> {
        loop {
            for client_id in self.server.get_client_ids() {
                match self.handle_client_packet(&client_id) {
                    Ok(_) => continue,
                    Err(VpnError::ClientNotFound) => {
                        self.server.remove_client(&client_id);
                    }
                    Err(e) => {
                        eprintln!("Error handling client {}: {:?}", client_id, e);
                        // Decide whether to remove client based on error type
                        if Self::is_fatal_error(&e) {
                            self.server.remove_client(&client_id);
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn handle_client_packet(&self, client_id: &str) -> Result<(), VpnError> {
        let encrypted_packet = self.server.service_read_packet(client_id)?;

        println!("Received packet from client {}", client_id);

        // Process the packet
        let packet = self.protocol_handler.unpack(&encrypted_packet)?;

        // Handle different packet types
        match packet.packet_type {
            PacketType::Data => self.handle_data_packet(client_id, packet),
            PacketType::Keepalive => self.handle_keepalive(client_id),
            PacketType::Control => {
                match packet
                    .control_type
                    .ok_or(VpnError::Protocol("Missing control type".into()))?
                {
                    ControlType::ConfigRequest => self.send_config(client_id),
                    ControlType::RouteUpdate => self.update_routes(client_id, &packet),
                    ControlType::Disconnect => self.handle_disconnect(client_id),
                    _ => Err(VpnError::Protocol("Unknown control type".into())),
                }
            }
        }
    }

    fn handle_data_packet(&self, client_id: &str, packet: VpnPacket) -> Result<(), VpnError> {
        // Process and route the data packet
        let response_packet = self.process_data_packet(packet)?;

        // Send response back to client
        let encrypted_response = self.protocol_handler.pack(response_packet)?;
        self.server.write_packet(client_id, &encrypted_response)
    }

    fn process_data_packet(&self, packet: VpnPacket) -> Result<VpnPacket, VpnError> {
        // Here you would implement routing logic
        // For now, we'll just echo back
        Ok(VpnPacket {
            source_ip: packet.dest_ip,
            dest_ip: packet.source_ip,
            packet_type: PacketType::Data,
            control_type: packet.control_type,
            payload: packet.payload,
        })
    }

    fn handle_keepalive(&self, client_id: &str) -> Result<(), VpnError> {
        // Update client's last seen timestamp
        self.server.update_client_timestamp(client_id)?;
        Ok(())
    }

    fn handle_control_packet(&self, client_id: &str, packet: VpnPacket) -> Result<(), VpnError> {
        // Handle control messages (configuration, routing updates, etc.)
        match packet.control_type() {
            Some(c_type) => match c_type {
                ControlType::ConfigRequest => self.send_config(client_id),
                ControlType::RouteUpdate => self.update_routes(client_id, &packet),
                ControlType::Disconnect => self.handle_disconnect(client_id),
                _ => Err(VpnError::Protocol("Unknown control packet".into())),
            },
            _ => Err(VpnError::Protocol("Unknown control packet".into())),
        }
    }

    fn check_client_keepalive(server: &TcpServer) {
        let stale_clients = server.get_stale_clients();
        for client_id in stale_clients {
            println!("Removing stale client: {}", client_id);
            server.remove_client(&client_id);
        }
    }

    fn is_fatal_error(error: &VpnError) -> bool {
        matches!(error, VpnError::ClientNotFound | VpnError::Protocol(_))
    }

    fn handle_disconnect(&self, client_id: &str) -> Result<(), VpnError> {
        println!("Client {} requesting disconnect", client_id);

        // Send disconnect acknowledgment
        let disconnect_ack = VpnPacket::new_control(ControlType::Disconnect);
        let encrypted_ack = self.protocol_handler.pack(disconnect_ack)?;
        self.server.write_packet(client_id, &encrypted_ack)?;

        // Remove client from server
        self.server.remove_client(client_id);

        // Clean up client routes
        let mut routes = self.routes.lock().unwrap();
        routes.remove(client_id);

        // Clean up client config
        let mut configs = self.client_configs.lock().unwrap();
        configs.remove(client_id);

        println!("Client {} disconnected", client_id);
        Ok(())
    }

    fn update_routes(&self, client_id: &str, packet: &VpnPacket) -> Result<(), VpnError> {
        // Extract route updates from payload
        let route_updates = self.parse_route_updates(&packet.payload)?;

        // Update routing table for this client
        let mut routes = self.routes.lock().unwrap();
        routes.insert(client_id.to_string(), route_updates.clone());

        // Create acknowledgment packet
        let mut ack_packet = VpnPacket::new_control(ControlType::RouteUpdate);
        ack_packet.set_payload(vec![1]); // Simple ACK

        println!("update");

        // Send acknowledgment
        let encrypted_ack = self.protocol_handler.pack(ack_packet)?;
        self.server.write_packet(client_id, &encrypted_ack)?;

        Ok(())
    }

    fn send_config(&self, client_id: &str) -> Result<(), VpnError> {
        // Create default config if none exists
        let config = {
            let mut configs = self.client_configs.lock().unwrap();
            configs
                .entry(client_id.to_string())
                .or_insert_with(|| VpnConfig {
                    mtu: 1500,
                    keepalive_interval: Duration::from_secs(30),
                    reconnect_attempts: 3,
                })
                .clone()
        };

        // Serialize config
        let config_data = self.serialize_config(&config)?;

        // Create config response packet
        let mut config_packet = VpnPacket::new_control(ControlType::ConfigResponse);
        config_packet.set_payload(config_data);

        println!("config");

        // Send config
        let encrypted_config = self.protocol_handler.pack(config_packet)?;
        self.server.write_packet(client_id, &encrypted_config)?;

        println!("Sent config to client {}", client_id);
        Ok(())
    }

    // Helper function to parse route updates from binary data
    fn parse_route_updates(&self, payload: &[u8]) -> Result<Vec<RouteEntry>, VpnError> {
        if payload.len() % 16 != 0 {
            return Err(VpnError::Protocol(
                "Invalid route update payload length".into(),
            ));
        }

        let mut routes = Vec::new();
        let mut offset = 0;

        while offset < payload.len() {
            let mut network = [0u8; 4];
            let mut mask = [0u8; 4];
            let mut next_hop = [0u8; 4];
            let mut metric_bytes = [0u8; 4];

            network.copy_from_slice(&payload[offset..offset + 4]);
            mask.copy_from_slice(&payload[offset + 4..offset + 8]);
            next_hop.copy_from_slice(&payload[offset + 8..offset + 12]);
            metric_bytes.copy_from_slice(&payload[offset + 12..offset + 16]);

            routes.push(RouteEntry {
                target_network: network,
                network_mask: mask,
                next_hop,
                metric: u32::from_be_bytes(metric_bytes),
            });

            offset += 16;
        }

        Ok(routes)
    }

    // Helper function to serialize config to binary data
    fn serialize_config(&self, config: &VpnConfig) -> Result<Vec<u8>, VpnError> {
        let mut data = Vec::new();

        // MTU (4 bytes)
        data.extend_from_slice(&(config.mtu as u32).to_be_bytes());

        // Keepalive interval in seconds (4 bytes)
        data.extend_from_slice(&(config.keepalive_interval.as_secs() as u32).to_be_bytes());

        // Reconnect attempts (4 bytes)
        data.extend_from_slice(&config.reconnect_attempts.to_be_bytes());

        Ok(data)
    }
}

impl VpnConfig {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VpnError> {
        if bytes.len() < 12 {
            return Err(VpnError::Protocol("Config data too short".into()));
        }

        let mut mtu_bytes = [0u8; 4];
        let mut keepalive_bytes = [0u8; 4];
        let mut reconnect_bytes = [0u8; 4];

        mtu_bytes.copy_from_slice(&bytes[0..4]);
        keepalive_bytes.copy_from_slice(&bytes[4..8]);
        reconnect_bytes.copy_from_slice(&bytes[8..12]);

        Ok(Self {
            mtu: u32::from_be_bytes(mtu_bytes) as usize,
            keepalive_interval: Duration::from_secs(u32::from_be_bytes(keepalive_bytes) as u64),
            reconnect_attempts: u32::from_be_bytes(reconnect_bytes),
        })
    }
}
