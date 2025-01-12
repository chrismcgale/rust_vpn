use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use crate::{
    error::VpnError,
    network::tcp_server::TcpServer,
    protocol::{ControlType, PacketType, ProtocolHandler, VpnPacket},
};

use crate::vpn_service::RouteEntry;
use crate::vpn_service::VpnConfig;

#[derive(Clone)]
pub struct ConnectionManager {
    server: TcpServer,
    protocol_handler: ProtocolHandler,
    connections: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
}

#[derive(Clone)]
pub struct ConnectionInfo {
    last_seen: Instant,
    connected_since: Instant,
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
}

impl ConnectionInfo {
    fn new() -> Self {
        Self {
            last_seen: Instant::now(),
            connected_since: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
        }
    }

    fn update_stats(&mut self, bytes_sent: u64, bytes_received: u64) {
        self.last_seen = Instant::now();
        self.bytes_sent += bytes_sent;
        self.bytes_received += bytes_received;
        self.packets_sent += 1;
        self.packets_received += 1;
    }
}

impl ConnectionManager {
    pub fn new(server: TcpServer, protocol_handler: ProtocolHandler) -> Result<Self, VpnError> {
        Ok(Self {
            server,
            protocol_handler,
            connections: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn start(&self) -> Result<(), VpnError> {
        // Start connection cleanup thread
        self.start_cleanup_thread();

        // Start the main connection handling loop
        self.handle_connections()?;

        Ok(())
    }

    fn start_cleanup_thread(&self) {
        let connections = Arc::clone(&self.connections);
        let server = self.server.clone();

        thread::spawn(move || loop {
            Self::cleanup_stale_connections(&connections, &server);
            thread::sleep(Duration::from_secs(30));
        });
    }

    fn cleanup_stale_connections(
        connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
        server: &TcpServer,
    ) {
        let mut conns = connections.lock().unwrap();
        let timeout = Duration::from_secs(90); // 1 minute timeout

        conns.retain(|client_id, info| {
            let is_active = info.last_seen.elapsed() < timeout;
            if !is_active {
                println!("Removing stale connection: {}", client_id);
                server.remove_client(client_id);
            }
            is_active
        });
    }

    pub fn handle_connections(&self) -> Result<(), VpnError> {
        loop {
            for client_id in self.server.get_client_ids() {
                match self.handle_client_packets(&client_id) {
                    Ok(_) => continue,
                    Err(VpnError::ClientNotFound) => {
                        self.remove_connection(&client_id);
                    }
                    Err(e) => {
                        eprintln!("Error handling client {}: {:?}", client_id, e);
                        if self.is_fatal_error(&e) {
                            self.remove_connection(&client_id);
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn handle_client_packets(&self, client_id: &String) -> Result<(), VpnError> {
        // Read encrypted packet
        let encrypted_packet = self.server.service_read_packet(client_id)?;

        // Decrypt and unpack packet
        let packet = self.protocol_handler.unpack(&encrypted_packet)?;

        // Update connection statistics
        self.update_connection_stats(client_id, encrypted_packet.len() as u64, 0);

        // Handle different packet types
        match packet.packet_type {
            PacketType::Data => self.handle_data_packet(client_id, packet)?,
            PacketType::Keepalive => self.handle_keepalive(client_id)?,
            PacketType::Control => self.handle_control_packet(client_id, packet)?,
        }

        Ok(())
    }

    fn handle_data_packet(&self, client_id: &String, packet: VpnPacket) -> Result<(), VpnError> {
        // Process data packet
        let response = self.process_data_packet(packet)?;

        // Pack and encrypt response
        let encrypted_response = self.protocol_handler.pack(response)?;

        // Send response
        self.server.write_packet(client_id, &encrypted_response)?;

        // Update statistics
        self.update_connection_stats(client_id, 0, encrypted_response.len() as u64);

        Ok(())
    }

    fn handle_keepalive(&self, client_id: &str) -> Result<(), VpnError> {
        // Update last seen timestamp
        if let Some(info) = self.connections.lock().unwrap().get_mut(client_id) {
            info.last_seen = Instant::now();
        }
        Ok(())
    }

    fn handle_control_packet(&self, client_id: &String, packet: VpnPacket) -> Result<(), VpnError> {
        // Handle control packet based on control type
        if let Some(control_type) = packet.control_type {
            match control_type {
                ControlType::ConfigRequest => self.send_config(client_id),
                ControlType::RouteUpdate => self.update_routes(client_id, &packet),
                ControlType::Disconnect => self.handle_disconnect(client_id),
                _ => Err(VpnError::Protocol("Unknown control type".into())),
            }
        } else {
            Err(VpnError::Protocol("Missing control type".into()))
        }
    }

    fn process_data_packet(&self, packet: VpnPacket) -> Result<VpnPacket, VpnError> {
        // For now, just echo back the packet
        Ok(VpnPacket {
            source_ip: packet.dest_ip,
            dest_ip: packet.source_ip,
            packet_type: PacketType::Data,
            control_type: None,
            payload: packet.payload,
        })
    }

    fn update_connection_stats(&self, client_id: &str, bytes_sent: u64, bytes_received: u64) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(info) = connections.get_mut(client_id) {
            info.update_stats(bytes_sent, bytes_received);
        } else {
            connections.insert(client_id.to_string(), ConnectionInfo::new());
        }
    }

    fn remove_connection(&self, client_id: &str) {
        self.connections.lock().unwrap().remove(client_id);
        self.server.remove_client(client_id);
    }

    pub fn get_connection_info(&self, client_id: &str) -> Option<ConnectionInfo> {
        self.connections.lock().unwrap().get(client_id).cloned()
    }

    fn is_fatal_error(&self, error: &VpnError) -> bool {
        matches!(error, VpnError::ClientNotFound | VpnError::Protocol(_))
    }

    fn send_config(&self, client_id: &String) -> Result<(), VpnError> {
        // Create default config
        let config = VpnConfig {
            mtu: 1500,
            keepalive_interval: Duration::from_secs(30),
            reconnect_attempts: 3,
        };

        // Serialize config
        let mut config_data = Vec::new();
        config_data.extend_from_slice(&(config.mtu as u32).to_be_bytes());
        config_data.extend_from_slice(&(config.keepalive_interval.as_secs() as u32).to_be_bytes());
        config_data.extend_from_slice(&config.reconnect_attempts.to_be_bytes());

        // Create config response packet
        let config_packet = VpnPacket {
            source_ip: [0; 4],
            dest_ip: [0; 4],
            packet_type: PacketType::Control,
            control_type: Some(ControlType::ConfigResponse),
            payload: config_data,
        };

        // Pack and send config
        let encrypted_config = self.protocol_handler.pack(config_packet)?;
        self.server.write_packet(client_id, &encrypted_config)?;

        println!("Sent config to client {}", client_id);
        Ok(())
    }

    fn update_routes(&self, client_id: &String, packet: &VpnPacket) -> Result<(), VpnError> {
        // Parse route updates from payload
        let mut routes = Vec::new();
        let payload = &packet.payload;
        let mut offset = 0;

        while offset + 16 <= payload.len() {
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

        // Create acknowledgment packet
        let ack_packet = VpnPacket {
            source_ip: [0; 4],
            dest_ip: [0; 4],
            packet_type: PacketType::Control,
            control_type: Some(ControlType::RouteUpdate),
            payload: vec![1], // Simple ACK
        };

        // Send acknowledgment
        let encrypted_ack = self.protocol_handler.pack(ack_packet)?;
        self.server.write_packet(client_id, &encrypted_ack)?;

        println!("Updated {} routes for client {}", routes.len(), client_id);
        Ok(())
    }

    fn handle_disconnect(&self, client_id: &String) -> Result<(), VpnError> {
        println!("Client {} requesting disconnect", client_id);

        // Send disconnect acknowledgment
        let disconnect_ack = VpnPacket {
            source_ip: [0; 4],
            dest_ip: [0; 4],
            packet_type: PacketType::Control,
            control_type: Some(ControlType::Disconnect),
            payload: Vec::new(),
        };

        let encrypted_ack = self.protocol_handler.pack(disconnect_ack)?;
        self.server.write_packet(client_id, &encrypted_ack)?;

        // Remove client
        self.remove_connection(client_id);

        println!("Client {} disconnected", client_id);
        Ok(())
    }
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        // Clean up all connections
        let client_ids: Vec<String> = self.server.get_client_ids();
        for client_id in client_ids {
            self.remove_connection(&client_id);
        }
    }
}
