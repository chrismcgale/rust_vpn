use crate::{
    error::VpnError,
    network::tcp_server::TcpServer,
    protocol::{packet::VpnPacket, ControlType, PacketType, ProtocolHandler},
    vpn_service::{RouteEntry, VpnConfig},
};

use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, atomic::Ordering, Arc, Mutex},
    thread,
    time::Duration,
    vec,
};

pub struct VpnWorker {
    server: Arc<Mutex<TcpServer>>,
    routes: Arc<Mutex<HashMap<String, Vec<RouteEntry>>>>,
    protocol_handler: Arc<Mutex<ProtocolHandler>>,
    client_configs: Arc<Mutex<HashMap<String, VpnConfig>>>,
    shutdown_flag: Arc<AtomicBool>,
}

impl VpnWorker {
    pub fn new(
        server: Arc<Mutex<TcpServer>>,
        routes: Arc<Mutex<HashMap<String, Vec<RouteEntry>>>>,
        protocol_handler: Arc<Mutex<ProtocolHandler>>,
        client_configs: Arc<Mutex<HashMap<String, VpnConfig>>>,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Result<Self, VpnError> {
        // Initialize TCP server

        Ok(Self {
            server,
            protocol_handler,
            routes,
            client_configs,
            shutdown_flag,
        })
    }
    pub fn main_loop(&self) -> Result<(), VpnError> {
        while !self.shutdown_flag.load(Ordering::Relaxed) {
            let mut client_ids: Vec<String>;
            {
                client_ids = self.server.lock().expect("Server in use").get_client_ids();
            }
            for client_id in client_ids {
                match self.handle_client_packet(&client_id) {
                    Ok(_) => continue,
                    Err(VpnError::ClientNotFound) => {
                        self.server
                            .lock()
                            .expect("Server in use")
                            .remove_client(&client_id);
                    }
                    Err(e) => {
                        eprintln!("Error handling client {}: {:?}", client_id, e);
                        // Decide whether to remove client based on error type
                        if Self::is_fatal_error(&e) {
                            self.server
                                .lock()
                                .expect("Server in use")
                                .remove_client(&client_id);
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        Ok(())
    }

    fn is_fatal_error(error: &VpnError) -> bool {
        matches!(error, VpnError::ClientNotFound | VpnError::Protocol(_))
    }

    fn handle_client_packet(&self, client_id: &str) -> Result<(), VpnError> {
        println!("Handling packet from client {}", client_id);
        let encrypted_packet = self
            .server
            .lock()
            .expect("Server_in_use")
            .service_read_packet(client_id)?;

        println!("Received packet from client {}", client_id);

        // Process the packet
        let packet = self
            .protocol_handler
            .lock()
            .expect("Protocol in use")
            .unpack(&encrypted_packet)?;

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

    fn handle_keepalive(&self, client_id: &str) -> Result<(), VpnError> {
        // Update client's last seen timestamp
        self.server
            .lock()
            .expect("Server in use")
            .update_client_timestamp(client_id)?;
        Ok(())
    }

    fn handle_disconnect(&self, client_id: &str) -> Result<(), VpnError> {
        println!("Client {} requesting disconnect", client_id);

        // Send disconnect acknowledgment
        let disconnect_ack = VpnPacket::new_control(ControlType::Disconnect);
        let encrypted_ack = self
            .protocol_handler
            .lock()
            .expect("Protocol in use")
            .pack(disconnect_ack)?;
        self.server
            .lock()
            .expect("Server in use")
            .write_packet(client_id, &encrypted_ack)?;

        // Remove client from server
        self.server
            .lock()
            .expect("Server in use")
            .remove_client(client_id);

        // Clean up client routes
        let mut routes = self.routes.lock().unwrap();
        routes.remove(client_id);

        // Clean up client config
        let mut configs = self.client_configs.lock().unwrap();
        configs.remove(client_id);

        println!("Client {} disconnected", client_id);
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

    fn handle_data_packet(&self, client_id: &str, packet: VpnPacket) -> Result<(), VpnError> {
        // Process and route the data packet
        let response_packet = self.process_data_packet(packet)?;

        // Send response back to client
        let encrypted_response = self
            .protocol_handler
            .lock()
            .expect("Protocol in use")
            .pack(response_packet)?;
        self.server
            .lock()
            .expect("Server in use")
            .write_packet(client_id, &encrypted_response)
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

        // Send acknowledgment
        let encrypted_ack = self
            .protocol_handler
            .lock()
            .expect("Protocol in use")
            .pack(ack_packet)?;
        self.server
            .lock()
            .expect("Server in use")
            .write_packet(client_id, &encrypted_ack)?;

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

        // Send config
        let encrypted_config = self
            .protocol_handler
            .lock()
            .expect("Protocol in use")
            .pack(config_packet)?;
        self.server
            .lock()
            .expect("Server in use")
            .write_packet(client_id, &encrypted_config)?;

        println!("Sent config to client {}", client_id);
        Ok(())
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
}
