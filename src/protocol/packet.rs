// src/protocol/packet.rs
use crate::error::VpnError;
use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PacketType {
    Data = 0,
    Keepalive = 1,
    Control = 2,
}

impl TryFrom<u8> for PacketType {
    type Error = VpnError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        println!("PacketType::try_from: value: {}", value);
        match value {
            0 => Ok(PacketType::Data),
            1 => Ok(PacketType::Keepalive),
            2 => Ok(PacketType::Control),
            _ => Err(VpnError::Protocol(format!(
                "Invalid packet type: {}",
                value
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ControlType {
    ConfigRequest = 0,
    ConfigResponse = 1,
    RouteUpdate = 2,
    Disconnect = 3,
}

impl TryFrom<u8> for ControlType {
    type Error = VpnError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ControlType::ConfigRequest),
            1 => Ok(ControlType::ConfigResponse),
            2 => Ok(ControlType::RouteUpdate),
            3 => Ok(ControlType::Disconnect),
            _ => Err(VpnError::Protocol(format!(
                "Invalid control type: {}",
                value
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VpnPacket {
    pub source_ip: [u8; 4],
    pub dest_ip: [u8; 4],
    pub packet_type: PacketType,
    pub control_type: Option<ControlType>,
    pub payload: Vec<u8>,
}

impl VpnPacket {
    pub fn new_data(source_ip: [u8; 4], dest_ip: [u8; 4], payload: Vec<u8>) -> Self {
        Self {
            source_ip,
            dest_ip,
            packet_type: PacketType::Data,
            control_type: None,
            payload,
        }
    }

    pub fn new_keepalive() -> Self {
        Self {
            source_ip: [0u8; 4],
            dest_ip: [0u8; 4],
            packet_type: PacketType::Keepalive,
            control_type: None,
            payload: Vec::new(),
        }
    }

    pub fn new_control(control_type: ControlType) -> Self {
        Self {
            source_ip: [0; 4],
            dest_ip: [0; 4],
            packet_type: PacketType::Control,
            control_type: Some(control_type),
            payload: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(10 + self.payload.len());

        // Add source and dest IPs
        bytes.extend_from_slice(&self.source_ip);
        bytes.extend_from_slice(&self.dest_ip);

        // Add packet type
        bytes.push(self.packet_type as u8);

        // Add control type if present
        match self.control_type {
            Some(ct) => bytes.push(ct as u8),
            None => bytes.push(0),
        }

        // Add payload
        bytes.extend_from_slice(&self.payload);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VpnError> {
        if bytes.len() < 10 {
            return Err(VpnError::Protocol("Packet too short".into()));
        }

        let mut source_ip = [0u8; 4];
        let mut dest_ip = [0u8; 4];
        source_ip.copy_from_slice(&bytes[0..4]);
        dest_ip.copy_from_slice(&bytes[4..8]);

        let packet_type = PacketType::try_from(bytes[8])?;
        let control_type = if packet_type == PacketType::Control {
            Some(ControlType::try_from(bytes[9])?)
        } else {
            None
        };

        let payload = bytes[10..].to_vec();

        Ok(Self {
            source_ip,
            dest_ip,
            packet_type,
            control_type,
            payload,
        })
    }

    pub fn is_keepalive(&self) -> bool {
        self.packet_type == PacketType::Keepalive
    }

    pub fn is_control(&self) -> bool {
        self.packet_type == PacketType::Control
    }

    pub fn control_type(&self) -> Option<ControlType> {
        self.control_type
    }

    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    pub fn set_source_ip(&mut self, ip: [u8; 4]) {
        self.source_ip = ip;
    }

    pub fn set_dest_ip(&mut self, ip: [u8; 4]) {
        self.dest_ip = ip;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_serialization() {
        let packet =
            VpnPacket::new_data([192, 168, 1, 1], [192, 168, 1, 2], b"test payload".to_vec());

        let bytes = packet.to_bytes();
        let decoded = VpnPacket::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.source_ip, packet.source_ip);
        assert_eq!(decoded.dest_ip, packet.dest_ip);
        assert_eq!(decoded.packet_type, packet.packet_type);
        assert_eq!(decoded.payload, packet.payload);
    }

    #[test]
    fn test_control_packet() {
        let packet = VpnPacket::new_control(ControlType::ConfigRequest);
        assert!(packet.is_control());
        assert_eq!(packet.control_type(), Some(ControlType::ConfigRequest));
    }

    #[test]
    fn test_keepalive_packet() {
        let packet = VpnPacket::new_keepalive();
        assert!(packet.is_keepalive());
        assert_eq!(packet.payload.len(), 0);
    }
}
