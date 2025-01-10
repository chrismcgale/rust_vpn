use crate::error::VpnError;
use crate::protocol::ControlType;
use crate::protocol::PacketType;
use crate::protocol::VpnPacket;
use crate::EncryptionManager;

#[derive(Clone)]
pub struct ProtocolHandler {
    encryption: EncryptionManager,
}

impl ProtocolHandler {
    pub fn new(encryption: EncryptionManager) -> Self {
        Self { encryption }
    }

    pub fn pack(&self, packet: VpnPacket) -> Result<Vec<u8>, VpnError> {
        let mut data = Vec::new();
        data.extend_from_slice(&packet.source_ip);
        data.extend_from_slice(&packet.dest_ip);
        data.push(packet.packet_type as u8);
        data.push(packet.control_type.unwrap_or(ControlType::ConfigRequest) as u8);
        data.extend_from_slice(&packet.payload);

        self.encryption.encrypt(&data)
    }

    pub fn unpack(&self, data: &[u8]) -> Result<VpnPacket, VpnError> {
        let decrypted = self.encryption.decrypt(data)?;

        if decrypted.len() < 8 {
            return Err("Invalid packet size".into());
        }

        let mut source_ip = [0u8; 4];
        let mut dest_ip = [0u8; 4];
        source_ip.copy_from_slice(&decrypted[0..4]);
        dest_ip.copy_from_slice(&decrypted[4..8]);
        let payload = decrypted[10..].to_vec();

        // Extract and validate packet type
        let packet_type = PacketType::try_from(decrypted[8])
            .map_err(|_| VpnError::Protocol("Invalid packet type".into()))?;

        // Extract and validate control type if present
        let control_type = if packet_type == PacketType::Control {
            Some(
                ControlType::try_from(decrypted[9])
                    .map_err(|_| VpnError::Protocol("Invalid control type".into()))?,
            )
        } else {
            None
        };

        Ok(VpnPacket {
            source_ip,
            dest_ip,
            packet_type,
            control_type,
            payload,
        })
    }
}
