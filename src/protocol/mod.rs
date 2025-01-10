mod handler;
pub mod packet; // Packet structure definition // Protocol handling logic

pub use crate::protocol::packet::VpnPacket;
pub use handler::ProtocolHandler;
pub use packet::{ControlType, PacketType};
