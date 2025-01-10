use crate::error::VpnError;

use std::{
    io::{Read, Write},
    net::TcpStream as StdTcpStream,
    time::Duration,
};

pub struct TcpClient {
    stream: StdTcpStream,
}

impl TcpClient {
    pub fn connect(addr: &str) -> Result<Self, VpnError> {
        let stream = StdTcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(45)))?;
        stream.set_write_timeout(Some(Duration::from_secs(45)))?;

        Ok(Self { stream })
    }

    pub fn client_read_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        // Read length prefix (4 bytes for length)
        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes)?;
        let packet_len = u32::from_be_bytes(len_bytes) as usize;

        // Validate packet length
        if packet_len > 65535 {
            return Err(VpnError::Protocol(format!(
                "Packet too large: {} bytes (max: {})",
                packet_len, 65535
            )));
        }

        // Read packet data
        let mut buffer = vec![0u8; packet_len];
        self.stream.read_exact(&mut buffer)?;

        Ok(buffer)
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        let len_bytes = (packet.len() as u32).to_be_bytes();
        self.stream.write_all(&len_bytes)?;
        self.stream.write_all(packet)?;
        self.stream.flush()?;

        Ok(())
    }

    pub fn try_clone(&self) -> Result<Self, VpnError> {
        Ok(Self {
            stream: self.stream.try_clone()?,
        })
    }
}

impl Clone for TcpClient {
    fn clone(&self) -> Self {
        Self {
            stream: self.stream.try_clone().unwrap(),
        }
    }
}
