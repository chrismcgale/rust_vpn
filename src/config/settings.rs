use crate::error::Result;
use crate::VpnError;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct VpnConfig {
    //pub bind_address: SocketAddr,
    //pub tun_name: String,
    pub mtu: usize,
    // pub peers: Vec<PeerConfig>,
    // pub log_level: String,
    pub keepalive_interval: Duration,
    pub reconnect_attempts: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: SocketAddr,
    pub persistent_keepalive: Option<u64>,
}

impl VpnConfig {
    pub fn from_file(path: PathBuf) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let config = serde_json::from_reader(file).map_err(|e| VpnError::Config(e.to_string()))?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        // Implement validation logic
        Ok(())
    }
}
