use thiserror::Error;

#[derive(Debug)]
pub enum VpnError {
    Io(std::io::Error),
    Encryption(String),
    Protocol(String),
    Config(String),
    Network(String),
    KeyExchange(String),
    GenericError(String),
    ClientNotFound,
}

impl From<&str> for VpnError {
    fn from(error: &str) -> Self {
        VpnError::GenericError(error.to_string())
    }
}

// Add From implementations for automatic error conversion
impl From<std::io::Error> for VpnError {
    fn from(error: std::io::Error) -> Self {
        VpnError::Io(error)
    }
}

// Optional: Add more From implementations for other error types you might need
impl From<aes_gcm::Error> for VpnError {
    fn from(error: aes_gcm::Error) -> Self {
        VpnError::Encryption(error.to_string())
    }
}

impl From<std::net::AddrParseError> for VpnError {
    fn from(error: std::net::AddrParseError) -> Self {
        VpnError::Protocol(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, VpnError>;
