use crate::error::VpnError;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;

#[derive(Clone)]
pub struct EncryptionManager {
    cipher: Aes256Gcm,
}

impl EncryptionManager {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("Invalid key length");
        Self { cipher }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, VpnError> {
        let mut rng = rand::thread_rng();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, data)
            .map_err(|e| VpnError::Encryption(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, VpnError> {
        println!("Decrypting data of length: {}", data.len());
        if data.len() < 12 {
            return Err("Data too short".into());
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| VpnError::Encryption(e.to_string()))?;

        if !plaintext.is_empty() {
            println!(
                "First few bytes of plaintext: {:02x?}",
                &plaintext[..std::cmp::min(4, plaintext.len())]
            );
        }

        Ok(plaintext)
    }
}
