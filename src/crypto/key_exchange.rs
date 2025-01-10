use crate::error::Result;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct KeyExchange {
    private_key: StaticSecret,
    public_key: PublicKey,
}

impl KeyExchange {
    pub fn new() -> Self {
        let private_key = StaticSecret::new(OsRng);
        let public_key = PublicKey::from(&private_key);

        Self {
            private_key,
            public_key,
        }
    }

    pub fn generate_shared_secret(&self, peer_public: &PublicKey) -> [u8; 32] {
        let shared_secret = self.private_key.diffie_hellman(peer_public);
        *shared_secret.as_bytes()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }
}
