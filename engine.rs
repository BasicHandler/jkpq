use crate::config::Config;
use crate::secure_store::SecureStore;
use crate::pq_kem::{generate_ephemeral_keypair, perform_encapsulation, perform_decapsulation, KEMSession};

#[derive(Debug)]
pub enum Engine {
    PQEphemeral,
    #[deprecated]
    LegacyRSA,
    #[deprecated]
    ECC,
}

impl Engine {
    pub fn initialize(_cfg: &Config) -> Self {
        // All configs resolve to PQEphemeral now
        Engine::PQEphemeral
    }

    /// Perform a post-quantum handshake based on ephemeral Kyber1024 KEM
    pub fn perform_handshake(&self, peer_pubkey: &[u8]) -> SessionFrame {
        match self {
            Engine::PQEphemeral => {
                let KEMSession { shared_secret, ciphertext: _, public_key: _ } =
                    perform_encapsulation(peer_pubkey);

                SessionFrame::new(shared_secret)
            }

            #[allow(unreachable_patterns)]
            _ => panic!("Handshake not supported for legacy engine"),
        }
    }

    /// Receive and decapsulate ciphertext to obtain shared secret
    pub fn receive_handshake(&self, ciphertext: &[u8], sk: &[u8]) -> SessionFrame {
        match self {
            Engine::PQEphemeral => {
                let shared_secret = perform_decapsulation(ciphertext, sk);
                SessionFrame::new(shared_secret)
            }
            _ => panic!("Responder path not supported for non-PQ engines"),
        }
    }

    /// Enforces full secure transport using ephemeral Kyber1024 KEM
    /// Always generates ephemeral keypair before performing encapsulation
    pub fn start_secure_transport(&self, peer_pub_key: &[u8]) -> SessionFrame {
        match self {
            Engine::PQEphemeral => {
                let (_ephemeral_pub, _ephemeral_sec) = generate_ephemeral_keypair();

                let KEMSession { shared_secret, ciphertext: _, public_key: _ } =
                    perform_encapsulation(peer_pub_key);

                // You could extend this to expose the ephemeral keys if needed
                SessionFrame::new(shared_secret)
            }

            _ => panic!("Transport not supported for non-PQ engines"),
        }
    }
}

pub struct SessionFrame {
    pub secret: SecureStore,
}

impl SessionFrame {
    pub fn new(secret: SecureStore) -> Self {
        SessionFrame { secret }
    }

    pub fn key(&self) -> &[u8] {
        self.secret.expose()
    }
}
