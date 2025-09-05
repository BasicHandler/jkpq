use std::time::{Instant, Duration};
use anyhow::{Result, bail};

use crate::config::{Config, initialize_module};
use crate::pq_kem::{generate_ephemeral_keypair, perform_encapsulation, perform_decapsulation, KEMSession};
use crate::secure_store::SecureStore;
use crate::crypto::SymmetricCipher;

pub struct SessionManager {
    config: Config,

    own_public_key: Vec<u8>,
    own_secret_key: Vec<u8>,

    peer_public_key: Option<Vec<u8>>,

    shared_secret: Option<SecureStore>,
    symmetric_cipher: Option<SymmetricCipher>,

    last_rotation: Instant,
    data_transferred_kb: usize,

    session_active: bool,
}

impl SessionManager {
    pub fn new() -> Result<Self> {
        let config = initialize_module();
        let (pk, sk) = generate_ephemeral_keypair();

        Ok(Self {
            config,
            own_public_key: pk,
            own_secret_key: sk,
            peer_public_key: None,
            shared_secret: None,
            symmetric_cipher: None,
            last_rotation: Instant::now(),
            data_transferred_kb: 0,
            session_active: false,
        })
    }

    pub fn get_own_public_key(&self) -> &[u8] {
        &self.own_public_key
    }

    /// Start a new session: reset counters and mark active
    pub fn start_session(&mut self) {
        self.session_active = true;
        self.last_rotation = Instant::now();
        self.data_transferred_kb = 0;
    }

    /// End the current session: zeroize secrets and mark inactive
    pub fn end_session(&mut self) {
        self.session_active = false;
        self.shared_secret = None;
        self.symmetric_cipher = None;
        self.peer_public_key = None;
        // Zeroize keys securely if your SecureStore supports it
        // For Vec<u8>, overwrite manually if needed
        self.own_secret_key.fill(0);
        self.data_transferred_kb = 0;
    }

    pub fn client_handshake(&mut self, peer_pk: &[u8], peer_ct: &[u8]) -> Result<()> {
        self.peer_public_key = Some(peer_pk.to_vec());

        let shared = perform_decapsulation(peer_ct, &self.own_secret_key);
        self.shared_secret = Some(shared);

        let secret_bytes = self.shared_secret.as_ref().unwrap().expose();
        self.symmetric_cipher = Some(SymmetricCipher::new(secret_bytes));

        self.start_session();

        Ok(())
    }

    pub fn server_handshake(&mut self, peer_pk: &[u8]) -> Result<Vec<u8>> {
        self.peer_public_key = Some(peer_pk.to_vec());

        let kem_session = perform_encapsulation(peer_pk);
        self.shared_secret = Some(kem_session.shared_secret);

        let secret_bytes = self.shared_secret.as_ref().unwrap().expose();
        self.symmetric_cipher = Some(SymmetricCipher::new(secret_bytes));

        self.start_session();

        Ok(kem_session.ciphertext)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.session_active {
            bail!("Session is not active");
        }
        if let Some(cipher) = &self.symmetric_cipher {
            Ok(cipher.encrypt(plaintext))
        } else {
            bail!("Session not initialized with symmetric cipher");
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.session_active {
            bail!("Session is not active");
        }
        if let Some(cipher) = &self.symmetric_cipher {
            cipher.decrypt(ciphertext)
        } else {
            bail!("Session not initialized with symmetric cipher");
        }
    }

    pub fn record_data_transfer(&mut self, bytes: usize) {
        if self.session_active {
            self.data_transferred_kb += bytes / 1024;
        }
    }

    pub fn should_rotate_keys(&self) -> bool {
        if !self.session_active {
            return false;
        }
        let elapsed = self.last_rotation.elapsed();
        if elapsed >= self.config.rotation_policy.time {
            return true;
        }
        if self.data_transferred_kb >= self.config.rotation_policy.volume_kb {
            return true;
        }
        if self.config.rotation_policy.session_bound {
            // Rotate at session boundary (end_session triggers rotation)
            return false;
        }
        false
    }

    /// Rotate keys and optionally perform handshake if peer key known
    pub fn rotate_keys(&mut self) -> Result<Option<Vec<u8>>> {
        if !self.session_active {
            bail!("Cannot rotate keys when session inactive");
        }

        let (new_pk, new_sk) = generate_ephemeral_keypair();
        self.own_public_key = new_pk;
        self.own_secret_key = new_sk;

        self.shared_secret = None;
        self.symmetric_cipher = None;
        self.last_rotation = Instant::now();
        self.data_transferred_kb = 0;

        if let Some(peer_pk) = &self.peer_public_key {
            let kem_session = perform_encapsulation(peer_pk);
            self.shared_secret = Some(kem_session.shared_secret.clone());
            let secret_bytes = kem_session.shared_secret.expose();
            self.symmetric_cipher = Some(SymmetricCipher::new(secret_bytes));
            Ok(Some(kem_session.ciphertext))
        } else {
            Ok(None)
        }
    }
}
