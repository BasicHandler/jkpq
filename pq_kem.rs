use pqcrypto_kyber::kyber1024::{
    PublicKey, Ciphertext, SecretKey, SharedSecret,
    encapsulate, decapsulate, keypair,
};

use pqcrypto_traits::kem::{PublicKey as KemPublicKey, Ciphertext as KemCiphertext, SecretKey as KemSecretKey, SharedSecret as KemSharedSecret};
use crate::secure_store::SecureStore;

/// Represents a wrapped KEM session result
pub struct KEMSession {
    pub shared_secret: SecureStore,
    pub ciphertext: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Performs KEM role: Server-side / Initiator
pub fn perform_encapsulation(peer_public_key: &[u8]) -> KEMSession {
    let peer_pk = KemPublicKey::from_bytes(peer_public_key)
        .expect("Invalid Kyber1024 public key");

    let (ciphertext, shared_secret) = encapsulate(&peer_pk);
    let secure = SecureStore::new(shared_secret.as_bytes());

    KEMSession {
        shared_secret: secure,
        ciphertext: ciphertext.as_bytes().to_vec(),
        public_key: vec![], // You can optionally fill this in later
    }
}

/// Performs KEM role: Client-side / Receiver
pub fn perform_decapsulation(ciphertext: &[u8], own_secret_key: &[u8]) -> SecureStore {
    let ct = KemCiphertext::from_bytes(ciphertext)
        .expect("Invalid Kyber1024 ciphertext");
    let sk = KemSecretKey::from_bytes(own_secret_key)
        .expect("Invalid Kyber1024 private key");

    let shared_secret = decapsulate(&ct, &sk);
    SecureStore::new(shared_secret.as_bytes())
}

/// Generates an ephemeral keypair for Kyber1024
pub fn generate_ephemeral_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

