use rand;
use base64::prelude::*;
use x25519_dalek::{StaticSecret, PublicKey};
use serde_bytes::ByteBuf;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

pub struct Encryption {
    priv_key: StaticSecret,
    pub_key: PublicKey,
}

impl Encryption {
    /// Constructor
    pub fn new() -> Encryption {
        let rng = rand::thread_rng();

        let priv_key = StaticSecret::random_from_rng(rng);
        let pub_key = PublicKey::from(&priv_key);

        Encryption {
            priv_key,
            pub_key
        }
    }

    pub fn get_pub_key_byte (&self) -> ByteBuf {
        ByteBuf::from(self.pub_key.to_bytes())
    }

    pub fn get_session_key (&self, client_pub_key_b64: String) -> ByteBuf {
        let client_pub_key = BASE64_STANDARD.decode(client_pub_key_b64)
            .expect("Failed to decode client public key");

        let client_pub_key_bytes: [u8; 32] = client_pub_key[..32]
            .try_into()
            .expect("Failed to decode client public key");

        let client_pub_key = PublicKey::from(client_pub_key_bytes);
        let session_key = self.priv_key.diffie_hellman(&client_pub_key);
        ByteBuf::from(session_key.to_bytes())
    }

    pub fn decrypt (encrypted_payload: String, session_key: &ByteBuf) -> String {
        let parts: Vec<&str> = encrypted_payload.split(":")
            .collect();

        let nonce_b64 = parts[0];
        let ciphertext_b64 = parts[1];

        let nonce = BASE64_STANDARD.decode(nonce_b64)
            .expect("Failed to decode nonce");
        let ciphertext = BASE64_STANDARD.decode(ciphertext_b64)
            .expect("Failed to decode ciphertext");

        let cipher = Aes256Gcm::new_from_slice(&session_key.as_slice())
            .expect("Failed to create cipher");
        
        let decrypted_vec = cipher.decrypt(Nonce::from_slice(nonce.as_slice()), ciphertext.as_slice())
            .expect("Failed to decrypt ciphertext");

        String::from_utf8(decrypted_vec)
            .expect("Failed to decode ciphertext")
    }

    pub fn encrypt (plaintext: String, session_key: &ByteBuf) -> String {
        let rng = rand::thread_rng();

        let nonce = Aes256Gcm::generate_nonce(rng);

        let cipher = Aes256Gcm::new_from_slice(&session_key.as_slice())
            .expect("Failed to create cipher");
        
        let ciphertext = cipher.encrypt(Nonce::from_slice(nonce.as_slice()), plaintext.as_bytes())
            .expect("Failed to encrypt plaintext");

        let ciphertext_b64 = BASE64_STANDARD.encode(ciphertext);
        let nonce_b64 = BASE64_STANDARD.encode(nonce);

        format!("{}:{}", nonce_b64, ciphertext_b64)
    }
}
