use ark_bls12_381::Fr as F;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use crate::crypto::{blake2b_hash, derive_memo_key};

/// Encrypted memo with authentication
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedMemo {
    /// Ciphertext (encrypted memo)
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; 12],
    /// Ephemeral public key for ECDH (optional, for asymmetric)
    pub ephemeral_pk: Option<Vec<u8>>,
}

/// Memo encryption/decryption functionality
pub struct MemoEncryption;

impl MemoEncryption {
    /// Encrypt a memo using a shared secret
    pub fn encrypt(plaintext: &[u8], shared_secret: &[u8; 32]) -> Result<EncryptedMemo, String> {
        // Derive encryption key from shared secret
        let key_bytes = derive_memo_key(shared_secret);
        let key = Key::from_slice(&key_bytes);
        
        // Generate random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        // Create cipher
        let cipher = ChaCha20Poly1305::new(key);
        
        // Encrypt
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Convert nonce to array
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(nonce.as_slice());
        
        Ok(EncryptedMemo {
            ciphertext,
            nonce: nonce_bytes,
            ephemeral_pk: None,
        })
    }
    
    /// Decrypt a memo using a shared secret
    pub fn decrypt(encrypted: &EncryptedMemo, shared_secret: &[u8; 32]) -> Result<Vec<u8>, String> {
        // Derive decryption key from shared secret
        let key_bytes = derive_memo_key(shared_secret);
        let key = Key::from_slice(&key_bytes);
        
        // Create cipher
        let cipher = ChaCha20Poly1305::new(key);
        
        // Decrypt
        let nonce = Nonce::from_slice(&encrypted.nonce);
        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        Ok(plaintext)
    }
    
    /// Compute memo hash for inclusion in note
    pub fn compute_memo_hash(encrypted: &EncryptedMemo) -> F {
        // Hash the ciphertext and nonce
        let mut input = Vec::new();
        input.extend_from_slice(&encrypted.ciphertext);
        input.extend_from_slice(&encrypted.nonce);
        
        if let Some(ref epk) = encrypted.ephemeral_pk {
            input.extend_from_slice(epk);
        }
        
        let hash = blake2b_hash(&input);
        crate::utils::bytes_to_field(&hash)
    }
    
    /// Create a shared secret from sender and receiver keys (simplified)
    /// In production, use proper ECDH
    pub fn derive_shared_secret(sender_key: &F, receiver_key: &F) -> [u8; 32] {
        // Simplified: just hash the two keys together
        // In production, use proper ECDH key agreement
        let hash = crate::crypto::poseidon_hash(&[*sender_key, *receiver_key]);
        let mut secret = [0u8; 32];
        let bytes = crate::utils::field_to_bytes(&hash);
        let len = bytes.len().min(32);
        secret[..len].copy_from_slice(&bytes[..len]);
        secret
    }
}

/// Memo structure before encryption
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Memo {
    /// Sender address/identifier
    pub sender: F,
    /// Recipient address/identifier  
    pub recipient: F,
    /// Message content
    pub message: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Optional metadata
    pub metadata: Vec<u8>,
}

impl Memo {
    /// Create a new memo
    pub fn new(sender: F, recipient: F, message: Vec<u8>) -> Self {
        Self {
            sender,
            recipient,
            message,
            timestamp: 0, // Set by caller
            metadata: vec![],
        }
    }
    
    /// Serialize memo to bytes for encryption
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Add sender (31 bytes, field_to_bytes returns exactly 31)
        let sender_bytes = crate::utils::field_to_bytes(&self.sender);
        bytes.extend_from_slice(&sender_bytes);
        
        // Add recipient (31 bytes)
        let recipient_bytes = crate::utils::field_to_bytes(&self.recipient);
        bytes.extend_from_slice(&recipient_bytes);
        
        // Add timestamp (8 bytes)
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        
        // Add message length (4 bytes) and message
        bytes.extend_from_slice(&(self.message.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.message);
        
        // Add metadata length (4 bytes) and metadata
        bytes.extend_from_slice(&(self.metadata.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.metadata);
        
        bytes
    }
    
    /// Deserialize memo from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 74 {
            return Err("Memo too short".to_string());
        }
        
        let mut offset = 0;
        
        // Read sender (31 bytes - field_to_bytes returns exactly 31)
        let sender = crate::utils::bytes_to_field(&bytes[offset..offset + 31]);
        offset += 31;
        
        // Read recipient (31 bytes)
        let recipient = crate::utils::bytes_to_field(&bytes[offset..offset + 31]);
        offset += 31;
        
        // Read timestamp (8 bytes)
        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.copy_from_slice(&bytes[offset..offset + 8]);
        let timestamp = u64::from_le_bytes(timestamp_bytes);
        offset += 8;
        
        // Read message length (4 bytes)
        let mut msg_len_bytes = [0u8; 4];
        msg_len_bytes.copy_from_slice(&bytes[offset..offset + 4]);
        let msg_len = u32::from_le_bytes(msg_len_bytes) as usize;
        offset += 4;
        
        // Read message
        if offset + msg_len > bytes.len() {
            return Err("Invalid message length".to_string());
        }
        let message = bytes[offset..offset + msg_len].to_vec();
        offset += msg_len;
        
        // Read metadata length (4 bytes)
        if offset + 4 > bytes.len() {
            return Err("Missing metadata length".to_string());
        }
        let mut meta_len_bytes = [0u8; 4];
        meta_len_bytes.copy_from_slice(&bytes[offset..offset + 4]);
        let meta_len = u32::from_le_bytes(meta_len_bytes) as usize;
        offset += 4;
        
        // Read metadata
        if offset + meta_len > bytes.len() {
            return Err("Invalid metadata length".to_string());
        }
        let metadata = bytes[offset..offset + meta_len].to_vec();
        
        Ok(Self {
            sender,
            recipient,
            message,
            timestamp,
            metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memo_encryption() {
        // Create a test memo with deterministic values
        let sender = F::from(111111u64);
        let recipient = F::from(222222u64);
        let message = b"Hello, this is a secret message!".to_vec();
        
        let memo = Memo::new(sender, recipient, message.clone());
        let plaintext = memo.to_bytes();
        
        // Generate shared secret with deterministic values
        let sender_key = F::from(333333u64);
        let receiver_key = F::from(444444u64);
        let shared_secret = MemoEncryption::derive_shared_secret(&sender_key, &receiver_key);
        
        // Encrypt
        let encrypted = MemoEncryption::encrypt(&plaintext, &shared_secret).unwrap();
        
        // Verify ciphertext is different from plaintext
        assert_ne!(encrypted.ciphertext, plaintext);
        
        // Decrypt
        let decrypted = MemoEncryption::decrypt(&encrypted, &shared_secret).unwrap();
        assert_eq!(decrypted, plaintext);
        
        // Verify decrypted memo matches original
        let recovered_memo = Memo::from_bytes(&decrypted).unwrap();
        assert_eq!(recovered_memo.sender, sender);
        assert_eq!(recovered_memo.recipient, recipient);
        assert_eq!(recovered_memo.message, message);
    }

    #[test]
    fn test_memo_hash() {
        let shared_secret = [42u8; 32];
        let plaintext = b"Test memo content";
        
        let encrypted1 = MemoEncryption::encrypt(plaintext, &shared_secret).unwrap();
        let hash1 = MemoEncryption::compute_memo_hash(&encrypted1);
        
        // Same content with same key should give different hash (due to random nonce)
        let encrypted2 = MemoEncryption::encrypt(plaintext, &shared_secret).unwrap();
        let hash2 = MemoEncryption::compute_memo_hash(&encrypted2);
        
        // Hashes should be different due to different nonces
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_memo_serialization() {
        // Use deterministic values that fit in 31 bytes
        let sender = F::from(1234567890u64);
        let recipient = F::from(9876543210u64);
        
        let mut memo = Memo::new(sender, recipient, b"Test message".to_vec());
        memo.timestamp = 1234567890;
        memo.metadata = b"metadata".to_vec();
        
        let bytes = memo.to_bytes();
        let recovered = Memo::from_bytes(&bytes).unwrap();
        
        assert_eq!(recovered.sender, memo.sender);
        assert_eq!(recovered.recipient, memo.recipient);
        assert_eq!(recovered.message, memo.message);
        assert_eq!(recovered.timestamp, memo.timestamp);
        assert_eq!(recovered.metadata, memo.metadata);
    }

    #[test]
    fn test_decryption_fails_with_wrong_key() {
        let shared_secret = [1u8; 32];
        let wrong_secret = [2u8; 32];
        let plaintext = b"Secret message";
        
        let encrypted = MemoEncryption::encrypt(plaintext, &shared_secret).unwrap();
        
        // Decryption with wrong key should fail
        let result = MemoEncryption::decrypt(&encrypted, &wrong_secret);
        assert!(result.is_err());
    }
}