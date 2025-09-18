use ark_bls12_381::Fr as F;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use crate::crypto::poseidon_hash;

/// Poseidon-based symmetric encryption for field elements
pub struct PoseidonEncryption;

impl PoseidonEncryption {
    /// Encrypt a message (field elements) with a key
    pub fn encrypt(key: &F, nonce: &F, plaintext: &[F]) -> Vec<F> {
        // Derive encryption key using Poseidon
        let enc_key = poseidon_hash(&[*key, *nonce]);
        
        // Create keystream
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut counter = F::from(0u64);
        
        for chunk in plaintext.chunks(1) {
            // Generate keystream block
            let keystream = poseidon_hash(&[enc_key, counter]);
            counter += F::from(1u64);
            
            // XOR with plaintext (field addition)
            for (i, &pt) in chunk.iter().enumerate() {
                if i == 0 {
                    ciphertext.push(pt + keystream);
                }
            }
        }
        
        ciphertext
    }
    
    /// Decrypt a message with a key
    pub fn decrypt(key: &F, nonce: &F, ciphertext: &[F]) -> Vec<F> {
        // Derive decryption key (same as encryption)
        let dec_key = poseidon_hash(&[*key, *nonce]);
        
        // Create keystream and decrypt
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut counter = F::from(0u64);
        
        for chunk in ciphertext.chunks(1) {
            // Generate keystream block
            let keystream = poseidon_hash(&[dec_key, counter]);
            counter += F::from(1u64);
            
            // XOR with ciphertext (field subtraction)
            for (i, &ct) in chunk.iter().enumerate() {
                if i == 0 {
                    plaintext.push(ct - keystream);
                }
            }
        }
        
        plaintext
    }
    
    /// Authenticated encryption with associated data (AEAD)
    pub fn encrypt_aead(key: &F, nonce: &F, plaintext: &[F], associated_data: &[F]) -> (Vec<F>, F) {
        // Compute authentication tag
        let mut auth_input = vec![*key, *nonce];
        auth_input.extend_from_slice(associated_data);
        let auth_tag = poseidon_hash(&auth_input);
        
        // Encrypt with modified key
        let enc_key = poseidon_hash(&[*key, *nonce, auth_tag]);
        let ciphertext = Self::encrypt(&enc_key, &F::from(0u64), plaintext);
        
        (ciphertext, auth_tag)
    }
    
    /// Authenticated decryption with associated data
    pub fn decrypt_aead(
        key: &F, 
        nonce: &F, 
        ciphertext: &[F], 
        associated_data: &[F], 
        auth_tag: &F
    ) -> Result<Vec<F>, String> {
        // Verify authentication tag
        let mut auth_input = vec![*key, *nonce];
        auth_input.extend_from_slice(associated_data);
        let expected_tag = poseidon_hash(&auth_input);
        
        if expected_tag != *auth_tag {
            return Err("Authentication failed".to_string());
        }
        
        // Decrypt with modified key
        let dec_key = poseidon_hash(&[*key, *nonce, *auth_tag]);
        let plaintext = Self::decrypt(&dec_key, &F::from(0u64), ciphertext);
        
        Ok(plaintext)
    }
}

/// Stream cipher mode using Poseidon in counter mode
pub struct PoseidonStreamCipher {
    key: F,
    nonce: F,
    counter: F,
    buffer: Vec<F>,
    buffer_pos: usize,
}

impl PoseidonStreamCipher {
    /// Create new stream cipher
    pub fn new(key: F, nonce: F) -> Self {
        Self {
            key,
            nonce,
            counter: F::from(0u64),
            buffer: Vec::new(),
            buffer_pos: 0,
        }
    }
    
    /// Generate next keystream block
    fn generate_keystream(&mut self) {
        // Generate 8 field elements per block
        self.buffer.clear();
        for i in 0..8 {
            let block_key = poseidon_hash(&[
                self.key,
                self.nonce,
                self.counter,
                F::from(i as u64),
            ]);
            self.buffer.push(block_key);
        }
        self.counter += F::from(1u64);
        self.buffer_pos = 0;
    }
    
    /// Process data (encrypt or decrypt)
    pub fn process(&mut self, data: &[F]) -> Vec<F> {
        let mut result = Vec::with_capacity(data.len());
        
        for &item in data {
            // Generate new keystream if needed
            if self.buffer_pos >= self.buffer.len() {
                self.generate_keystream();
            }
            
            // XOR with keystream (use subtraction for decryption)
            result.push(item + self.buffer[self.buffer_pos]);
            self.buffer_pos += 1;
        }
        
        result
    }
    
    /// Decrypt data (inverse of encrypt)
    pub fn decrypt(&mut self, data: &[F]) -> Vec<F> {
        let mut result = Vec::with_capacity(data.len());
        
        for &item in data {
            // Generate new keystream if needed
            if self.buffer_pos >= self.buffer.len() {
                self.generate_keystream();
            }
            
            // XOR with keystream (use subtraction for decryption)
            result.push(item - self.buffer[self.buffer_pos]);
            self.buffer_pos += 1;
        }
        
        result
    }
    
    /// Reset cipher to initial state
    pub fn reset(&mut self) {
        self.counter = F::from(0u64);
        self.buffer.clear();
        self.buffer_pos = 0;
    }
}

/// Key derivation using Poseidon
pub struct PoseidonKDF;

impl PoseidonKDF {
    /// Derive key from password and salt
    pub fn derive_key(password: &[F], salt: &F, iterations: u32) -> F {
        let mut key = poseidon_hash(&[password[0], *salt]);
        
        for i in 1..iterations {
            let mut input = vec![key, *salt, F::from(i as u64)];
            if password.len() > 1 {
                input.extend_from_slice(&password[1..]);
            }
            key = poseidon_hash(&input);
        }
        
        key
    }
    
    /// Derive multiple keys from master key
    pub fn derive_subkeys(master_key: &F, context: &[u8], num_keys: usize) -> Vec<F> {
        let context_field = crate::utils::bytes_to_field(context);
        let mut keys = Vec::with_capacity(num_keys);
        
        for i in 0..num_keys {
            keys.push(poseidon_hash(&[
                *master_key,
                context_field,
                F::from(i as u64),
            ]));
        }
        
        keys
    }
}

/// Commitment with encryption
pub struct EncryptedCommitment {
    pub commitment: F,
    pub encrypted_data: Vec<F>,
    pub nonce: F,
}

impl EncryptedCommitment {
    /// Create encrypted commitment
    pub fn new(data: &[F], blinding: &F, enc_key: &F) -> Self {
        let mut rng = rand::thread_rng();
        let nonce = F::rand(&mut rng);
        
        // Compute commitment
        let mut commit_input = data.to_vec();
        commit_input.push(*blinding);
        let commitment = poseidon_hash(&commit_input);
        
        // Encrypt data
        let encrypted_data = PoseidonEncryption::encrypt(enc_key, &nonce, data);
        
        Self {
            commitment,
            encrypted_data,
            nonce,
        }
    }
    
    /// Open and decrypt commitment
    pub fn open(&self, blinding: &F, enc_key: &F) -> Result<Vec<F>, String> {
        // Decrypt data
        let data = PoseidonEncryption::decrypt(enc_key, &self.nonce, &self.encrypted_data);
        
        // Verify commitment
        let mut commit_input = data.clone();
        commit_input.push(*blinding);
        let computed = poseidon_hash(&commit_input);
        
        if computed != self.commitment {
            return Err("Commitment verification failed".to_string());
        }
        
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;
    
    #[test]
    fn test_poseidon_encryption() {
        let mut rng = thread_rng();
        let key = F::rand(&mut rng);
        let nonce = F::rand(&mut rng);
        
        // Test single field element
        let plaintext = vec![F::from(42u64)];
        let ciphertext = PoseidonEncryption::encrypt(&key, &nonce, &plaintext);
        let decrypted = PoseidonEncryption::decrypt(&key, &nonce, &ciphertext);
        
        assert_eq!(plaintext, decrypted);
        
        // Test multiple field elements
        let plaintext: Vec<F> = (0..10).map(|i| F::from(i as u64)).collect();
        let ciphertext = PoseidonEncryption::encrypt(&key, &nonce, &plaintext);
        let decrypted = PoseidonEncryption::decrypt(&key, &nonce, &ciphertext);
        
        assert_eq!(plaintext, decrypted);
    }
    
    #[test]
    fn test_poseidon_aead() {
        let mut rng = thread_rng();
        let key = F::rand(&mut rng);
        let nonce = F::rand(&mut rng);
        
        let plaintext = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
        let associated_data = vec![F::from(100u64), F::from(200u64)];
        
        // Encrypt with authentication
        let (ciphertext, auth_tag) = PoseidonEncryption::encrypt_aead(
            &key,
            &nonce,
            &plaintext,
            &associated_data,
        );
        
        // Decrypt with authentication
        let decrypted = PoseidonEncryption::decrypt_aead(
            &key,
            &nonce,
            &ciphertext,
            &associated_data,
            &auth_tag,
        ).unwrap();
        
        assert_eq!(plaintext, decrypted);
        
        // Test authentication failure with wrong tag
        let wrong_tag = F::rand(&mut rng);
        let result = PoseidonEncryption::decrypt_aead(
            &key,
            &nonce,
            &ciphertext,
            &associated_data,
            &wrong_tag,
        );
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_stream_cipher() {
        let mut rng = thread_rng();
        let key = F::rand(&mut rng);
        let nonce = F::rand(&mut rng);
        
        let plaintext: Vec<F> = (0..20).map(|i| F::from(i as u64)).collect();
        
        // Encrypt
        let mut cipher = PoseidonStreamCipher::new(key, nonce);
        let ciphertext = cipher.process(&plaintext);
        
        // Decrypt
        cipher.reset();
        let decrypted = cipher.decrypt(&ciphertext);
        
        assert_eq!(plaintext, decrypted);
    }
    
    #[test]
    fn test_kdf() {
        let mut rng = thread_rng();
        let password = vec![F::from(12345u64)];
        let salt = F::rand(&mut rng);
        
        // Derive key with different iteration counts
        let key1 = PoseidonKDF::derive_key(&password, &salt, 100);
        let key2 = PoseidonKDF::derive_key(&password, &salt, 100);
        let key3 = PoseidonKDF::derive_key(&password, &salt, 200);
        
        // Same parameters should give same key
        assert_eq!(key1, key2);
        
        // Different iterations should give different key
        assert_ne!(key1, key3);
        
        // Test subkey derivation
        let master = F::rand(&mut rng);
        let subkeys = PoseidonKDF::derive_subkeys(&master, b"context", 5);
        
        assert_eq!(subkeys.len(), 5);
        // All subkeys should be different
        for i in 0..5 {
            for j in i+1..5 {
                assert_ne!(subkeys[i], subkeys[j]);
            }
        }
    }
    
    #[test]
    fn test_encrypted_commitment() {
        let mut rng = thread_rng();
        let enc_key = F::rand(&mut rng);
        let blinding = F::rand(&mut rng);
        
        let data = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
        
        // Create encrypted commitment
        let ec = EncryptedCommitment::new(&data, &blinding, &enc_key);
        
        // Open and verify
        let opened = ec.open(&blinding, &enc_key).unwrap();
        assert_eq!(data, opened);
        
        // Wrong blinding should fail
        let wrong_blinding = F::rand(&mut rng);
        let result = ec.open(&wrong_blinding, &enc_key);
        assert!(result.is_err());
    }
}