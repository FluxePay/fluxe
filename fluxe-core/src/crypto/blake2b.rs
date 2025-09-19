use blake2::{Blake2b512, Digest};
use ark_bls12_381::Fr as F;
use ark_ff::{BigInteger, PrimeField};

/// Blake2b hash for entropy derivation
pub fn blake2b_hash(input: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Blake2b hash with domain separator
pub fn blake2b_hash_with_domain(domain: &[u8], input: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(domain);
    hasher.update(b"|"); // separator
    hasher.update(input);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Derive per-note entropy (psi) from secret and nonce
pub fn derive_note_entropy(secret: &F, nonce: &[u8; 32]) -> [u8; 32] {
    let secret_bytes = secret.into_bigint().to_bytes_le();
    let mut input = Vec::new();
    input.extend_from_slice(&secret_bytes);
    input.extend_from_slice(nonce);
    
    let hash = blake2b_hash_with_domain(b"FLUXE_NOTE_ENTROPY", &input);
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash[..32]);
    output
}

/// Derive memo encryption key from shared secret
pub fn derive_memo_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hash = blake2b_hash_with_domain(b"FLUXE_MEMO_KEY", shared_secret);
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash[..32]);
    output
}

/// Key derivation function using Blake2b
pub fn blake2b_kdf(secret: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_len);
    let mut counter = 0u32;
    
    while output.len() < output_len {
        let mut hasher = Blake2b512::new();
        hasher.update(secret);
        hasher.update(counter.to_le_bytes());
        hasher.update(info);
        
        let hash = hasher.finalize();
        let remaining = output_len - output.len();
        let to_copy = remaining.min(64);
        output.extend_from_slice(&hash[..to_copy]);
        
        counter += 1;
    }
    
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_blake2b_hash() {
        let input = b"test input";
        let hash1 = blake2b_hash(input);
        let hash2 = blake2b_hash(input);
        
        // Hash should be deterministic
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_derive_note_entropy() {
        let mut rng = thread_rng();
        let secret = F::rand(&mut rng);
        let nonce = [1u8; 32];
        
        let entropy = derive_note_entropy(&secret, &nonce);
        assert_eq!(entropy.len(), 32);
        
        // Different nonce should give different entropy
        let nonce2 = [2u8; 32];
        let entropy2 = derive_note_entropy(&secret, &nonce2);
        assert_ne!(entropy, entropy2);
    }

    #[test]
    fn test_kdf() {
        let secret = b"secret";
        let info = b"context info";
        
        let key1 = blake2b_kdf(secret, info, 32);
        assert_eq!(key1.len(), 32);
        
        let key2 = blake2b_kdf(secret, info, 64);
        assert_eq!(key2.len(), 64);
        
        // First 32 bytes should match
        assert_eq!(&key1[..], &key2[..32]);
    }
}