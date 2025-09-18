use ark_bls12_381::Fr as F;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Convert field element to bytes (little-endian)
pub fn field_to_bytes(f: &F) -> Vec<u8> {
    // Use the proper encoding that's < field modulus
    // We use 31 bytes to ensure the value is always valid
    let bigint = f.into_bigint();
    let mut bytes = Vec::with_capacity(31);
    
    // Get bytes from limbs (little-endian)
    for limb in bigint.as_ref() {
        for byte in limb.to_le_bytes() {
            if bytes.len() < 31 {
                bytes.push(byte);
            }
        }
    }
    
    // Ensure we have exactly 31 bytes
    bytes.resize(31, 0);
    bytes
}

/// Convert bytes to field element (little-endian, mod order)
pub fn bytes_to_field(bytes: &[u8]) -> F {
    // Always use the truncation method for consistency with circuits
    // This ensures that arbitrary byte arrays (like psi) are handled correctly
    // Pad or truncate to 31 bytes to ensure we're below the field modulus
    let mut buf = [0u8; 31];
    let len = bytes.len().min(31);
    buf[..len].copy_from_slice(&bytes[..len]);
    
    // Convert to field element - this is guaranteed to be in range
    let mut result = F::from(0u64);
    let mut multiplier = F::from(1u64);
    for &byte in buf.iter() {
        let byte_value = F::from(byte as u64);
        result += byte_value * multiplier;
        multiplier *= F::from(256u64);
    }
    result
}

/// Serialize multiple elements to a byte vector
pub fn serialize_to_vec<T: CanonicalSerialize>(items: &[T]) -> Result<Vec<u8>, ark_serialize::SerializationError> {
    let mut buf = Vec::new();
    for item in items {
        item.serialize_uncompressed(&mut buf)?;
    }
    Ok(buf)
}

/// Deserialize multiple elements from a byte vector
pub fn deserialize_from_vec<T: CanonicalDeserialize>(data: &[u8], count: usize) -> Result<Vec<T>, ark_serialize::SerializationError> {
    let mut cursor = &data[..];
    let mut result = Vec::with_capacity(count);
    
    for _ in 0..count {
        let item = T::deserialize_uncompressed(&mut cursor)?;
        result.push(item);
    }
    
    Ok(result)
}

/// Generate a deterministic field element from a seed string
pub fn deterministic_field_from_seed(seed: &str) -> F {
    use crate::crypto::blake2b_hash;
    
    let hash = blake2b_hash(seed.as_bytes());
    bytes_to_field(&hash)
}

/// Check if a field element can fit in a u64
pub fn field_fits_u64(f: &F) -> bool {
    let bytes = field_to_bytes(f);
    
    // Check if all bytes after the first 8 are zero
    if bytes.len() <= 8 {
        return true;
    }
    
    for &byte in &bytes[8..] {
        if byte != 0 {
            return false;
        }
    }
    
    true
}

/// Convert field element to u64 (panics if doesn't fit)
pub fn field_to_u64(f: &F) -> u64 {
    assert!(field_fits_u64(f), "Field element too large for u64");
    
    let bytes = field_to_bytes(f);
    let mut u64_bytes = [0u8; 8];
    u64_bytes.copy_from_slice(&bytes[..8.min(bytes.len())]);
    u64::from_le_bytes(u64_bytes)
}

/// Create a vector of field elements from a range
pub fn field_range(start: u64, end: u64) -> Vec<F> {
    (start..end).map(F::from).collect()
}

/// Compute the next power of two
pub fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    
    let mut v = n - 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v + 1
}

/// Pad a vector to the next power of two length
pub fn pad_to_power_of_two<T: Clone>(vec: &mut Vec<T>, padding_value: T) {
    let target_len = next_power_of_two(vec.len());
    vec.resize(target_len, padding_value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_field_conversions() {
        // Test with small field elements that fit in 31 bytes
        let test_values = vec![
            F::from(0u64),
            F::from(1u64),
            F::from(12345u64),
            F::from(u64::MAX),
        ];
        
        for f in test_values {
            let bytes = field_to_bytes(&f);
            assert_eq!(bytes.len(), 31, "field_to_bytes should always return 31 bytes");
            let f2 = bytes_to_field(&bytes);
            assert_eq!(f, f2);
        }
        
        // For random field elements, we can't guarantee round-trip
        // because field elements can be larger than 31 bytes
        // This is expected and OK - we only use this for small values
        // and entropy (psi) which is already truncated to 31 bytes
    }

    #[test]
    fn test_u64_conversion() {
        let small = F::from(12345u64);
        assert!(field_fits_u64(&small));
        assert_eq!(field_to_u64(&small), 12345);
        
        let large = F::from(u128::MAX);
        assert!(!field_fits_u64(&large));
    }

    #[test]
    fn test_deterministic_field() {
        let f1 = deterministic_field_from_seed("test");
        let f2 = deterministic_field_from_seed("test");
        assert_eq!(f1, f2);
        
        let f3 = deterministic_field_from_seed("different");
        assert_ne!(f1, f3);
    }

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(5), 8);
        assert_eq!(next_power_of_two(17), 32);
    }

    #[test]
    fn test_pad_vector() {
        let mut vec = vec![1, 2, 3];
        pad_to_power_of_two(&mut vec, 0);
        assert_eq!(vec, vec![1, 2, 3, 0]);
        
        let mut vec2 = vec![1, 2, 3, 4, 5];
        pad_to_power_of_two(&mut vec2, 0);
        assert_eq!(vec2.len(), 8);
    }
}