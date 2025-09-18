use ark_bls12_381::Fr as F;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use std::ops::{Add, Mul, Sub, Div};
use std::fmt;

/// Wrapper type for field elements with serde support
#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FieldElement(pub F);

impl FieldElement {
    pub fn new(value: F) -> Self {
        Self(value)
    }
    
    pub fn zero() -> Self {
        Self(F::from(0u64))
    }
    
    pub fn one() -> Self {
        Self(F::from(1u64))
    }
    
    pub fn from_u64(value: u64) -> Self {
        Self(F::from(value))
    }
    
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        use crate::utils::bytes_to_field;
        Self(bytes_to_field(bytes))
    }
    
    pub fn to_bytes_le(&self) -> Vec<u8> {
        use ark_ff::BigInteger;
        self.0.into_bigint().to_bytes_le()
    }
    
    pub fn inner(&self) -> F {
        self.0
    }
}

// Implement serde for FieldElement
impl Serialize for FieldElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as hex string
        let bytes = self.to_bytes_le();
        let hex = hex::encode(&bytes);
        serializer.serialize_str(&hex)
    }
}

impl<'de> Deserialize<'de> for FieldElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex).map_err(serde::de::Error::custom)?;
        Ok(Self::from_bytes_le(&bytes))
    }
}

// Arithmetic operations
impl Add for FieldElement {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl Sub for FieldElement {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl Mul for FieldElement {
    type Output = Self;
    
    fn mul(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl Div for FieldElement {
    type Output = Self;
    
    fn div(self, other: Self) -> Self {
        Self(self.0 / other.0)
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<F> for FieldElement {
    fn from(value: F) -> Self {
        Self(value)
    }
}

impl From<u64> for FieldElement {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<u128> for FieldElement {
    fn from(value: u128) -> Self {
        Self(F::from(value))
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_field_wrapper_serde() {
        let field = FieldElement::from_u64(12345);
        let json = serde_json::to_string(&field).unwrap();
        let recovered: FieldElement = serde_json::from_str(&json).unwrap();
        assert_eq!(field, recovered);
    }
    
    #[test]
    fn test_field_arithmetic() {
        let a = FieldElement::from_u64(10);
        let b = FieldElement::from_u64(20);
        
        assert_eq!(a + b, FieldElement::from_u64(30));
        assert_eq!(b - a, FieldElement::from_u64(10));
        assert_eq!(a * b, FieldElement::from_u64(200));
    }
}