use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_serialize::{SerializationError, Read, Write};
use std::fmt;
use ark_bls12_381::Fr as F;

/// Wrapper for u128 amounts with ark_serialize support
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Amount(pub u128);

impl Amount {
    pub fn new(value: u128) -> Self {
        Self(value)
    }
    
    pub fn zero() -> Self {
        Self(0)
    }
    
    pub fn value(&self) -> u128 {
        self.0
    }
    
    /// Convert to field element (may truncate if amount is too large)
    pub fn to_field(&self) -> F {
        // Safe for amounts up to ~2^64 which is sufficient for real-world use
        F::from(self.0 as u64)
    }
}

impl CanonicalSerialize for Amount {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        // Serialize as two u64s (low and high)
        let low = (self.0 & 0xFFFFFFFFFFFFFFFF) as u64;
        let high = (self.0 >> 64) as u64;
        low.serialize_with_mode(&mut writer, ark_serialize::Compress::No)?;
        high.serialize_with_mode(&mut writer, ark_serialize::Compress::No)?;
        Ok(())
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        16 // 2 * u64
    }
}

impl Valid for Amount {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for Amount {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        let low = u64::deserialize_with_mode(&mut reader, ark_serialize::Compress::No, ark_serialize::Validate::No)?;
        let high = u64::deserialize_with_mode(&mut reader, ark_serialize::Compress::No, ark_serialize::Validate::No)?;
        let value = (high as u128) << 64 | (low as u128);
        Ok(Self(value))
    }
}

impl From<u128> for Amount {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<u64> for Amount {
    fn from(value: u64) -> Self {
        Self(value as u128)
    }
}

impl From<u32> for Amount {
    fn from(value: u32) -> Self {
        Self(value as u128)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Arithmetic operations
impl Amount {
    pub fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }
    
    pub fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
    
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
    
    pub fn as_i128(&self) -> i128 {
        self.0 as i128
    }
}

impl std::ops::Add for Amount {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl std::ops::Sub for Amount {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl std::ops::Mul<u128> for Amount {
    type Output = Self;
    
    fn mul(self, scalar: u128) -> Self {
        Self(self.0 * scalar)
    }
}

impl std::ops::Div<u128> for Amount {
    type Output = Self;
    
    fn div(self, scalar: u128) -> Self {
        Self(self.0 / scalar)
    }
}