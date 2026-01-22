//! Bridge event data structures for cross-chain deposit and withdrawal monitoring.
//!
//! These structures represent events emitted by bridge contracts on external chains
//! (Ethereum, Solana) that need to be processed by the FLUXE sequencer.

use crate::types::{Amount, AssetType, ChainId};
use ark_bn254::Fr as F;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur when processing bridge events
#[derive(Error, Debug)]
pub enum BridgeEventError {
    #[error("Invalid event data: {0}")]
    InvalidEventData(String),

    #[error("Event parsing failed: {0}")]
    ParseError(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid commitment format: expected 32 bytes, got {0}")]
    InvalidCommitmentLength(usize),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Duplicate event detected: {0}")]
    DuplicateEvent(String),
}

/// A deposit event emitted by a bridge contract when tokens are deposited.
///
/// This event is emitted on the source chain (e.g., Ethereum) when a user
/// deposits tokens into the FLUXE bridge contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositEvent {
    /// Chain ID where the deposit occurred
    pub source_chain: ChainId,

    /// Asset type identifier (matches token address on chain)
    pub asset_type: AssetType,

    /// Amount deposited (in smallest unit, e.g., wei for ETH)
    pub amount: Amount,

    /// Beneficiary commitment - the Poseidon hash of the note commitment
    /// that will receive the deposited funds in FLUXE
    #[serde(with = "field_element_serde")]
    pub beneficiary_cm: F,

    /// Hash of the ingress receipt computed on-chain
    #[serde(with = "field_element_serde")]
    pub ingress_hash: F,

    /// Block number where the deposit was confirmed
    pub block_number: u64,

    /// Transaction hash of the deposit (for reference/debugging)
    pub tx_hash: [u8; 32],

    /// Log index within the block (for event ordering)
    pub log_index: u64,

    /// Timestamp of the block (Unix timestamp)
    pub timestamp: u64,
}

impl DepositEvent {
    /// Create a new deposit event
    pub fn new(
        source_chain: ChainId,
        asset_type: AssetType,
        amount: Amount,
        beneficiary_cm: F,
        ingress_hash: F,
        block_number: u64,
    ) -> Self {
        Self {
            source_chain,
            asset_type,
            amount,
            beneficiary_cm,
            ingress_hash,
            block_number,
            tx_hash: [0u8; 32],
            log_index: 0,
            timestamp: 0,
        }
    }

    /// Set the transaction hash
    pub fn with_tx_hash(mut self, tx_hash: [u8; 32]) -> Self {
        self.tx_hash = tx_hash;
        self
    }

    /// Set the log index
    pub fn with_log_index(mut self, log_index: u64) -> Self {
        self.log_index = log_index;
        self
    }

    /// Set the timestamp
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Compute a unique identifier for this event (for deduplication)
    pub fn unique_id(&self) -> EventId {
        EventId {
            chain_id: self.source_chain,
            block_number: self.block_number,
            tx_hash: self.tx_hash,
            log_index: self.log_index,
        }
    }

    /// Validate the deposit event data
    pub fn validate(&self) -> Result<(), BridgeEventError> {
        if self.amount.is_zero() {
            return Err(BridgeEventError::InvalidAmount(
                "Deposit amount cannot be zero".to_string(),
            ));
        }

        Ok(())
    }
}

/// A withdrawal event for tracking withdrawals on the destination chain.
///
/// This is primarily used for monitoring the settlement of exit receipts
/// on the target chain after a user burns their FLUXE notes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalEvent {
    /// Chain ID where the withdrawal will be processed
    pub destination_chain: ChainId,

    /// Asset type identifier
    pub asset_type: AssetType,

    /// Amount being withdrawn
    pub amount: Amount,

    /// Recipient address (chain-specific encoding)
    pub recipient: Vec<u8>,

    /// Exit receipt hash from FLUXE
    #[serde(with = "field_element_serde")]
    pub exit_receipt_hash: F,

    /// Block number where the withdrawal was processed
    pub block_number: u64,

    /// Transaction hash of the withdrawal
    pub tx_hash: [u8; 32],

    /// Whether the withdrawal has been claimed
    pub claimed: bool,
}

impl WithdrawalEvent {
    /// Create a new withdrawal event
    pub fn new(
        destination_chain: ChainId,
        asset_type: AssetType,
        amount: Amount,
        recipient: Vec<u8>,
        exit_receipt_hash: F,
        block_number: u64,
    ) -> Self {
        Self {
            destination_chain,
            asset_type,
            amount,
            recipient,
            exit_receipt_hash,
            block_number,
            tx_hash: [0u8; 32],
            claimed: false,
        }
    }

    /// Set the transaction hash
    pub fn with_tx_hash(mut self, tx_hash: [u8; 32]) -> Self {
        self.tx_hash = tx_hash;
        self
    }

    /// Mark as claimed
    pub fn mark_claimed(mut self) -> Self {
        self.claimed = true;
        self
    }

    /// Compute a unique identifier for this event
    pub fn unique_id(&self) -> EventId {
        EventId {
            chain_id: self.destination_chain,
            block_number: self.block_number,
            tx_hash: self.tx_hash,
            log_index: 0, // Withdrawals typically don't need log_index disambiguation
        }
    }
}

/// Unique identifier for a bridge event (used for deduplication)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId {
    /// Chain ID where the event occurred
    pub chain_id: ChainId,

    /// Block number
    pub block_number: u64,

    /// Transaction hash
    pub tx_hash: [u8; 32],

    /// Log index within the transaction
    pub log_index: u64,
}

impl EventId {
    /// Create a new event ID
    pub fn new(chain_id: ChainId, block_number: u64, tx_hash: [u8; 32], log_index: u64) -> Self {
        Self {
            chain_id,
            block_number,
            tx_hash,
            log_index,
        }
    }

    /// Convert to a hex string for storage/logging
    pub fn to_hex(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.chain_id,
            self.block_number,
            hex::encode(self.tx_hash),
            self.log_index
        )
    }
}

/// Serde helper for field elements
mod field_element_serde {
    use ark_bn254::Fr as F;
    use ark_ff::{PrimeField, BigInteger};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(field: &F, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = field.into_bigint().to_bytes_be();
        hex::encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<F, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        F::from_be_bytes_mod_order(&bytes)
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid field element"))
    }
}

/// Solana-specific deposit event data as emitted by the bridge program.
///
/// This structure mirrors the Anchor event format from the Solana bridge program.
/// It's used for parsing program logs before converting to the unified `DepositEvent`.
///
/// The fields match the `DepositEvent` struct in `contracts/solana/programs/fluxe_bridge/src/lib.rs`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolanaDepositEventData {
    /// Asset type identifier
    pub asset_type: u32,
    /// Deposit amount in smallest units (e.g., micro-USDC)
    pub amount: u64,
    /// Beneficiary commitment bytes (32 bytes)
    pub beneficiary_cm: [u8; 32],
    /// Computed ingress hash (32 bytes)
    pub ingress_hash: [u8; 32],
    /// Deposit nonce (sequential counter)
    pub nonce: u64,
    /// Depositor pubkey (base58 encoded)
    pub depositor: String,
}

impl SolanaDepositEventData {
    /// Convert to unified DepositEvent.
    ///
    /// # Arguments
    ///
    /// * `chain_id` - The Solana chain ID (typically 501)
    /// * `slot` - The slot where the event occurred
    /// * `signature` - The transaction signature
    ///
    /// # Returns
    ///
    /// A unified `DepositEvent` that can be processed by the sequencer.
    pub fn to_deposit_event(
        &self,
        chain_id: ChainId,
        slot: u64,
        signature: [u8; 32],
    ) -> DepositEvent {
        // Convert byte arrays to field elements
        let beneficiary_cm = crate::utils::bytes_to_field(&self.beneficiary_cm);
        let ingress_hash = crate::utils::bytes_to_field(&self.ingress_hash);

        DepositEvent::new(
            chain_id,
            self.asset_type,
            Amount::from(self.amount as u128),
            beneficiary_cm,
            ingress_hash,
            slot,
        )
        .with_tx_hash(signature)
        .with_log_index(self.nonce) // Use nonce as log index for Solana events
    }

    /// Validate the event data.
    pub fn validate(&self) -> Result<(), BridgeEventError> {
        if self.amount == 0 {
            return Err(BridgeEventError::InvalidAmount(
                "Deposit amount cannot be zero".to_string(),
            ));
        }

        if self.beneficiary_cm == [0u8; 32] {
            return Err(BridgeEventError::InvalidEventData(
                "Beneficiary commitment cannot be all zeros".to_string(),
            ));
        }

        if self.ingress_hash == [0u8; 32] {
            return Err(BridgeEventError::InvalidEventData(
                "Ingress hash cannot be all zeros".to_string(),
            ));
        }

        Ok(())
    }
}

/// Anchor event discriminator for DepositEvent.
///
/// Anchor events are prefixed with an 8-byte discriminator derived from
/// `sha256("event:EventName")[..8]`. This is the discriminator for "event:DepositEvent".
pub const SOLANA_DEPOSIT_EVENT_DISCRIMINATOR: [u8; 8] = {
    // This value should be computed as: sha256("event:DepositEvent")[..8]
    // The actual bytes depend on the exact Anchor version and event name
    [0x9e, 0xbf, 0xde, 0xa7, 0xe4, 0x1b, 0x80, 0x67]
};

/// Size of the Solana deposit event data in bytes (excluding discriminator).
///
/// Layout:
/// - asset_type: 4 bytes (u32)
/// - amount: 8 bytes (u64)
/// - beneficiary_cm: 32 bytes
/// - ingress_hash: 32 bytes
/// - nonce: 8 bytes (u64)
/// - depositor: 32 bytes (Pubkey)
pub const SOLANA_DEPOSIT_EVENT_SIZE: usize = 4 + 8 + 32 + 32 + 8 + 32;

/// Parse a raw Anchor event from program log data.
///
/// Anchor events are base64-encoded in program logs with the format:
/// `Program data: <base64-encoded-event>`
///
/// # Arguments
///
/// * `data` - The decoded event data (after base64 decoding and discriminator check)
///
/// # Returns
///
/// The parsed `SolanaDepositEventData` if successful.
pub fn parse_solana_deposit_event(data: &[u8]) -> Result<SolanaDepositEventData, BridgeEventError> {
    if data.len() < SOLANA_DEPOSIT_EVENT_SIZE {
        return Err(BridgeEventError::InvalidEventData(format!(
            "Event data too short: expected at least {} bytes, got {}",
            SOLANA_DEPOSIT_EVENT_SIZE,
            data.len()
        )));
    }

    // Parse fields in order
    let mut offset = 0;

    // asset_type: u32 (4 bytes, little-endian)
    let asset_type = u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .map_err(|_| BridgeEventError::ParseError("Failed to parse asset_type".to_string()))?,
    );
    offset += 4;

    // amount: u64 (8 bytes, little-endian)
    let amount = u64::from_le_bytes(
        data[offset..offset + 8]
            .try_into()
            .map_err(|_| BridgeEventError::ParseError("Failed to parse amount".to_string()))?,
    );
    offset += 8;

    // beneficiary_cm: [u8; 32]
    let mut beneficiary_cm = [0u8; 32];
    beneficiary_cm.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    // ingress_hash: [u8; 32]
    let mut ingress_hash = [0u8; 32];
    ingress_hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    // nonce: u64 (8 bytes, little-endian)
    let nonce = u64::from_le_bytes(
        data[offset..offset + 8]
            .try_into()
            .map_err(|_| BridgeEventError::ParseError("Failed to parse nonce".to_string()))?,
    );
    offset += 8;

    // depositor: Pubkey (32 bytes) - encode as hex since bs58 is not available
    let depositor_bytes = &data[offset..offset + 32];
    let depositor = hex::encode(depositor_bytes);

    Ok(SolanaDepositEventData {
        asset_type,
        amount,
        beneficiary_cm,
        ingress_hash,
        nonce,
        depositor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_deposit_event_creation() {
        let mut rng = thread_rng();
        let beneficiary_cm = F::rand(&mut rng);
        let ingress_hash = F::rand(&mut rng);

        let event = DepositEvent::new(
            1, // Ethereum mainnet
            1, // USDC
            Amount::from(1_000_000u128), // 1 USDC
            beneficiary_cm,
            ingress_hash,
            1234567,
        );

        assert_eq!(event.source_chain, 1);
        assert_eq!(event.asset_type, 1);
        assert_eq!(event.block_number, 1234567);
    }

    #[test]
    fn test_deposit_event_builder() {
        let mut rng = thread_rng();
        let beneficiary_cm = F::rand(&mut rng);
        let ingress_hash = F::rand(&mut rng);
        let tx_hash = [0xabu8; 32];

        let event = DepositEvent::new(
            1,
            1,
            Amount::from(1_000_000u128),
            beneficiary_cm,
            ingress_hash,
            1234567,
        )
        .with_tx_hash(tx_hash)
        .with_log_index(5)
        .with_timestamp(1700000000);

        assert_eq!(event.tx_hash, tx_hash);
        assert_eq!(event.log_index, 5);
        assert_eq!(event.timestamp, 1700000000);
    }

    #[test]
    fn test_deposit_event_validation() {
        let mut rng = thread_rng();
        let beneficiary_cm = F::rand(&mut rng);
        let ingress_hash = F::rand(&mut rng);

        // Valid event
        let valid_event = DepositEvent::new(
            1,
            1,
            Amount::from(1_000_000u128),
            beneficiary_cm,
            ingress_hash,
            1234567,
        );
        assert!(valid_event.validate().is_ok());

        // Invalid: zero amount
        let zero_amount_event = DepositEvent::new(
            1,
            1,
            Amount::zero(),
            beneficiary_cm,
            ingress_hash,
            1234567,
        );
        assert!(zero_amount_event.validate().is_err());
    }

    #[test]
    fn test_event_unique_id() {
        let mut rng = thread_rng();
        let beneficiary_cm = F::rand(&mut rng);
        let ingress_hash = F::rand(&mut rng);
        let tx_hash1 = [0xabu8; 32];
        let tx_hash2 = [0xcdu8; 32];

        let event1 = DepositEvent::new(
            1,
            1,
            Amount::from(1_000_000u128),
            beneficiary_cm,
            ingress_hash,
            1234567,
        )
        .with_tx_hash(tx_hash1)
        .with_log_index(0);

        let event2 = DepositEvent::new(
            1,
            1,
            Amount::from(1_000_000u128),
            beneficiary_cm,
            ingress_hash,
            1234567,
        )
        .with_tx_hash(tx_hash1)
        .with_log_index(1);

        let event3 = DepositEvent::new(
            1,
            1,
            Amount::from(1_000_000u128),
            beneficiary_cm,
            ingress_hash,
            1234567,
        )
        .with_tx_hash(tx_hash2)
        .with_log_index(0);

        // Same block/tx but different log index
        assert_ne!(event1.unique_id(), event2.unique_id());

        // Different tx hash
        assert_ne!(event1.unique_id(), event3.unique_id());

        // Same event should have same ID
        let event1_copy = event1.clone();
        assert_eq!(event1.unique_id(), event1_copy.unique_id());
    }

    #[test]
    fn test_withdrawal_event() {
        let mut rng = thread_rng();
        let exit_receipt_hash = F::rand(&mut rng);
        let recipient = vec![0xab; 20]; // Ethereum address

        let event = WithdrawalEvent::new(
            1,
            1,
            Amount::from(500_000u128),
            recipient.clone(),
            exit_receipt_hash,
            9876543,
        );

        assert_eq!(event.destination_chain, 1);
        assert_eq!(event.recipient, recipient);
        assert!(!event.claimed);

        let claimed_event = event.mark_claimed();
        assert!(claimed_event.claimed);
    }

    #[test]
    fn test_event_id_hex() {
        let id = EventId::new(
            1,
            1234567,
            [0xab; 32],
            5,
        );

        let hex_str = id.to_hex();
        assert!(hex_str.starts_with("1:1234567:"));
        assert!(hex_str.ends_with(":5"));
    }

    // ============ Solana-specific tests ============

    #[test]
    fn test_solana_deposit_event_data_creation() {
        let data = SolanaDepositEventData {
            asset_type: 1,
            amount: 1_000_000,
            beneficiary_cm: [0xab; 32],
            ingress_hash: [0xcd; 32],
            nonce: 42,
            depositor: "11111111111111111111111111111111".to_string(), // System program pubkey
        };

        assert_eq!(data.asset_type, 1);
        assert_eq!(data.amount, 1_000_000);
        assert_eq!(data.nonce, 42);
    }

    #[test]
    fn test_solana_deposit_event_data_validation() {
        // Valid data
        let valid_data = SolanaDepositEventData {
            asset_type: 1,
            amount: 1_000_000,
            beneficiary_cm: [0xab; 32],
            ingress_hash: [0xcd; 32],
            nonce: 42,
            depositor: "11111111111111111111111111111111".to_string(),
        };
        assert!(valid_data.validate().is_ok());

        // Zero amount
        let zero_amount = SolanaDepositEventData {
            asset_type: 1,
            amount: 0,
            beneficiary_cm: [0xab; 32],
            ingress_hash: [0xcd; 32],
            nonce: 42,
            depositor: "11111111111111111111111111111111".to_string(),
        };
        assert!(zero_amount.validate().is_err());

        // Zero beneficiary
        let zero_beneficiary = SolanaDepositEventData {
            asset_type: 1,
            amount: 1_000_000,
            beneficiary_cm: [0x00; 32],
            ingress_hash: [0xcd; 32],
            nonce: 42,
            depositor: "11111111111111111111111111111111".to_string(),
        };
        assert!(zero_beneficiary.validate().is_err());

        // Zero ingress hash
        let zero_ingress = SolanaDepositEventData {
            asset_type: 1,
            amount: 1_000_000,
            beneficiary_cm: [0xab; 32],
            ingress_hash: [0x00; 32],
            nonce: 42,
            depositor: "11111111111111111111111111111111".to_string(),
        };
        assert!(zero_ingress.validate().is_err());
    }

    #[test]
    fn test_solana_deposit_event_data_to_deposit_event() {
        let data = SolanaDepositEventData {
            asset_type: 1,
            amount: 1_000_000,
            beneficiary_cm: [0xab; 32],
            ingress_hash: [0xcd; 32],
            nonce: 42,
            depositor: "11111111111111111111111111111111".to_string(),
        };

        let chain_id = 501; // Solana
        let slot = 12345;
        let signature = [0xef; 32];

        let event = data.to_deposit_event(chain_id, slot, signature);

        assert_eq!(event.source_chain, 501);
        assert_eq!(event.asset_type, 1);
        assert_eq!(event.amount, Amount::from(1_000_000u128));
        assert_eq!(event.block_number, 12345);
        assert_eq!(event.tx_hash, signature);
        assert_eq!(event.log_index, 42); // nonce used as log_index
    }

    #[test]
    fn test_parse_solana_deposit_event() {
        // Construct raw event data
        let mut data = Vec::new();

        // asset_type: u32 = 1
        data.extend_from_slice(&1u32.to_le_bytes());
        // amount: u64 = 1_000_000
        data.extend_from_slice(&1_000_000u64.to_le_bytes());
        // beneficiary_cm: [u8; 32]
        data.extend_from_slice(&[0xab; 32]);
        // ingress_hash: [u8; 32]
        data.extend_from_slice(&[0xcd; 32]);
        // nonce: u64 = 42
        data.extend_from_slice(&42u64.to_le_bytes());
        // depositor: Pubkey (32 bytes)
        data.extend_from_slice(&[0x00; 32]); // All zeros pubkey

        let result = parse_solana_deposit_event(&data);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.asset_type, 1);
        assert_eq!(parsed.amount, 1_000_000);
        assert_eq!(parsed.beneficiary_cm, [0xab; 32]);
        assert_eq!(parsed.ingress_hash, [0xcd; 32]);
        assert_eq!(parsed.nonce, 42);
        // Depositor is base58 encoded 32-byte zero pubkey
        assert!(!parsed.depositor.is_empty());
    }

    #[test]
    fn test_parse_solana_deposit_event_too_short() {
        let data = vec![0u8; 10]; // Way too short
        let result = parse_solana_deposit_event(&data);
        assert!(result.is_err());

        match result {
            Err(BridgeEventError::InvalidEventData(msg)) => {
                assert!(msg.contains("too short"));
            }
            _ => panic!("Expected InvalidEventData error"),
        }
    }

    #[test]
    fn test_solana_deposit_event_size_constant() {
        // Verify the size constant matches the expected layout
        let expected_size = 4 + 8 + 32 + 32 + 8 + 32; // asset_type + amount + beneficiary_cm + ingress_hash + nonce + depositor
        assert_eq!(SOLANA_DEPOSIT_EVENT_SIZE, expected_size);
        assert_eq!(SOLANA_DEPOSIT_EVENT_SIZE, 116);
    }
}
