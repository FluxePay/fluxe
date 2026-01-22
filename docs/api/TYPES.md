# FLUXE Data Types Reference

This document describes all data types used in the FLUXE API.

## Table of Contents

- [Primitive Types](#primitive-types)
- [Core Types](#core-types)
- [API Request Types](#api-request-types)
- [API Response Types](#api-response-types)
- [Configuration Types](#configuration-types)
- [Cryptographic Types](#cryptographic-types)

---

## Primitive Types

### Type Aliases

| Type | Underlying | Description |
|------|------------|-------------|
| `AssetType` | `u32` | Asset type identifier (e.g., 1 = USDC, 2 = USDT) |
| `ChainHint` | `u32` | Target chain identifier for notes |
| `ChainId` | `u32` | Unique chain identifier |
| `PoolId` | `u32` | Policy pool identifier |
| `Time` | `u64` | Unix timestamp in seconds |
| `Commitment` | `F` | Note commitment (BN254 field element) |
| `Nullifier` | `F` | Spent note nullifier (BN254 field element) |
| `MerkleRoot` | `F` | Merkle tree root (BN254 field element) |
| `AuthAddr` | `F` | Owner address (Poseidon hash or Ethereum address) |
| `ComplianceHash` | `F` | Commitment to compliance metadata |
| `LineageHash` | `F` | Bounded lineage accumulator |
| `CallbacksHash` | `F` | Hash-chain head for pending callbacks |
| `MemoHash` | `F` | Hash of encrypted memo |
| `RepScore` | `u32` | Reputation score |
| `RiskScore` | `u32` | Risk score for compliance |

### Amount

Wrapper type for monetary amounts.

```rust
pub struct Amount(pub u128);
```

**Methods:**

| Method | Description |
|--------|-------------|
| `Amount::zero()` | Create a zero amount |
| `Amount::from(value: u128)` | Create from u128 |
| `value()` | Get the underlying u128 value |
| `to_field()` | Convert to field element |
| `saturating_add(other)` | Add with saturation |
| `saturating_sub(other)` | Subtract with saturation |
| `checked_sub(other)` | Subtract returning Option |

**JSON Representation:**

```json
{
  "amount": 1000000
}
```

---

## Core Types

### Note

A confidential UTXO representing owned value.

```rust
pub struct Note {
    pub asset_type: AssetType,
    pub v_comm: PedersenCommitment,
    pub owner_addr: AuthAddr,
    pub psi: [u8; 32],
    pub chain_hint: ChainHint,
    pub compliance_hash: ComplianceHash,
    pub lineage_hash: LineageHash,
    pub pool_id: PoolId,
    pub callbacks_hash: CallbacksHash,
    pub memo_hash: MemoHash,
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `asset_type` | `u32` | Asset type identifier |
| `v_comm` | `PedersenCommitment` | Pedersen commitment to the value |
| `owner_addr` | `F` | Owner's authentication address |
| `psi` | `[u8; 32]` | Per-note entropy for nullifier derivation |
| `chain_hint` | `u32` | Target chain for cross-chain transfers |
| `compliance_hash` | `F` | Commitment to compliance metadata |
| `lineage_hash` | `F` | Rolling hash tracking note history |
| `pool_id` | `u32` | Policy pool this note belongs to |
| `callbacks_hash` | `F` | Hash of embedded callbacks |
| `memo_hash` | `F` | Hash of encrypted memo |

**Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `new(asset_type, v_comm, owner_addr, psi, pool_id)` | `Note` | Create a new note |
| `commitment()` | `F` | Compute the note commitment |
| `nullifier(nk)` | `F` | Compute the nullifier given nullifier key |

---

### IngressReceipt

Receipt for deposits/mints from external chains.

```rust
pub struct IngressReceipt {
    pub source_chain: ChainId,
    pub asset_type: AssetType,
    pub amount: Amount,
    pub beneficiary_cm: F,
    pub nonce: u64,
    pub aux: F,
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `source_chain` | `u32` | Chain ID where the deposit occurred |
| `asset_type` | `u32` | Asset type being minted |
| `amount` | `Amount` | Amount being minted |
| `beneficiary_cm` | `F` | Commitment to output notes |
| `nonce` | `u64` | Unique nonce for replay protection |
| `aux` | `F` | Auxiliary data (e.g., external tx hash) |

**Hash Computation:**

```
IngressReceipt.hash() = Poseidon(
    source_chain,
    asset_type,
    amount,
    beneficiary_cm,
    nonce,
    aux
)
```

---

### ExitReceipt

Receipt for withdrawals/burns to external chains.

```rust
pub struct ExitReceipt {
    pub destination_chain: ChainId,
    pub asset_type: AssetType,
    pub amount: Amount,
    pub burned_nf: Nullifier,
    pub nonce: u64,
    pub aux: F,
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `destination_chain` | `u32` | Chain ID for the withdrawal |
| `asset_type` | `u32` | Asset type being burned |
| `amount` | `Amount` | Amount being burned |
| `burned_nf` | `F` | Nullifier proving the burn |
| `nonce` | `u64` | Unique nonce for replay protection |
| `aux` | `F` | Auxiliary data (e.g., destination address) |

---

### StateRoots

Collection of all Merkle tree roots.

```rust
pub struct StateRoots {
    pub cmt_root: MerkleRoot,
    pub nft_root: MerkleRoot,
    pub obj_root: MerkleRoot,
    pub cb_root: MerkleRoot,
    pub ingress_root: MerkleRoot,
    pub exit_root: MerkleRoot,
    pub sanctions_root: MerkleRoot,
    pub pool_rules_root: MerkleRoot,
}
```

**Fields:**

| Field | Description |
|-------|-------------|
| `cmt_root` | Note commitment tree root |
| `nft_root` | Nullifier tree root (sorted) |
| `obj_root` | ZK object board root |
| `cb_root` | Callback board root |
| `ingress_root` | Ingress receipt tree root |
| `exit_root` | Exit receipt tree root |
| `sanctions_root` | Sanctions list root |
| `pool_rules_root` | Pool policy rules root |

---

### Supply

Supply tracking for each asset.

```rust
pub struct Supply {
    pub minted_total: Amount,
    pub burned_total: Amount,
}
```

**Methods:**

| Method | Description |
|--------|-------------|
| `current_supply()` | Returns `minted_total - burned_total` |
| `mint(amount)` | Add to minted total |
| `burn(amount)` | Add to burned total (checks supply) |

---

### TransactionType

Enumeration of transaction types.

```rust
pub enum TransactionType {
    Mint,
    Burn,
    Transfer,
    ObjectUpdate,
}
```

---

### CallbackOperation

Operations on the callback board.

```rust
pub enum CallbackOperation {
    Add(CallbackInvocation),
    Process(F),
}
```

**Variants:**

| Variant | Description |
|---------|-------------|
| `Add(invocation)` | Add a new callback invocation |
| `Process(ticket)` | Mark a callback as processed by ticket |

---

### CallbackInvocation

A callback waiting to be processed.

```rust
pub struct CallbackInvocation {
    pub ticket: F,
    pub payload: Vec<u8>,
    pub timestamp: Time,
    pub signature: Option<SchnorrSignature>,
}
```

---

## API Request Types

### SubmitMintRequest

```rust
pub struct SubmitMintRequest {
    pub asset_type: AssetType,
    pub amount: u64,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub notes_out: Vec<SerializableNote>,
}
```

**JSON Example:**

```json
{
  "asset_type": 1,
  "amount": 1000000,
  "proof": [1, 2, 3, ...],
  "public_inputs": [
    "0x0102030405060708091011121314151617181920212223242526272829303132"
  ],
  "notes_out": [
    {
      "asset_type": 1,
      "owner_addr": "0x...",
      "psi": [1, 2, 3, ...],
      "chain_hint": 1,
      "pool_id": 1
    }
  ]
}
```

---

### SubmitBurnRequest

```rust
pub struct SubmitBurnRequest {
    pub asset_type: AssetType,
    pub amount: u64,
    pub nullifier: String,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
}
```

**JSON Example:**

```json
{
  "asset_type": 1,
  "amount": 500000,
  "nullifier": "0x...",
  "proof": [1, 2, 3, ...],
  "public_inputs": ["0x..."]
}
```

---

### SubmitTransferRequest

```rust
pub struct SubmitTransferRequest {
    pub nullifiers: Vec<String>,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub notes_out: Vec<SerializableNote>,
}
```

**JSON Example:**

```json
{
  "nullifiers": ["0x...", "0x..."],
  "proof": [1, 2, 3, ...],
  "public_inputs": ["0x..."],
  "notes_out": [
    {
      "asset_type": 1,
      "owner_addr": "0x...",
      "psi": [1, 2, 3, ...],
      "chain_hint": 1,
      "pool_id": 1
    }
  ]
}
```

---

### SubmitObjectUpdateRequest

```rust
pub struct SubmitObjectUpdateRequest {
    pub old_object_cm: String,
    pub new_object_cm: String,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub callback_operations: Vec<SerializableCallbackOp>,
}
```

**JSON Example:**

```json
{
  "old_object_cm": "0x...",
  "new_object_cm": "0x...",
  "proof": [1, 2, 3, ...],
  "public_inputs": ["0x..."],
  "callback_operations": [
    {
      "op_type": "add",
      "ticket": "0x...",
      "payload": [1, 2, 3],
      "timestamp": 1704067200,
      "signature": [10, 20, 30, ...]
    },
    {
      "op_type": "process",
      "ticket": "0x..."
    }
  ]
}
```

---

### SerializableNote

API-friendly representation of a Note.

```rust
pub struct SerializableNote {
    pub asset_type: AssetType,
    pub owner_addr: String,
    pub psi: [u8; 32],
    pub chain_hint: ChainHint,
    pub pool_id: PoolId,
}
```

---

### SerializableCallbackOp

API-friendly representation of a callback operation.

```rust
pub struct SerializableCallbackOp {
    pub op_type: String,
    pub ticket: Option<String>,
    pub payload: Option<Vec<u8>>,
    pub timestamp: Option<Time>,
    pub signature: Option<Vec<u8>>,
}
```

**Operation Types:**

| `op_type` | Required Fields |
|-----------|-----------------|
| `"add"` | `ticket`, `payload`, `timestamp`, `signature` |
| `"process"` | `ticket` |

---

## API Response Types

### ApiResponse\<T\>

Generic wrapper for all API responses.

```rust
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}
```

---

### StateRootsResponse

```rust
pub struct StateRootsResponse {
    pub cmt_root: String,
    pub nft_root: String,
    pub obj_root: String,
    pub cb_root: String,
    pub ingress_root: String,
    pub exit_root: String,
    pub sanctions_root: String,
    pub pool_rules_root: String,
    pub chain_id: Option<u32>,
}
```

All root values are hex-encoded field elements with `0x` prefix.

---

### SupplyResponse

```rust
pub struct SupplyResponse {
    pub asset_type: AssetType,
    pub minted_total: u64,
    pub burned_total: u64,
    pub current_supply: u64,
    pub chain_id: Option<u32>,
}
```

---

### ProofResponse

```rust
pub struct ProofResponse {
    pub exists: bool,
    pub path: Option<Vec<String>>,
    pub leaf: Option<String>,
    pub index: Option<usize>,
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `exists` | `bool` | Whether the element exists (or non-membership proof exists) |
| `path` | `[string]?` | Merkle path siblings (hex-encoded) |
| `leaf` | `string?` | Leaf hash (hex-encoded) |
| `index` | `usize?` | Leaf index in the tree |

---

### ChainInfo

```rust
pub struct ChainInfo {
    pub chain_id: u32,
    pub chain_type: String,
    pub name: String,
    pub enabled: bool,
    pub block_time_ms: u64,
    pub finality_blocks: u64,
    pub supported_assets: Vec<u32>,
}
```

---

## Configuration Types

### ChainType

```rust
pub enum ChainType {
    EVM,
    SVM,
}
```

| Variant | Description |
|---------|-------------|
| `EVM` | Ethereum Virtual Machine chains |
| `SVM` | Solana Virtual Machine |

---

### ChainConfig

Configuration for a single chain.

```rust
pub struct ChainConfig {
    pub chain_id: u32,
    pub chain_type: ChainType,
    pub name: String,
    pub rpc_endpoint: String,
    pub ws_endpoint: Option<String>,
    pub bridge_address: String,
    pub verifier_address: Option<String>,
    pub assets: Vec<AssetConfig>,
    pub block_time_ms: u64,
    pub finality_blocks: u64,
    pub max_batch_size: usize,
    pub base_fee: u64,
    pub gas_oracle: Option<String>,
    pub enabled: bool,
}
```

---

### AssetConfig

Configuration for an asset on a chain.

```rust
pub struct AssetConfig {
    pub asset_type: u32,
    pub name: String,
    pub token_address: String,
    pub decimals: u8,
    pub min_deposit: u64,
    pub max_deposit: u64,
    pub enabled: bool,
}
```

---

### MultiChainConfig

Top-level multi-chain configuration.

```rust
pub struct MultiChainConfig {
    chains_map: HashMap<String, ChainConfig>,
    pub default_chain: Option<u32>,
}
```

**TOML Example:**

```toml
default_chain = 1

[chains.ethereum]
chain_id = 1
chain_type = "EVM"
name = "Ethereum"
rpc_endpoint = "https://eth-mainnet.g.alchemy.com/v2/..."
bridge_address = "0x1234567890123456789012345678901234567890"
block_time_ms = 12000
finality_blocks = 64
max_batch_size = 100
base_fee = 1000000
enabled = true

[[chains.ethereum.assets]]
asset_type = 1
name = "USDC"
token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
decimals = 6
min_deposit = 1000000
max_deposit = 1000000000000

[[chains.ethereum.assets]]
asset_type = 2
name = "USDT"
token_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
decimals = 6
min_deposit = 1000000
max_deposit = 1000000000000
```

---

## Cryptographic Types

### Groth16 Proof Format

Proofs are serialized in compressed format using `ark_serialize::CanonicalSerialize`.

**Structure:**

```
Proof {
    a: G1Affine,  // 32 bytes compressed
    b: G2Affine,  // 64 bytes compressed
    c: G1Affine,  // 32 bytes compressed
}
```

**Total size:** 128 bytes (compressed)

---

### Field Element Format

All field elements (BN254 scalar field, Fr) are:

- Serialized using `ark_serialize::CanonicalSerialize` (compressed)
- Encoded as hex strings with `0x` prefix
- 32 bytes (256 bits)

**Example:**

```
0x0102030405060708091011121314151617181920212223242526272829303132
```

---

### Merkle Path Format

Merkle paths are arrays of sibling hashes from leaf to root:

```json
{
  "path": [
    "0x1111...",  // Sibling at level 0 (leaf level)
    "0x2222...",  // Sibling at level 1
    "0x3333...",  // Sibling at level 2
    ...
  ],
  "leaf": "0x...",
  "index": 42
}
```

The `index` determines whether each sibling is on the left or right:
- If bit `i` of `index` is 0: sibling[i] is on the right
- If bit `i` of `index` is 1: sibling[i] is on the left

---

### Pedersen Commitment

Value commitments use the Pedersen commitment scheme:

```
C = v * G + r * H
```

Where:
- `v` is the value
- `r` is the randomness
- `G`, `H` are generator points on BN254 G1

The commitment is serialized as a compressed G1 point (32 bytes).

---

## Type Validation Rules

### Asset Type

- Must be a positive `u32` value
- Asset type `0` is reserved
- Common asset types:
  - `1`: USDC
  - `2`: USDT

### Chain ID

- Must be a positive `u32` value
- EVM chains use standard chain IDs (1 = Ethereum, 137 = Polygon, etc.)
- SVM chains use custom IDs (501 = Solana)

### Amounts

- Must be non-negative
- Represented in smallest unit (e.g., 6 decimals for USDC)
- Maximum value: `u64::MAX` for API, `u128::MAX` internally

### Hex Strings

- Must start with `0x` prefix
- Must contain valid hexadecimal characters (0-9, a-f, A-F)
- Field elements must be exactly 64 hex characters (32 bytes)
- Addresses must match chain format:
  - EVM: 40 hex characters (20 bytes)
  - SVM: Base58 encoded (32-44 characters)
