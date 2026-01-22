# Multi-Chain API Reference

## Overview

The FluxeAPI now supports multi-chain operations with chain-specific routes and global queries across all chains.

## Base URL

```
http://localhost:8080
```

---

## Chain Management Endpoints

### GET /chains

List all supported chains and their configurations.

**Response**:
```json
{
  "success": true,
  "data": [
    {
      "chain_id": 1,
      "chain_type": "EVM",
      "name": "Ethereum Mainnet",
      "enabled": true,
      "block_time_ms": 12000,
      "finality_blocks": 32,
      "supported_assets": [1, 2, 3]
    },
    {
      "chain_id": 501,
      "chain_type": "SVM",
      "name": "Solana Mainnet",
      "enabled": true,
      "block_time_ms": 400,
      "finality_blocks": 32,
      "supported_assets": [1, 2, 3]
    }
  ],
  "error": null
}
```

---

## Chain-Specific Transaction Submission

### POST /chain/:chain_id/submit/mint

Submit a mint transaction to a specific chain.

**Parameters**:
- `chain_id` (path): Chain identifier (e.g., 1 for Ethereum, 501 for Solana)

**Request Body**:
```json
{
  "asset_type": 1,
  "amount": 1000000,
  "proof": [/* proof bytes */],
  "public_inputs": ["0x...", "0x..."],
  "notes_out": [
    {
      "asset_type": 1,
      "owner_addr": "0x123...",
      "psi": [/* 32 bytes */],
      "chain_hint": 1,
      "pool_id": 0
    }
  ]
}
```

**Response**:
```json
{
  "success": true,
  "data": "chain_1_mint_123",
  "error": null
}
```

**Error Cases**:
- `400 BAD_REQUEST`: Invalid chain_id
- `503 SERVICE_UNAVAILABLE`: Chain is disabled
- `400 BAD_REQUEST`: Asset not supported on chain

---

### POST /chain/:chain_id/submit/burn

Submit a burn transaction to a specific chain.

**Parameters**:
- `chain_id` (path): Chain identifier

**Request Body**:
```json
{
  "asset_type": 1,
  "amount": 1000000,
  "nullifier": "0x456...",
  "proof": [/* proof bytes */],
  "public_inputs": ["0x...", "0x..."]
}
```

**Response**:
```json
{
  "success": true,
  "data": "chain_1_burn_456",
  "error": null
}
```

---

### POST /chain/:chain_id/submit/transfer

Submit a private transfer transaction to a specific chain.

**Parameters**:
- `chain_id` (path): Chain identifier

**Request Body**:
```json
{
  "nullifiers": ["0x...", "0x..."],
  "proof": [/* proof bytes */],
  "public_inputs": ["0x...", "0x..."],
  "notes_out": [
    {
      "asset_type": 1,
      "owner_addr": "0x789...",
      "psi": [/* 32 bytes */],
      "chain_hint": 1,
      "pool_id": 0
    }
  ]
}
```

**Response**:
```json
{
  "success": true,
  "data": "chain_1_transfer_789",
  "error": null
}
```

---

### POST /chain/:chain_id/submit/object_update

Submit a compliance object update transaction to a specific chain.

**Parameters**:
- `chain_id` (path): Chain identifier

**Request Body**:
```json
{
  "old_object_cm": "0xabc...",
  "new_object_cm": "0xdef...",
  "proof": [/* proof bytes */],
  "public_inputs": ["0x...", "0x..."],
  "callback_operations": [
    {
      "op_type": "add",
      "ticket": "0x111...",
      "payload": [/* bytes */],
      "timestamp": 1234567890,
      "signature": [/* bytes */]
    }
  ]
}
```

**Response**:
```json
{
  "success": true,
  "data": "chain_1_object_012",
  "error": null
}
```

---

## Chain-Specific State Queries

### GET /chain/:chain_id/state/roots

Get state roots for a specific chain.

**Parameters**:
- `chain_id` (path): Chain identifier

**Response**:
```json
{
  "success": true,
  "data": {
    "cmt_root": "0x123...",
    "nft_root": "0x456...",
    "obj_root": "0x789...",
    "cb_root": "0xabc...",
    "ingress_root": "0xdef...",
    "exit_root": "0x012...",
    "sanctions_root": "0x345...",
    "pool_rules_root": "0x678...",
    "chain_id": 1
  },
  "error": null
}
```

---

### GET /chain/:chain_id/state/supply/:asset_type

Get supply information for a specific asset on a specific chain.

**Parameters**:
- `chain_id` (path): Chain identifier
- `asset_type` (path): Asset type identifier

**Response**:
```json
{
  "success": true,
  "data": {
    "asset_type": 1,
    "minted_total": 1000000000,
    "burned_total": 100000000,
    "current_supply": 900000000,
    "chain_id": 1
  },
  "error": null
}
```

**Error Cases**:
- `400 BAD_REQUEST`: Invalid chain_id
- `400 BAD_REQUEST`: Asset not supported on chain

---

### GET /chain/:chain_id/batch/status

Get batch processing status for a specific chain.

**Parameters**:
- `chain_id` (path): Chain identifier

**Response**:
```json
{
  "success": true,
  "data": {
    "chain_id": 1,
    "pending_transactions": 42,
    "last_block": 12345,
    "last_processed": "2024-01-01T12:00:00Z"
  },
  "error": null
}
```

---

## Global State Queries

### GET /state/global/roots

Get global state roots across all chains (CMT, NFT, OBJ, CB trees).

**Response**:
```json
{
  "success": true,
  "data": {
    "cmt_root": "0x123...",
    "nft_root": "0x456...",
    "obj_root": "0x789...",
    "cb_root": "0xabc...",
    "ingress_root": "0xdef...",
    "exit_root": "0x012...",
    "sanctions_root": "0x345...",
    "pool_rules_root": "0x678...",
    "chain_id": null
  },
  "error": null
}
```

**Note**: `chain_id` is `null` for global queries.

---

### GET /state/global/supply/:asset_type

Get total supply across all chains for a specific asset.

**Parameters**:
- `asset_type` (path): Asset type identifier

**Response**:
```json
{
  "success": true,
  "data": {
    "asset_type": 1,
    "minted_total": 5000000000,
    "burned_total": 500000000,
    "current_supply": 4500000000,
    "chain_id": null
  },
  "error": null
}
```

**Note**: This aggregates supply across all configured chains.

---

## Legacy Single-Chain Endpoints

All existing endpoints are maintained for backward compatibility:

- `POST /submit/mint`
- `POST /submit/burn`
- `POST /submit/transfer`
- `POST /submit/object_update`
- `GET /state/roots`
- `GET /state/supply/:asset_type`
- `GET /batch/status`

These routes use the default chain if configured, otherwise return an error.

---

## Error Response Format

All endpoints return errors in a consistent format:

```json
{
  "success": false,
  "data": null,
  "error": "Error message describing what went wrong"
}
```

### Common HTTP Status Codes

- `200 OK`: Request succeeded
- `400 BAD_REQUEST`: Invalid parameters or chain_id
- `503 SERVICE_UNAVAILABLE`: Chain is disabled
- `500 INTERNAL_SERVER_ERROR`: Server processing error

---

## Usage Examples

### cURL Examples

**List chains**:
```bash
curl http://localhost:8080/chains
```

**Submit mint on Ethereum (chain_id = 1)**:
```bash
curl -X POST http://localhost:8080/chain/1/submit/mint \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": 1,
    "amount": 1000000,
    "proof": [],
    "public_inputs": ["0x01"],
    "notes_out": []
  }'
```

**Get Solana state roots (chain_id = 501)**:
```bash
curl http://localhost:8080/chain/501/state/roots
```

**Get global supply for USDC (asset_type = 1)**:
```bash
curl http://localhost:8080/state/global/supply/1
```

---

### Rust Client Example

```rust
use fluxe_api::{FluxeApi, SubmitMintRequest, ChainInfo};
use fluxe_core::config::MultiChainConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load chain configuration
    let config = MultiChainConfig::from_file("config/chains.toml")?;

    // Create HTTP client
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8080";

    // List supported chains
    let chains: Vec<ChainInfo> = client
        .get(&format!("{}/chains", base_url))
        .send()
        .await?
        .json()
        .await?;

    println!("Supported chains: {:#?}", chains);

    // Submit mint to Ethereum (chain_id = 1)
    let mint_request = SubmitMintRequest {
        asset_type: 1,
        amount: 1_000_000,
        proof: vec![],
        public_inputs: vec!["0x01".to_string()],
        notes_out: vec![],
    };

    let response = client
        .post(&format!("{}/chain/1/submit/mint", base_url))
        .json(&mint_request)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    println!("Mint response: {:#?}", response);

    Ok(())
}
```

---

### JavaScript/TypeScript Example

```typescript
const BASE_URL = 'http://localhost:8080';

// List supported chains
async function listChains() {
  const response = await fetch(`${BASE_URL}/chains`);
  const data = await response.json();
  return data.data; // Array of ChainInfo
}

// Submit mint on specific chain
async function submitMint(chainId: number, request: any) {
  const response = await fetch(`${BASE_URL}/chain/${chainId}/submit/mint`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  return await response.json();
}

// Get global supply
async function getGlobalSupply(assetType: number) {
  const response = await fetch(`${BASE_URL}/state/global/supply/${assetType}`);
  const data = await response.json();
  return data.data;
}

// Usage
(async () => {
  const chains = await listChains();
  console.log('Supported chains:', chains);

  const mintResult = await submitMint(1, {
    asset_type: 1,
    amount: 1000000,
    proof: [],
    public_inputs: ['0x01'],
    notes_out: [],
  });
  console.log('Mint result:', mintResult);
})();
```

---

## Chain Configuration

Chains are configured in `config/chains.toml`:

```toml
[chains.ethereum]
chain_id = 1
chain_type = "EVM"
name = "Ethereum Mainnet"
rpc_endpoint = "https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY"
bridge_address = "0x..."
verifier_address = "0x..."
block_time_ms = 12000
finality_blocks = 32
max_batch_size = 100

[[chains.ethereum.assets]]
asset_type = 1
name = "USDC"
token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
decimals = 6
min_deposit = 1000000
max_deposit = 1000000000000
enabled = true

[chains.solana]
chain_id = 501
chain_type = "SVM"
name = "Solana Mainnet"
rpc_endpoint = "https://api.mainnet-beta.solana.com"
bridge_address = "FLUXEBridgeXXXXXXXXXXXXXXXXXXXXXXXXXXX"
block_time_ms = 400
finality_blocks = 32
max_batch_size = 100

[[chains.solana.assets]]
asset_type = 1
name = "USDC"
token_address = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
decimals = 6
min_deposit = 1000000
max_deposit = 1000000000000
enabled = true
```

---

## Migration Guide

### For Existing Single-Chain Clients

Your existing code will continue to work without changes:

**Before** (still works):
```rust
POST /submit/mint
GET /state/roots
```

**After** (recommended for multi-chain):
```rust
POST /chain/1/submit/mint
GET /chain/1/state/roots
```

### For New Multi-Chain Clients

1. Start by listing available chains: `GET /chains`
2. Choose target chain based on user preference or liquidity
3. Use chain-specific endpoints: `/chain/:chain_id/...`
4. Monitor global state with: `/state/global/...`

---

## Performance Notes

- Chain validation is O(1) using HashMap lookup
- No additional latency for chain-specific routes
- Global queries aggregate data from all chains (may be slower)

---

## Security Notes

- Chain IDs are validated before processing
- Disabled chains return 503 errors immediately
- Asset support is validated per chain
- All validation happens before state modification

---

## Future Enhancements

Planned for future releases:

1. **Cross-chain transfer routes**: Direct transfers between chains
2. **Chain-specific batch queries**: Query batches by chain
3. **Supply rebalancing endpoints**: Manual rebalancing triggers
4. **Chain health monitoring**: Per-chain uptime and status
