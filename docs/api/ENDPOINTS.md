# FLUXE API Endpoints Reference

This document provides a complete reference for all FLUXE API endpoints.

## Table of Contents

- [Health and Info](#health-and-info)
- [Chain Management](#chain-management)
- [Transaction Submission](#transaction-submission)
  - [Legacy Endpoints](#legacy-endpoints-default-chain)
  - [Chain-Specific Endpoints](#chain-specific-endpoints)
- [State Queries](#state-queries)
- [Proof Queries](#proof-queries)
- [Batch Processing](#batch-processing)

---

## Health and Info

### GET /health

Check if the API server is running.

**Response:**

```json
{
  "success": true,
  "data": "OK",
  "error": null
}
```

---

### GET /info

Get API server information.

**Response:**

```json
{
  "success": true,
  "data": {
    "name": "Fluxe Privacy & Compliance Protocol",
    "version": "0.1.0",
    "description": "ZK-based private stablecoin with compliance",
    "spec_version": "v0.2"
  },
  "error": null
}
```

---

## Chain Management

### GET /chains

List all supported chains with their configuration.

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "chain_id": 1,
      "chain_type": "EVM",
      "name": "Ethereum",
      "enabled": true,
      "block_time_ms": 12000,
      "finality_blocks": 64,
      "supported_assets": [1, 2]
    },
    {
      "chain_id": 501,
      "chain_type": "SVM",
      "name": "Solana",
      "enabled": true,
      "block_time_ms": 400,
      "finality_blocks": 32,
      "supported_assets": [1]
    }
  ],
  "error": null
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `chain_id` | `u32` | Unique chain identifier |
| `chain_type` | `string` | Chain type: "EVM" or "SVM" |
| `name` | `string` | Human-readable chain name |
| `enabled` | `bool` | Whether the chain is currently active |
| `block_time_ms` | `u64` | Average block time in milliseconds |
| `finality_blocks` | `u64` | Number of blocks for finality |
| `supported_assets` | `[u32]` | List of supported asset type IDs |

---

## Transaction Submission

### Legacy Endpoints (Default Chain)

These endpoints operate on the default configured chain (typically chain 1).

#### POST /submit/mint

Submit a mint transaction to deposit assets into the FLUXE protocol.

**Request Body:**

```json
{
  "asset_type": 1,
  "amount": 1000000,
  "proof": "<base64-encoded-groth16-proof>",
  "public_inputs": [
    "0x1234567890abcdef...",
    "0xfedcba0987654321..."
  ],
  "notes_out": [
    {
      "asset_type": 1,
      "owner_addr": "0x...",
      "psi": "<32-bytes-base64>",
      "chain_hint": 1,
      "pool_id": 1
    }
  ]
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `asset_type` | `u32` | Yes | Asset type identifier (e.g., 1 = USDC) |
| `amount` | `u64` | Yes | Amount in smallest unit (e.g., 1000000 = 1 USDC) |
| `proof` | `[u8]` | Yes | Serialized Groth16 proof bytes |
| `public_inputs` | `[string]` | Yes | Hex-encoded field elements |
| `notes_out` | `[Note]` | Yes | Output notes created by this mint |

**Response:**

```json
{
  "success": true,
  "data": "mint_tx_1",
  "error": null
}
```

---

#### POST /submit/burn

Submit a burn transaction to withdraw assets from the FLUXE protocol.

**Request Body:**

```json
{
  "asset_type": 1,
  "amount": 500000,
  "nullifier": "0x...",
  "proof": "<base64-encoded-groth16-proof>",
  "public_inputs": [
    "0x..."
  ]
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `asset_type` | `u32` | Yes | Asset type identifier |
| `amount` | `u64` | Yes | Amount to burn in smallest unit |
| `nullifier` | `string` | Yes | Hex-encoded nullifier of the note being burned |
| `proof` | `[u8]` | Yes | Serialized Groth16 proof bytes |
| `public_inputs` | `[string]` | Yes | Hex-encoded field elements |

**Response:**

```json
{
  "success": true,
  "data": "burn_tx_1",
  "error": null
}
```

---

#### POST /submit/transfer

Submit a private transfer transaction.

**Request Body:**

```json
{
  "nullifiers": [
    "0x...",
    "0x..."
  ],
  "proof": "<base64-encoded-groth16-proof>",
  "public_inputs": [
    "0x..."
  ],
  "notes_out": [
    {
      "asset_type": 1,
      "owner_addr": "0x...",
      "psi": "<32-bytes-base64>",
      "chain_hint": 1,
      "pool_id": 1
    }
  ]
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `nullifiers` | `[string]` | Yes | Hex-encoded nullifiers of input notes |
| `proof` | `[u8]` | Yes | Serialized Groth16 proof bytes |
| `public_inputs` | `[string]` | Yes | Hex-encoded field elements |
| `notes_out` | `[Note]` | Yes | Output notes created by this transfer |

**Response:**

```json
{
  "success": true,
  "data": "transfer_tx",
  "error": null
}
```

---

#### POST /submit/object_update

Submit a ZK object state update transaction.

**Request Body:**

```json
{
  "old_object_cm": "0x...",
  "new_object_cm": "0x...",
  "proof": "<base64-encoded-groth16-proof>",
  "public_inputs": [
    "0x..."
  ],
  "callback_operations": [
    {
      "op_type": "add",
      "ticket": "0x...",
      "payload": "<base64-bytes>",
      "timestamp": 1704067200,
      "signature": "<base64-signature>"
    },
    {
      "op_type": "process",
      "ticket": "0x..."
    }
  ]
}
```

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `old_object_cm` | `string` | Yes | Hex-encoded old object commitment |
| `new_object_cm` | `string` | Yes | Hex-encoded new object commitment |
| `proof` | `[u8]` | Yes | Serialized Groth16 proof bytes |
| `public_inputs` | `[string]` | Yes | Hex-encoded field elements |
| `callback_operations` | `[CallbackOp]` | Yes | List of callback operations |

**Callback Operation Types:**

| `op_type` | Required Fields | Description |
|-----------|-----------------|-------------|
| `add` | `ticket`, `payload`, `timestamp`, `signature` | Add a new callback invocation |
| `process` | `ticket` | Mark a callback as processed |

**Response:**

```json
{
  "success": true,
  "data": "object_update_tx",
  "error": null
}
```

---

### Chain-Specific Endpoints

These endpoints allow specifying the target chain explicitly.

#### POST /chain/{chain_id}/submit/mint

Submit a mint transaction to a specific chain.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `chain_id` | `u32` | Target chain identifier |

**Request Body:** Same as `POST /submit/mint`

**Response:**

```json
{
  "success": true,
  "data": "chain_1_mint_mint_tx_1",
  "error": null
}
```

**Error Response (Chain Disabled):**

```json
{
  "success": false,
  "data": null,
  "error": "Chain is not enabled"
}
```

**Error Response (Asset Not Supported):**

```json
{
  "success": false,
  "data": null,
  "error": "Asset type 3 is not supported on chain 1"
}
```

---

#### POST /chain/{chain_id}/submit/burn

Submit a burn transaction to a specific chain.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `chain_id` | `u32` | Target chain identifier |

**Request Body:** Same as `POST /submit/burn`

---

#### POST /chain/{chain_id}/submit/transfer

Submit a transfer transaction on a specific chain.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `chain_id` | `u32` | Target chain identifier |

**Request Body:** Same as `POST /submit/transfer`

---

#### POST /chain/{chain_id}/submit/object_update

Submit an object update transaction on a specific chain.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `chain_id` | `u32` | Target chain identifier |

**Request Body:** Same as `POST /submit/object_update`

---

## State Queries

### GET /state/roots

Get current state roots for the default chain.

**Response:**

```json
{
  "success": true,
  "data": {
    "cmt_root": "0x0102030405060708091011121314151617181920212223242526272829303132",
    "nft_root": "0x...",
    "obj_root": "0x...",
    "cb_root": "0x...",
    "ingress_root": "0x...",
    "exit_root": "0x...",
    "sanctions_root": "0x...",
    "pool_rules_root": "0x..."
  },
  "error": null
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `cmt_root` | `string` | Commitment tree root (note commitments) |
| `nft_root` | `string` | Nullifier tree root (sorted Merkle tree) |
| `obj_root` | `string` | Object board root (ZK objects) |
| `cb_root` | `string` | Callback board root |
| `ingress_root` | `string` | Ingress receipt tree root (deposits) |
| `exit_root` | `string` | Exit receipt tree root (withdrawals) |
| `sanctions_root` | `string` | Sanctions list root |
| `pool_rules_root` | `string` | Pool policy rules root |
| `chain_id` | `u32?` | Chain ID (only for chain-specific queries) |

---

### GET /state/supply/{asset_type}

Get supply information for a specific asset.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `asset_type` | `u32` | Asset type identifier |

**Response:**

```json
{
  "success": true,
  "data": {
    "asset_type": 1,
    "minted_total": 10000000000,
    "burned_total": 2500000000,
    "current_supply": 7500000000
  },
  "error": null
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `asset_type` | `u32` | Asset type identifier |
| `minted_total` | `u64` | Total amount ever minted |
| `burned_total` | `u64` | Total amount ever burned |
| `current_supply` | `u64` | Current circulating supply |
| `chain_id` | `u32?` | Chain ID (only for chain-specific queries) |

---

### GET /chain/{chain_id}/state/roots

Get state roots for a specific chain.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `chain_id` | `u32` | Chain identifier |

**Response:** Same as `GET /state/roots` with `chain_id` field populated.

---

### GET /chain/{chain_id}/state/supply/{asset_type}

Get supply information for a specific asset on a specific chain.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `chain_id` | `u32` | Chain identifier |
| `asset_type` | `u32` | Asset type identifier |

---

### GET /state/global/roots

Get global state roots (protocol-wide, not chain-specific).

**Response:**

```json
{
  "success": true,
  "data": {
    "cmt_root": "0x...",
    "nft_root": "0x...",
    "obj_root": "0x...",
    "cb_root": "0x...",
    "ingress_root": "0x...",
    "exit_root": "0x...",
    "sanctions_root": "0x...",
    "pool_rules_root": "0x..."
  },
  "error": null
}
```

---

### GET /state/global/supply/{asset_type}

Get global supply information for an asset across all chains.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `asset_type` | `u32` | Asset type identifier |

---

## Proof Queries

### GET /proofs/commitment/{cm}

Get a membership proof for a note commitment.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `cm` | `string` | Hex-encoded commitment |

**Response (Commitment Exists):**

```json
{
  "success": true,
  "data": {
    "exists": true,
    "path": [
      "0x1111...",
      "0x2222...",
      "0x3333..."
    ],
    "leaf": "0x...",
    "index": 42
  },
  "error": null
}
```

**Response (Commitment Not Found):**

```json
{
  "success": true,
  "data": {
    "exists": false,
    "path": null,
    "leaf": null,
    "index": null
  },
  "error": null
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `exists` | `bool` | Whether the commitment exists in the tree |
| `path` | `[string]?` | Merkle path siblings (hex-encoded) |
| `leaf` | `string?` | Leaf value (hex-encoded) |
| `index` | `usize?` | Leaf index in the tree |

---

### GET /proofs/nullifier/{nf}

Get a membership or non-membership proof for a nullifier.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `nf` | `string` | Hex-encoded nullifier |

**Response (Nullifier Exists - Already Spent):**

```json
{
  "success": true,
  "data": {
    "exists": true,
    "path": ["0x..."],
    "leaf": "0x...",
    "index": 15
  },
  "error": null
}
```

**Response (Nullifier Not Found - Can Be Spent):**

```json
{
  "success": true,
  "data": {
    "exists": false,
    "path": ["0x..."],
    "leaf": "0x...",
    "index": 14
  },
  "error": null
}
```

Note: For non-membership proofs, the path and leaf refer to the gap proof (predecessor leaf in the sorted tree).

---

### GET /proofs/object/{obj}

Get a membership proof for an object commitment.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `obj` | `string` | Hex-encoded object commitment |

**Response:** Same structure as commitment proof.

---

### GET /proofs/sanctions/{addr}

Check if an address is sanctioned and get a non-membership proof.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `addr` | `string` | Hex-encoded address |

**Response (Not Sanctioned):**

```json
{
  "success": true,
  "data": {
    "exists": true,
    "path": ["0x..."],
    "leaf": null,
    "index": null
  },
  "error": null
}
```

Note: `exists: true` means a non-membership proof exists (address is NOT sanctioned).

---

## Batch Processing

### POST /batch/process

Trigger batch processing of pending transactions.

**Response:**

```json
{
  "success": true,
  "data": "Block 42 created",
  "error": null
}
```

---

### GET /batch/status

Get current batch processing status for the default chain.

**Response:**

```json
{
  "success": true,
  "data": {
    "pending_transactions": 15,
    "last_block": 41,
    "last_processed": "2024-01-01T00:00:00Z"
  },
  "error": null
}
```

---

### GET /chain/{chain_id}/batch/status

Get batch processing status for a specific chain.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `chain_id` | `u32` | Chain identifier |

**Response:**

```json
{
  "success": true,
  "data": {
    "chain_id": 1,
    "pending_transactions": 15,
    "last_block": 41,
    "last_processed": "2024-01-01T00:00:00Z"
  },
  "error": null
}
```

---

## Error Handling

All errors are returned in the standard response format:

```json
{
  "success": false,
  "data": null,
  "error": "Error message describing what went wrong"
}
```

### Common Error Messages

| Error | Description |
|-------|-------------|
| `Chain is not enabled` | The specified chain is disabled in configuration |
| `Asset type X is not supported on chain Y` | The asset is not configured for the chain |
| `Invalid hex: ...` | Malformed hex-encoded field |
| `Failed to deserialize proof: ...` | Invalid Groth16 proof format |
| `Invalid field element: ...` | Field element outside valid range |
| `Chain not found` | Chain ID does not exist |
| `Insufficient supply to burn` | Burn amount exceeds available supply |

---

## HTTP Status Codes

| Status | Description |
|--------|-------------|
| 200 | Request processed (check `success` field) |
| 400 | Bad request - invalid chain ID or path parameters |
| 500 | Internal server error |

Note: Most application-level errors return HTTP 200 with `success: false` in the response body.
