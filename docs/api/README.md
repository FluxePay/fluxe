# FLUXE API Documentation

FLUXE is a privacy-preserving, compliance-enabled cross-chain Layer 2 protocol built on zero-knowledge proofs. This documentation covers the REST API for interacting with FLUXE services.

## Overview

The FLUXE API provides endpoints for:

- **Transaction submission**: Mint, burn, transfer, and object update operations
- **State queries**: Access current Merkle roots and asset supply information
- **Proof queries**: Retrieve membership and non-membership proofs
- **Multi-chain operations**: Support for EVM and SVM chains
- **Batch processing**: Manage transaction batching

## Base URL

```
Production: https://api.fluxe.network
Staging:    https://staging-api.fluxe.network
Local:      http://localhost:3000
```

## Authentication

Currently, the FLUXE API does not require authentication for public endpoints. Future versions may introduce API keys for rate limiting and access control.

## Response Format

All API responses follow a consistent JSON structure:

```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```

### Success Response

```json
{
  "success": true,
  "data": {
    "transaction_id": "mint_tx_1"
  },
  "error": null
}
```

### Error Response

```json
{
  "success": false,
  "data": null,
  "error": "Chain is not enabled"
}
```

## Quick Start

### 1. Check API Health

```bash
curl -X GET http://localhost:3000/health
```

Response:
```json
{
  "success": true,
  "data": "OK",
  "error": null
}
```

### 2. Get API Information

```bash
curl -X GET http://localhost:3000/info
```

Response:
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

### 3. List Supported Chains

```bash
curl -X GET http://localhost:3000/chains
```

Response:
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

### 4. Get Current State Roots

```bash
curl -X GET http://localhost:3000/state/roots
```

Response:
```json
{
  "success": true,
  "data": {
    "cmt_root": "0x1234...",
    "nft_root": "0x5678...",
    "obj_root": "0x9abc...",
    "cb_root": "0xdef0...",
    "ingress_root": "0x1111...",
    "exit_root": "0x2222...",
    "sanctions_root": "0x3333...",
    "pool_rules_root": "0x4444..."
  },
  "error": null
}
```

### 5. Submit a Mint Transaction

```bash
curl -X POST http://localhost:3000/chain/1/submit/mint \
  -H "Content-Type: application/json" \
  -d '{
    "asset_type": 1,
    "amount": 1000000,
    "proof": "...",
    "public_inputs": ["0x..."],
    "notes_out": [...]
  }'
```

## Documentation Structure

- **[ENDPOINTS.md](./ENDPOINTS.md)** - Complete API endpoint reference
- **[CLIENT.md](./CLIENT.md)** - Rust client SDK documentation
- **[TYPES.md](./TYPES.md)** - Data type definitions and schemas

## Supported Chains

FLUXE supports two chain types:

| Chain Type | Description | Examples |
|------------|-------------|----------|
| EVM | Ethereum Virtual Machine | Ethereum, Arbitrum, Base, Polygon |
| SVM | Solana Virtual Machine | Solana |

## Rate Limits

| Endpoint Type | Rate Limit |
|---------------|------------|
| Read (GET) | 100 requests/minute |
| Write (POST) | 20 requests/minute |
| Batch Processing | 5 requests/minute |

## Error Codes

| HTTP Status | Description |
|-------------|-------------|
| 200 | Success (check `success` field in response) |
| 400 | Bad Request - Invalid parameters |
| 404 | Not Found - Resource not found |
| 500 | Internal Server Error |

## Cryptographic Primitives

FLUXE uses the following cryptographic primitives:

- **Curve**: BN254 (alt_bn128)
- **Hash Function**: Poseidon
- **Proof System**: Groth16
- **Commitment Scheme**: Pedersen

All field elements are serialized as hex strings with `0x` prefix in compressed format.

## Related Resources

- [FLUXE Specification](../FLUXE.md)
- [Deployment Roadmap](../DEPLOYMENT_ROADMAP.md)
- [Rapidsnark Integration Guide](../../RAPIDSNARK_GUIDE.md)
