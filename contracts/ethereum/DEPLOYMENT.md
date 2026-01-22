# FLUXE Ethereum Contract Deployment Guide

## Prerequisites

1. **Foundry** - Install from https://getfoundry.sh
2. **ETH for gas** - Fund your deployer wallet with Sepolia ETH
3. **RPC endpoint** - Get one from Alchemy, Infura, or similar

## Quick Start

### 1. Set up environment

```bash
cd contracts/ethereum
cp .env.example .env
# Edit .env with your values
```

### 2. Deploy contracts

```bash
# Load environment variables
source .env

# Deploy to Sepolia (dry-run first)
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL

# Deploy with broadcast
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast

# Deploy with verification
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast --verify
```

### 3. Verify deployment

```bash
# Set contract addresses from deployment output
export VERIFIER_ADDRESS=0x...
export ROLLUP_ADDRESS=0x...
export BRIDGE_ADDRESS=0x...

# Run verification script
forge script script/Deploy.s.sol:VerifyDeploymentScript --rpc-url $SEPOLIA_RPC_URL
```

### 4. Register assets

```bash
# Set bridge address and token addresses
export BRIDGE_ADDRESS=0x...
export WETH_ADDRESS=0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9  # Sepolia WETH

# Register assets
forge script script/Deploy.s.sol:RegisterAssetsScript --rpc-url $SEPOLIA_RPC_URL --broadcast
```

## Contract Architecture

```
┌─────────────────────┐
│  Groth16Verifier    │  ← Verifies ZK proofs
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│    FluxeRollup      │  ← Manages state roots & batches
│  - verifier         │
│  - sequencer        │
│  - finalizedBatches │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│    FluxeBridge      │  ← Handles deposits & withdrawals
│  - rollup           │
│  - chainId          │
│  - poolBalances     │
└─────────────────────┘
```

## Deployment Order

1. **Groth16Verifier** - No dependencies
2. **FluxeRollup** - Requires verifier address
3. **FluxeBridge** - Requires rollup address

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PRIVATE_KEY` | Yes | Deployer private key |
| `SEPOLIA_RPC_URL` | Yes | Sepolia RPC endpoint |
| `ETHERSCAN_API_KEY` | No | For contract verification |
| `SEQUENCER_ADDRESS` | No | Defaults to deployer |
| `BRIDGE_CHAIN_ID` | No | Defaults to 11155111 (Sepolia) |

### Chain IDs

| Network | Chain ID |
|---------|----------|
| Ethereum Mainnet | 1 |
| Sepolia Testnet | 11155111 |
| Goerli Testnet | 5 |

## Post-Deployment

### 1. Transfer Sequencer Role (if needed)

```solidity
// Owner initiates transfer
rollup.initiateSequencerTransfer(newSequencerAddress);

// New sequencer accepts
rollup.acceptSequencer();
```

### 2. Register Assets

```solidity
// Register WETH with limits
bridge.registerAsset(
    1,                  // assetType
    wethAddress,        // token address
    0.001 ether,        // minDeposit
    100 ether           // maxDeposit
);
```

### 3. Monitor Events

```solidity
// Key events to monitor
event BatchSubmitted(uint64 indexed batchId, bytes32 indexed stateRootsHash, uint32 txCount, uint64 timestamp);
event Deposit(uint32 indexed assetType, uint256 amount, bytes32 beneficiaryCm, bytes32 indexed ingressReceiptHash, uint64 nonce, address indexed depositor);
event Withdrawal(uint32 indexed assetType, uint256 amount, address indexed recipient, bytes32 indexed exitReceiptHash, uint64 batchId);
```

## Security Considerations

1. **Verification Key** - The Groth16Verifier uses PLACEHOLDER values. Before mainnet:
   - Generate real VK from trusted setup
   - Update verifier contract constants
   - Redeploy and verify

2. **Access Control**
   - Only sequencer can submit batches
   - Only owner can register assets and pause contracts
   - Two-step sequencer transfer prevents accidents

3. **Pause Mechanism**
   - Both contracts support pause/unpause
   - Use for emergency security response

## Troubleshooting

### Common Issues

1. **"OnlySequencer" error** - Only the designated sequencer can submit batches
2. **"InvalidBatchId" error** - Batch IDs must be sequential
3. **"AssetNotRegistered" error** - Register asset before deposits

### Gas Estimates

| Operation | Estimated Gas |
|-----------|---------------|
| Deploy Groth16Verifier | ~800,000 |
| Deploy FluxeRollup | ~1,200,000 |
| Deploy FluxeBridge | ~1,500,000 |
| Submit Batch | ~250,000 |
| Deposit | ~140,000 |
| Withdrawal | ~100,000 |

## Testnet Addresses

After deployment, update these addresses:

```
Sepolia:
- Groth16Verifier: 0x...
- FluxeRollup: 0x...
- FluxeBridge: 0x...
```
