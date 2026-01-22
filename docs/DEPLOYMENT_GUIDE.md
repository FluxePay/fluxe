# FLUXE Protocol Deployment Guide

**Version**: 1.0
**Last Updated**: 2025-01-22

This guide covers the complete deployment of the FLUXE privacy protocol, including:
- Backend infrastructure (sequencer, SP1 aggregation)
- Mobile app integration (React Native + Mopro)
- On-chain contracts
- Client-side proof generation

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Phase 1: Circuit Setup & Key Generation](#3-phase-1-circuit-setup--key-generation)
4. [Phase 2: Backend Infrastructure](#4-phase-2-backend-infrastructure)
5. [Phase 3: Mobile App Integration](#5-phase-3-mobile-app-integration)
6. [Phase 4: On-Chain Contracts](#6-phase-4-on-chain-contracts)
7. [Phase 5: End-to-End Testing](#7-phase-5-end-to-end-testing)
8. [Production Deployment](#8-production-deployment)
9. [Monitoring & Operations](#9-monitoring--operations)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           FLUXE ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌─────────────────────┐         ┌─────────────────────────────────┐   │
│   │   MOBILE APP        │         │      FLUXE SEQUENCER            │   │
│   │   (React Native)    │         │                                 │   │
│   │                     │  HTTP   │  ┌───────────────────────────┐  │   │
│   │  ┌───────────────┐  │ ──────► │  │   Transaction Processor   │  │   │
│   │  │ Mopro Native  │  │         │  │   • Verify Groth16 proofs │  │   │
│   │  │ Proof Gen     │  │         │  │   • Update state trees    │  │   │
│   │  │ (rapidsnark)  │  │         │  │   • Batch transactions    │  │   │
│   │  └───────────────┘  │         │  └───────────────────────────┘  │   │
│   │         │           │         │              │                   │   │
│   │         ▼           │         │              ▼                   │   │
│   │  ┌───────────────┐  │         │  ┌───────────────────────────┐  │   │
│   │  │ Circuit Keys  │  │         │  │   SP1 Aggregation         │  │   │
│   │  │ (.zkey files) │  │         │  │   • Verify all proofs     │  │   │
│   │  └───────────────┘  │         │  │   • Generate aggregate    │  │   │
│   └─────────────────────┘         │  │   • ~10M cycles/proof     │  │   │
│                                   │  └───────────────────────────┘  │   │
│                                   │              │                   │   │
│                                   └──────────────┼───────────────────┘   │
│                                                  │                       │
│                        ┌─────────────────────────┼─────────────────────┐ │
│                        │                         ▼                     │ │
│                        │   ┌───────────────────────────────────────┐   │ │
│                        │   │         ON-CHAIN SETTLEMENT           │   │ │
│                        │   └───────────────────────────────────────┘   │ │
│                        │          │                      │             │ │
│                        │          ▼                      ▼             │ │
│                        │   ┌────────────┐        ┌────────────┐       │ │
│                        │   │ Ethereum   │        │  Solana    │       │ │
│                        │   │ Bridge     │        │  Bridge    │       │ │
│                        │   │ (Solidity) │        │  (Anchor)  │       │ │
│                        │   └────────────┘        └────────────┘       │ │
│                        └───────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Description | Technology |
|-----------|-------------|------------|
| **Mobile App** | User wallet with native proof generation | React Native + Expo + Mopro |
| **Mopro** | Native proof generator using rapidsnark | Rust + Swift/Kotlin |
| **Sequencer** | Transaction processing and batching | Rust (axum) |
| **SP1 Aggregation** | zkVM proof aggregation | SP1 + BN254 pairings |
| **Ethereum Bridge** | EVM deposit/withdrawal contracts | Solidity |
| **Solana Bridge** | SVM deposit/withdrawal program | Anchor/Rust |

---

## 2. Prerequisites

### 2.1 Development Environment

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
rustup target add wasm32-unknown-unknown  # For circuits

# Node.js (for snarkjs and app)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
npm install -g snarkjs yarn

# Circom (optional, for custom circuits)
git clone https://github.com/iden3/circom.git
cd circom && cargo build --release
sudo cp target/release/circom /usr/local/bin/

# Rapidsnark
git clone https://github.com/nickovs/rapidsnark.git
cd rapidsnark
./build_gmp.sh host
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo cp prover /usr/local/bin/rapidsnark-prover

# SP1 toolchain
curl -L https://sp1.succinct.xyz | bash
sp1up
```

### 2.2 Mobile Development

```bash
# React Native / Expo
npm install -g expo-cli eas-cli

# iOS (macOS only)
xcode-select --install
sudo gem install cocoapods

# Android
# Install Android Studio with NDK 26+
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools
```

### 2.3 Blockchain Tools

```bash
# Foundry (Ethereum)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"
cargo install --git https://github.com/coral-xyz/anchor anchor-cli

# SP1 SDK
cargo install sp1-cli
```

---

## 3. Phase 1: Circuit Setup & Key Generation

### 3.1 Generate Powers of Tau

Download the Hermez ceremony powers of tau file:

```bash
cd fluxe

# Power 17 supports up to 131k constraints (sufficient for all circuits)
curl -L -o pot17_final.ptau \
  "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_17.ptau"

# Verify the file
sha256sum pot17_final.ptau
# Expected: 982bfe8...
```

### 3.2 Export Circuits to R1CS

```bash
# Run the circuit setup test
cargo test -p e2e-rapidsnark-sp1 --test full_e2e_test test_r1cs_export_only -- --nocapture

# This generates:
# - outputs/mint.r1cs (31k constraints)
# - outputs/transfer.r1cs (94k constraints)
# - outputs/burn.r1cs (69k constraints)
```

### 3.3 Generate Proving Keys

```bash
# Generate proving keys for each circuit
cd tests/e2e_rapidsnark_sp1/outputs

for circuit in mint transfer burn; do
    echo "Generating keys for $circuit..."

    # Phase 1: Initial zkey from ptau
    snarkjs groth16 setup ${circuit}.r1cs ../pot17_final.ptau ${circuit}_0.zkey

    # Phase 2: Contribute randomness (in production, use multi-party ceremony)
    snarkjs zkey contribute ${circuit}_0.zkey ${circuit}_final.zkey \
        --name="FLUXE Setup" -e="$(head -c 64 /dev/urandom | xxd -p)"

    # Export verification key (JSON for snarkjs)
    snarkjs zkey export verificationkey ${circuit}_final.zkey ${circuit}_vk.json

    # Cleanup
    rm ${circuit}_0.zkey

    echo "✓ $circuit keys generated"
done
```

### 3.4 Convert VKs to Gnark Binary Format

For SP1 aggregation, VKs need to be in gnark binary format:

```bash
# Run the VK conversion
cargo test -p e2e-rapidsnark-sp1 --lib test_convert_existing_vks_to_binary -- --nocapture

# This generates:
# - outputs/mint_vk.bin (~1KB)
# - outputs/transfer_vk.bin (~1KB)
# - outputs/burn_vk.bin (~1KB)
```

### 3.5 Copy Keys to SP1 Program

```bash
# Copy VKs to SP1 program for embedding
cp outputs/mint_vk.bin ../../../fluxe-aggregation/program/vks/
cp outputs/transfer_vk.bin ../../../fluxe-aggregation/program/vks/
cp outputs/burn_vk.bin ../../../fluxe-aggregation/program/vks/
```

### 3.6 Package Keys for Mobile App

Create a distribution package for the mobile app:

```bash
# Create key distribution directory
mkdir -p ../../../fluxe-app/assets/circuits

# Copy proving keys (large, ~45-112MB each)
cp outputs/mint_final.zkey ../../../fluxe-app/assets/circuits/
cp outputs/transfer_final.zkey ../../../fluxe-app/assets/circuits/
cp outputs/burn_final.zkey ../../../fluxe-app/assets/circuits/

# For production, host these on CDN and download on-demand
```

---

## 4. Phase 2: Backend Infrastructure

### 4.1 Build the Sequencer

```bash
cd fluxe

# Build in release mode
cargo build --release -p fluxe-api

# The binary is at target/release/fluxe-api
```

### 4.2 Configuration

Create `config/sequencer.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8080
max_connections = 1000

[database]
url = "postgres://fluxe:password@localhost/fluxe"
max_pool_size = 20

[chains.ethereum]
chain_id = 1
chain_type = "EVM"
name = "Ethereum Mainnet"
rpc_endpoint = "https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY"
ws_endpoint = "wss://eth-mainnet.alchemyapi.io/v2/YOUR_KEY"
bridge_address = "0x..."  # FluxeBridge.sol address
verifier_address = "0x..." # Groth16Verifier.sol address
block_time_ms = 12000
finality_blocks = 32
max_batch_size = 100

[[chains.ethereum.assets]]
asset_type = 1
name = "USDC"
token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
decimals = 6
min_deposit = 1000000  # 1 USDC

[chains.solana]
chain_id = 501
chain_type = "SVM"
name = "Solana Mainnet"
rpc_endpoint = "https://api.mainnet-beta.solana.com"
ws_endpoint = "wss://api.mainnet-beta.solana.com"
bridge_address = "FLUXEBridge..."  # Program ID
block_time_ms = 400
finality_blocks = 32
max_batch_size = 100

[[chains.solana.assets]]
asset_type = 1
name = "USDC"
token_address = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # SPL USDC
decimals = 6
min_deposit = 1000000

[batching]
interval_seconds = 60
max_size = 100
min_fee = 1000  # Minimum fee in base units

[proving]
circuit_keys_dir = "./keys"
aggregation_enabled = true
sp1_execution_only = false  # Set true for testnet
```

### 4.3 Run the Sequencer

```bash
# Development mode
RUST_LOG=info cargo run -p fluxe-api -- --config config/sequencer.toml

# Production mode
./target/release/fluxe-api --config config/sequencer.toml
```

### 4.4 API Endpoints

The sequencer exposes these endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/chains` | GET | List supported chains |
| `/chain/:chain_id/state/roots` | GET | Get current state roots |
| `/chain/:chain_id/submit/mint` | POST | Submit mint proof |
| `/chain/:chain_id/submit/transfer` | POST | Submit transfer proof |
| `/chain/:chain_id/submit/burn` | POST | Submit burn proof |
| `/chain/:chain_id/batch/status/:id` | GET | Get batch status |
| `/chain/:chain_id/withdrawal/proof/:hash` | GET | Get withdrawal proof |

### 4.5 Docker Deployment

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  sequencer:
    build:
      context: .
      dockerfile: Dockerfile.sequencer
    ports:
      - "8080:8080"
    environment:
      - RUST_LOG=info
      - DATABASE_URL=postgres://fluxe:password@db/fluxe
    depends_on:
      - db
      - redis
    volumes:
      - ./config:/app/config
      - ./keys:/app/keys

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=fluxe
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=fluxe
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7
    command: redis-server --appendonly yes
    volumes:
      - redisdata:/data

volumes:
  pgdata:
  redisdata:
```

---

## 5. Phase 3: Mobile App Integration

### 5.1 Project Structure

```
fluxe-app/
├── src/
│   ├── app/                 # Expo Router pages
│   ├── components/          # React components
│   │   ├── menu/
│   │   │   ├── deposit/     # Deposit flow
│   │   │   ├── send/        # Transfer flow
│   │   │   ├── withdraw/    # Withdrawal flow (new)
│   │   │   └── proof/       # Proof generation (new)
│   │   └── ui/
│   ├── services/            # API & crypto services (new)
│   │   ├── api/             # Sequencer API client
│   │   ├── crypto/          # Key management
│   │   └── proof/           # Proof generation
│   ├── store/               # Redux state
│   └── types/               # TypeScript types
├── modules/
│   └── mopro/               # Native proof module
├── assets/
│   └── circuits/            # Proving keys (.zkey files)
└── package.json
```

### 5.2 Install Dependencies

```bash
cd fluxe-app

# Install required packages
npm install @reduxjs/toolkit react-redux
npm install axios
npm install @react-native-async-storage/async-storage
npm install react-native-sodium  # For encryption
npm install bip39  # For mnemonic generation

# Already included:
# - expo-file-system (for .zkey loading)
# - mopro (native proof module)
```

### 5.3 Create API Service

Create `src/services/api/sequencer.ts`:

```typescript
import axios, { AxiosInstance } from 'axios';

export interface StateRoots {
  cmtRoot: string;
  nftRoot: string;
  ingressRoot: string;
  exitRoot: string;
}

export interface SubmitProofRequest {
  proof: CircomProofResult;
  publicInputs: string[];
  txType: 'mint' | 'transfer' | 'burn';
}

export interface SubmitProofResponse {
  txHash: string;
  batchId: number;
  status: 'pending' | 'included' | 'finalized';
}

export class SequencerAPI {
  private client: AxiosInstance;

  constructor(baseUrl: string) {
    this.client = axios.create({
      baseURL: baseUrl,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  async getChains(): Promise<ChainInfo[]> {
    const response = await this.client.get('/chains');
    return response.data;
  }

  async getStateRoots(chainId: number): Promise<StateRoots> {
    const response = await this.client.get(`/chain/${chainId}/state/roots`);
    return response.data;
  }

  async submitMintProof(
    chainId: number,
    request: SubmitProofRequest
  ): Promise<SubmitProofResponse> {
    const response = await this.client.post(
      `/chain/${chainId}/submit/mint`,
      request
    );
    return response.data;
  }

  async submitTransferProof(
    chainId: number,
    request: SubmitProofRequest
  ): Promise<SubmitProofResponse> {
    const response = await this.client.post(
      `/chain/${chainId}/submit/transfer`,
      request
    );
    return response.data;
  }

  async submitBurnProof(
    chainId: number,
    request: SubmitProofRequest
  ): Promise<SubmitProofResponse> {
    const response = await this.client.post(
      `/chain/${chainId}/submit/burn`,
      request
    );
    return response.data;
  }

  async getBatchStatus(chainId: number, batchId: number): Promise<BatchStatus> {
    const response = await this.client.get(
      `/chain/${chainId}/batch/status/${batchId}`
    );
    return response.data;
  }

  async getWithdrawalProof(
    chainId: number,
    exitHash: string
  ): Promise<WithdrawalProof> {
    const response = await this.client.get(
      `/chain/${chainId}/withdrawal/proof/${exitHash}`
    );
    return response.data;
  }
}

export const sequencer = new SequencerAPI(
  process.env.EXPO_PUBLIC_SEQUENCER_URL || 'http://localhost:8080'
);
```

### 5.4 Create Proof Service

Create `src/services/proof/generator.ts`:

```typescript
import * as FileSystem from 'expo-file-system';
import { Asset } from 'expo-asset';
import { Platform } from 'react-native';
import {
  generateCircomProof,
  verifyCircomProof,
  CircomProofResult,
  ProofLibOption,
} from '../../modules/mopro';

// Import proving keys as assets
const CIRCUIT_KEYS = {
  mint: require('../../../assets/circuits/mint_final.zkey'),
  transfer: require('../../../assets/circuits/transfer_final.zkey'),
  burn: require('../../../assets/circuits/burn_final.zkey'),
};

export type CircuitType = 'mint' | 'transfer' | 'burn';

interface MintInputs {
  // Note fields
  noteCommitment: string;
  value: string;
  randomness: string;
  owner: string;

  // Ingress receipt
  sourceChain: string;
  assetType: string;
  amount: string;
  beneficiaryCm: string;
  nonce: string;
  ingressAux: string;

  // Merkle paths
  cmtPath: string[];
  ingressPath: string[];

  // State roots
  cmtRootOld: string;
  cmtRootNew: string;
  ingressRootOld: string;
  ingressRootNew: string;
}

interface TransferInputs {
  // Input notes
  inputCommitments: string[];
  inputValues: string[];
  inputRandomness: string[];
  inputOwnerSk: string[];
  inputOwnerPk: string[][];
  inputNk: string[];

  // Output notes
  outputCommitments: string[];
  outputValues: string[];
  outputRandomness: string[];
  outputOwners: string[];

  // Nullifiers
  nullifiers: string[];

  // Merkle paths
  cmtPaths: string[][];
  nftRangePaths: string[][];
  nftInsertWitnesses: string[][];

  // Sanctions
  sanctionsPaths: string[][];

  // State roots
  cmtRootOld: string;
  cmtRootNew: string;
  nftRootOld: string;
  nftRootNew: string;
  sanctionsRoot: string;
  poolRulesRoot: string;

  // Fee
  fee: string;
}

interface BurnInputs {
  // Input note
  inputCommitment: string;
  inputValue: string;
  inputRandomness: string;
  inputOwnerSk: string;
  inputOwnerPkX: string;
  inputOwnerPkY: string;
  inputNk: string;

  // Exit receipt
  destinationChain: string;
  assetType: string;
  amount: string;
  burnedNf: string;
  nonce: string;
  exitAux: string;

  // Merkle paths
  cmtPath: string[];
  nftRangePath: string[];
  nftInsertWitness: string[];
  exitPath: string[];

  // State roots
  cmtRoot: string;
  nftRootOld: string;
  nftRootNew: string;
  exitRootOld: string;
  exitRootNew: string;
}

export class ProofGenerator {
  private keyPaths: Map<CircuitType, string> = new Map();
  private initialized: boolean = false;

  async initialize(): Promise<void> {
    if (this.initialized) return;

    console.log('[ProofGenerator] Initializing...');

    for (const [circuit, assetModule] of Object.entries(CIRCUIT_KEYS)) {
      const asset = Asset.fromModule(assetModule);
      await asset.downloadAsync();

      const filename = `${circuit}_final.zkey`;
      const destPath = `${FileSystem.documentDirectory}${filename}`;

      // Check if already downloaded
      const fileInfo = await FileSystem.getInfoAsync(destPath);
      if (!fileInfo.exists) {
        console.log(`[ProofGenerator] Downloading ${circuit} key...`);
        await FileSystem.copyAsync({
          from: asset.localUri!,
          to: destPath,
        });
      }

      this.keyPaths.set(circuit as CircuitType, this.normalizePath(destPath));
      console.log(`[ProofGenerator] ${circuit} key ready`);
    }

    this.initialized = true;
    console.log('[ProofGenerator] Initialization complete');
  }

  private normalizePath(path: string): string {
    // Remove file:// prefix for native modules
    if (Platform.OS !== 'web' && path.startsWith('file://')) {
      return path.slice(7);
    }
    return path;
  }

  async generateMintProof(inputs: MintInputs): Promise<CircomProofResult> {
    await this.initialize();

    const zkeyPath = this.keyPaths.get('mint')!;
    const circuitInputs = this.formatMintInputs(inputs);

    console.log('[ProofGenerator] Generating mint proof...');
    const startTime = Date.now();

    const result = await generateCircomProof(
      zkeyPath,
      JSON.stringify(circuitInputs),
      { proofLib: ProofLibOption.Rapidsnark }
    );

    console.log(`[ProofGenerator] Mint proof generated in ${Date.now() - startTime}ms`);
    return result;
  }

  async generateTransferProof(inputs: TransferInputs): Promise<CircomProofResult> {
    await this.initialize();

    const zkeyPath = this.keyPaths.get('transfer')!;
    const circuitInputs = this.formatTransferInputs(inputs);

    console.log('[ProofGenerator] Generating transfer proof...');
    const startTime = Date.now();

    const result = await generateCircomProof(
      zkeyPath,
      JSON.stringify(circuitInputs),
      { proofLib: ProofLibOption.Rapidsnark }
    );

    console.log(`[ProofGenerator] Transfer proof generated in ${Date.now() - startTime}ms`);
    return result;
  }

  async generateBurnProof(inputs: BurnInputs): Promise<CircomProofResult> {
    await this.initialize();

    const zkeyPath = this.keyPaths.get('burn')!;
    const circuitInputs = this.formatBurnInputs(inputs);

    console.log('[ProofGenerator] Generating burn proof...');
    const startTime = Date.now();

    const result = await generateCircomProof(
      zkeyPath,
      JSON.stringify(circuitInputs),
      { proofLib: ProofLibOption.Rapidsnark }
    );

    console.log(`[ProofGenerator] Burn proof generated in ${Date.now() - startTime}ms`);
    return result;
  }

  async verifyProof(
    circuit: CircuitType,
    proof: CircomProofResult
  ): Promise<boolean> {
    await this.initialize();

    const zkeyPath = this.keyPaths.get(circuit)!;
    return verifyCircomProof(zkeyPath, proof, {
      proofLib: ProofLibOption.Rapidsnark,
    });
  }

  private formatMintInputs(inputs: MintInputs): object {
    return {
      note_commitment: inputs.noteCommitment,
      value: inputs.value,
      randomness: inputs.randomness,
      owner: inputs.owner,
      source_chain: inputs.sourceChain,
      asset_type: inputs.assetType,
      amount: inputs.amount,
      beneficiary_cm: inputs.beneficiaryCm,
      nonce: inputs.nonce,
      ingress_aux: inputs.ingressAux,
      cmt_path: inputs.cmtPath,
      ingress_path: inputs.ingressPath,
      cmt_root_old: inputs.cmtRootOld,
      cmt_root_new: inputs.cmtRootNew,
      ingress_root_old: inputs.ingressRootOld,
      ingress_root_new: inputs.ingressRootNew,
    };
  }

  private formatTransferInputs(inputs: TransferInputs): object {
    return {
      input_commitments: inputs.inputCommitments,
      input_values: inputs.inputValues,
      input_randomness: inputs.inputRandomness,
      input_owner_sk: inputs.inputOwnerSk,
      input_owner_pk: inputs.inputOwnerPk,
      input_nk: inputs.inputNk,
      output_commitments: inputs.outputCommitments,
      output_values: inputs.outputValues,
      output_randomness: inputs.outputRandomness,
      output_owners: inputs.outputOwners,
      nullifiers: inputs.nullifiers,
      cmt_paths: inputs.cmtPaths,
      nft_range_paths: inputs.nftRangePaths,
      nft_insert_witnesses: inputs.nftInsertWitnesses,
      sanctions_paths: inputs.sanctionsPaths,
      cmt_root_old: inputs.cmtRootOld,
      cmt_root_new: inputs.cmtRootNew,
      nft_root_old: inputs.nftRootOld,
      nft_root_new: inputs.nftRootNew,
      sanctions_root: inputs.sanctionsRoot,
      pool_rules_root: inputs.poolRulesRoot,
      fee: inputs.fee,
    };
  }

  private formatBurnInputs(inputs: BurnInputs): object {
    return {
      input_commitment: inputs.inputCommitment,
      input_value: inputs.inputValue,
      input_randomness: inputs.inputRandomness,
      input_owner_sk: inputs.inputOwnerSk,
      input_owner_pk_x: inputs.inputOwnerPkX,
      input_owner_pk_y: inputs.inputOwnerPkY,
      input_nk: inputs.inputNk,
      destination_chain: inputs.destinationChain,
      asset_type: inputs.assetType,
      amount: inputs.amount,
      burned_nf: inputs.burnedNf,
      nonce: inputs.nonce,
      exit_aux: inputs.exitAux,
      cmt_path: inputs.cmtPath,
      nft_range_path: inputs.nftRangePath,
      nft_insert_witness: inputs.nftInsertWitness,
      exit_path: inputs.exitPath,
      cmt_root: inputs.cmtRoot,
      nft_root_old: inputs.nftRootOld,
      nft_root_new: inputs.nftRootNew,
      exit_root_old: inputs.exitRootOld,
      exit_root_new: inputs.exitRootNew,
    };
  }
}

export const proofGenerator = new ProofGenerator();
```

### 5.5 Create Wallet Service

Create `src/services/crypto/wallet.ts`:

```typescript
import * as bip39 from 'bip39';
import AsyncStorage from '@react-native-async-storage/async-storage';

// Poseidon hash implementation (use a library or WASM module)
import { poseidonHash } from './poseidon';

export interface NoteRecord {
  commitment: string;
  value: bigint;
  randomness: string;
  owner: string;
  nk: string;  // Nullifier key
  ownerSk: string;
  ownerPkX: string;
  ownerPkY: string;
  assetType: number;
  chainHint: number;
  spent: boolean;
}

export interface WalletState {
  mnemonic: string;
  masterKey: string;
  notes: NoteRecord[];
  addressIndex: number;
}

export class WalletService {
  private state: WalletState | null = null;
  private readonly STORAGE_KEY = '@fluxe/wallet';

  async create(): Promise<string> {
    const mnemonic = bip39.generateMnemonic(256);  // 24 words
    const seed = await bip39.mnemonicToSeed(mnemonic);
    const masterKey = seed.slice(0, 32).toString('hex');

    this.state = {
      mnemonic,
      masterKey,
      notes: [],
      addressIndex: 0,
    };

    await this.save();
    return mnemonic;
  }

  async restore(mnemonic: string): Promise<void> {
    if (!bip39.validateMnemonic(mnemonic)) {
      throw new Error('Invalid mnemonic');
    }

    const seed = await bip39.mnemonicToSeed(mnemonic);
    const masterKey = seed.slice(0, 32).toString('hex');

    this.state = {
      mnemonic,
      masterKey,
      notes: [],
      addressIndex: 0,
    };

    await this.save();
  }

  async load(): Promise<boolean> {
    const stored = await AsyncStorage.getItem(this.STORAGE_KEY);
    if (!stored) return false;

    this.state = JSON.parse(stored);
    return true;
  }

  private async save(): Promise<void> {
    if (!this.state) return;
    await AsyncStorage.setItem(this.STORAGE_KEY, JSON.stringify(this.state));
  }

  deriveNoteKeys(index: number): {
    ownerSk: string;
    ownerPkX: string;
    ownerPkY: string;
    nk: string;
  } {
    if (!this.state) throw new Error('Wallet not initialized');

    // Derive keys using Poseidon hash
    const derivedKey = poseidonHash([
      BigInt('0x' + this.state.masterKey),
      BigInt(index),
    ]);

    // Split into owner secret key and nullifier key
    const ownerSk = derivedKey.toString(16).padStart(64, '0');
    const nk = poseidonHash([derivedKey, BigInt(1)]).toString(16).padStart(64, '0');

    // Derive public key (EC scalar multiplication on Baby JubJub)
    const { x, y } = this.derivePublicKey(ownerSk);

    return {
      ownerSk,
      ownerPkX: x,
      ownerPkY: y,
      nk,
    };
  }

  private derivePublicKey(sk: string): { x: string; y: string } {
    // Baby JubJub EC multiplication
    // In production, use a proper EC library
    // Placeholder implementation
    const skBigInt = BigInt('0x' + sk);

    // TODO: Implement proper Baby JubJub scalar multiplication
    // or call native module for EC operations

    return {
      x: poseidonHash([skBigInt, BigInt(0)]).toString(16).padStart(64, '0'),
      y: poseidonHash([skBigInt, BigInt(1)]).toString(16).padStart(64, '0'),
    };
  }

  computeOwnerAddress(pkX: string, pkY: string): string {
    const addr = poseidonHash([BigInt('0x' + pkX), BigInt('0x' + pkY)]);
    return addr.toString(16).padStart(64, '0');
  }

  addNote(note: NoteRecord): void {
    if (!this.state) throw new Error('Wallet not initialized');
    this.state.notes.push(note);
    this.save();
  }

  markNoteSpent(commitment: string): void {
    if (!this.state) throw new Error('Wallet not initialized');
    const note = this.state.notes.find(n => n.commitment === commitment);
    if (note) {
      note.spent = true;
      this.save();
    }
  }

  getUnspentNotes(): NoteRecord[] {
    if (!this.state) return [];
    return this.state.notes.filter(n => !n.spent);
  }

  getBalance(assetType: number): bigint {
    return this.getUnspentNotes()
      .filter(n => n.assetType === assetType)
      .reduce((sum, n) => sum + n.value, BigInt(0));
  }
}

export const wallet = new WalletService();
```

### 5.6 Create Transaction Flows

Create `src/services/transactions/deposit.ts`:

```typescript
import { sequencer } from '../api/sequencer';
import { proofGenerator } from '../proof/generator';
import { wallet, NoteRecord } from '../crypto/wallet';
import { poseidonHash } from '../crypto/poseidon';

export interface DepositParams {
  chainId: number;
  assetType: number;
  amount: bigint;
  onChainTxHash: string;  // From bridge deposit
}

export async function processDeposit(params: DepositParams): Promise<string> {
  const { chainId, assetType, amount, onChainTxHash } = params;

  // 1. Get current state from sequencer
  const stateRoots = await sequencer.getStateRoots(chainId);

  // 2. Derive note keys
  const noteIndex = Date.now();  // Use timestamp as unique index
  const keys = wallet.deriveNoteKeys(noteIndex);
  const ownerAddr = wallet.computeOwnerAddress(keys.ownerPkX, keys.ownerPkY);

  // 3. Generate randomness for value commitment
  const randomness = generateRandomFieldElement();

  // 4. Compute note commitment
  const noteCommitment = computeNoteCommitment({
    assetType,
    valueCommitment: computeValueCommitment(amount, randomness),
    owner: ownerAddr,
    chainHint: chainId,
  });

  // 5. Compute beneficiary commitment (for ingress receipt)
  const beneficiaryCm = poseidonHash([BigInt(0), BigInt('0x' + noteCommitment)]);

  // 6. Build circuit inputs
  const inputs = {
    noteCommitment,
    value: amount.toString(),
    randomness,
    owner: ownerAddr,
    sourceChain: chainId.toString(),
    assetType: assetType.toString(),
    amount: amount.toString(),
    beneficiaryCm: beneficiaryCm.toString(16),
    nonce: noteIndex.toString(),
    ingressAux: onChainTxHash,
    // Merkle paths would come from sequencer
    cmtPath: [], // Get from sequencer
    ingressPath: [], // Get from sequencer
    cmtRootOld: stateRoots.cmtRoot,
    cmtRootNew: '', // Computed
    ingressRootOld: stateRoots.ingressRoot,
    ingressRootNew: '', // Computed
  };

  // 7. Generate proof
  console.log('[Deposit] Generating proof...');
  const proofResult = await proofGenerator.generateMintProof(inputs);

  // 8. Submit to sequencer
  console.log('[Deposit] Submitting to sequencer...');
  const response = await sequencer.submitMintProof(chainId, {
    proof: proofResult,
    publicInputs: proofResult.inputs,
    txType: 'mint',
  });

  // 9. Store note locally
  const noteRecord: NoteRecord = {
    commitment: noteCommitment,
    value: amount,
    randomness,
    owner: ownerAddr,
    nk: keys.nk,
    ownerSk: keys.ownerSk,
    ownerPkX: keys.ownerPkX,
    ownerPkY: keys.ownerPkY,
    assetType,
    chainHint: chainId,
    spent: false,
  };
  wallet.addNote(noteRecord);

  console.log('[Deposit] Complete:', response.txHash);
  return response.txHash;
}

function generateRandomFieldElement(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function computeValueCommitment(value: bigint, randomness: string): string {
  // Pedersen commitment: v*G + r*H
  // Simplified for demonstration
  return poseidonHash([value, BigInt('0x' + randomness)]).toString(16);
}

function computeNoteCommitment(params: {
  assetType: number;
  valueCommitment: string;
  owner: string;
  chainHint: number;
}): string {
  return poseidonHash([
    BigInt(params.assetType),
    BigInt('0x' + params.valueCommitment),
    BigInt('0x' + params.owner),
    BigInt(params.chainHint),
  ]).toString(16);
}
```

### 5.7 Update Redux Store

Create `src/store/features/wallet/slice.ts`:

```typescript
import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { wallet, NoteRecord } from '../../../services/crypto/wallet';
import { sequencer } from '../../../services/api/sequencer';

interface WalletState {
  initialized: boolean;
  loading: boolean;
  error: string | null;
  balance: { [assetType: number]: string };
  notes: NoteRecord[];
  pendingTxs: PendingTransaction[];
}

interface PendingTransaction {
  id: string;
  type: 'deposit' | 'transfer' | 'withdraw';
  status: 'generating_proof' | 'submitting' | 'pending' | 'confirmed' | 'failed';
  amount: string;
  assetType: number;
  timestamp: number;
}

const initialState: WalletState = {
  initialized: false,
  loading: false,
  error: null,
  balance: {},
  notes: [],
  pendingTxs: [],
};

export const initializeWallet = createAsyncThunk(
  'wallet/initialize',
  async (mnemonic?: string) => {
    if (mnemonic) {
      await wallet.restore(mnemonic);
    } else {
      const loaded = await wallet.load();
      if (!loaded) {
        await wallet.create();
      }
    }
    return wallet.getUnspentNotes();
  }
);

export const refreshBalance = createAsyncThunk(
  'wallet/refreshBalance',
  async (assetType: number) => {
    const balance = wallet.getBalance(assetType);
    return { assetType, balance: balance.toString() };
  }
);

const walletSlice = createSlice({
  name: 'wallet',
  initialState,
  reducers: {
    addPendingTx: (state, action: PayloadAction<PendingTransaction>) => {
      state.pendingTxs.push(action.payload);
    },
    updateTxStatus: (
      state,
      action: PayloadAction<{ id: string; status: PendingTransaction['status'] }>
    ) => {
      const tx = state.pendingTxs.find(t => t.id === action.payload.id);
      if (tx) {
        tx.status = action.payload.status;
      }
    },
    addNote: (state, action: PayloadAction<NoteRecord>) => {
      state.notes.push(action.payload);
    },
    markNoteSpent: (state, action: PayloadAction<string>) => {
      const note = state.notes.find(n => n.commitment === action.payload);
      if (note) {
        note.spent = true;
      }
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(initializeWallet.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(initializeWallet.fulfilled, (state, action) => {
        state.loading = false;
        state.initialized = true;
        state.notes = action.payload;
      })
      .addCase(initializeWallet.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to initialize wallet';
      })
      .addCase(refreshBalance.fulfilled, (state, action) => {
        state.balance[action.payload.assetType] = action.payload.balance;
      });
  },
});

export const { addPendingTx, updateTxStatus, addNote, markNoteSpent } =
  walletSlice.actions;
export default walletSlice.reducer;
```

### 5.8 Environment Configuration

Create `.env`:

```bash
# API Configuration
EXPO_PUBLIC_SEQUENCER_URL=http://localhost:8080
EXPO_PUBLIC_SEQUENCER_WS_URL=ws://localhost:8080

# Chain Configuration
EXPO_PUBLIC_ETHEREUM_RPC=https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY
EXPO_PUBLIC_SOLANA_RPC=https://api.mainnet-beta.solana.com

# Bridge Contract Addresses
EXPO_PUBLIC_ETH_BRIDGE_ADDRESS=0x...
EXPO_PUBLIC_SOL_BRIDGE_PROGRAM=FLUXE...

# Feature Flags
EXPO_PUBLIC_ENABLE_TESTNET=true
EXPO_PUBLIC_ENABLE_ANALYTICS=false
```

### 5.9 Build the App

```bash
# Development
npm start

# iOS build
eas build --platform ios --profile development

# Android build
eas build --platform android --profile development

# Production builds
eas build --platform all --profile production
```

---

## 6. Phase 4: On-Chain Contracts

### 6.1 Ethereum Contracts

See `contracts/ethereum/` for full implementation.

Deploy using Foundry:

```bash
cd contracts/ethereum

# Compile
forge build

# Deploy to testnet
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url $SEPOLIA_RPC \
  --private-key $DEPLOYER_KEY \
  --broadcast \
  --verify
```

### 6.2 Solana Program

See `contracts/solana/` for full implementation.

Deploy using Anchor:

```bash
cd contracts/solana

# Build
anchor build

# Deploy to devnet
anchor deploy --provider.cluster devnet

# Initialize bridge
anchor run initialize
```

---

## 7. Phase 5: End-to-End Testing

### 7.1 Run Integration Tests

```bash
# Full E2E test with proof generation
cargo test -p e2e-rapidsnark-sp1 --test full_e2e_test -- --ignored --nocapture

# Expected output:
# ✓ MintCircuit: 31,271 constraints, ~130ms proof time
# ✓ TransferCircuit: 93,792 constraints, ~280ms proof time
# ✓ BurnCircuit: 68,823 constraints, ~250ms proof time
# ✓ SP1 Aggregation: ~32M cycles, ~36s verification
```

### 7.2 Test Mobile App

```bash
cd fluxe-app

# Run on iOS simulator
npm run ios

# Run on Android emulator
npm run android

# Test proof generation
# Navigate to Menu > Proof Example
# Enter test values and verify proof generates successfully
```

### 7.3 Test E2E Flow

```bash
# 1. Start sequencer
cargo run -p fluxe-api -- --config config/sequencer.dev.toml

# 2. In another terminal, run the mobile app
cd fluxe-app && npm start

# 3. Test flow:
#    a. Create wallet (backup mnemonic)
#    b. Deposit on testnet bridge
#    c. Generate mint proof in app
#    d. Submit to sequencer
#    e. Transfer to another address
#    f. Withdraw to different chain
```

---

## 8. Production Deployment

### 8.1 Infrastructure Requirements

| Component | Specification | Count |
|-----------|---------------|-------|
| Sequencer | 16GB RAM, 8 CPU | 2 (redundant) |
| Database | PostgreSQL 15, 500GB SSD | 1 (+ replica) |
| Redis | 8GB RAM | 1 (+ replica) |
| Archive Node | 2TB SSD, 32GB RAM | 1 per chain |

### 8.2 Deployment Checklist

- [ ] Generate production circuit keys (multi-party ceremony)
- [ ] Deploy contracts to mainnet
- [ ] Configure production RPC endpoints
- [ ] Set up monitoring (Grafana, Prometheus)
- [ ] Configure alerting (PagerDuty, Discord)
- [ ] Set up backup procedures
- [ ] Configure rate limiting
- [ ] Enable TLS/SSL
- [ ] Security audit complete

### 8.3 CI/CD Pipeline

```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/toolchain@v1
      - run: cargo test --all

  deploy-sequencer:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t fluxe-sequencer .
      - run: docker push $ECR_REPO/fluxe-sequencer
      - uses: aws-actions/amazon-ecs-deploy-task-definition@v1

  deploy-mobile:
    needs: test
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - uses: expo/expo-github-action@v8
      - run: eas build --platform all --non-interactive
```

---

## 9. Monitoring & Operations

### 9.1 Metrics to Monitor

| Metric | Alert Threshold |
|--------|-----------------|
| Proof generation time | > 5s |
| Sequencer latency | > 500ms |
| Batch finalization time | > 5 min |
| Error rate | > 1% |
| Memory usage | > 80% |
| Queue depth | > 1000 txs |

### 9.2 Grafana Dashboard

Import the dashboard from `monitoring/grafana/fluxe-dashboard.json`:

- Transaction throughput (TPS)
- Proof generation times
- Batch sizes
- Chain supply balances
- Error rates by type

### 9.3 Runbook

See `docs/RUNBOOK.md` for operational procedures:

- Handling stuck batches
- Emergency pause procedure
- Bridge rebalancing
- Key rotation
- Incident response

---

## Appendix A: Circuit Sizes

| Circuit | Constraints | Public Inputs | Proving Time* | Proof Size |
|---------|-------------|---------------|---------------|------------|
| Mint | 31,271 | 8 | ~130ms | 256 bytes |
| Transfer | 93,792 | 10 | ~280ms | 256 bytes |
| Burn | 68,823 | 9 | ~250ms | 256 bytes |

*Proving times on iPhone 14 Pro using rapidsnark

---

## Appendix B: API Reference

See `docs/API.md` for complete API documentation.

---

## Appendix C: Security Considerations

1. **Private Key Storage**: Use secure enclave (iOS) / Keystore (Android)
2. **Proof Generation**: All proofs generated locally, never sent to server
3. **Note Encryption**: Notes encrypted with user's master key
4. **Transport Security**: TLS 1.3 for all API communication
5. **Rate Limiting**: Prevent DoS on sequencer
6. **Audit Trail**: All state transitions are verifiable on-chain

---

## Support

- Documentation: https://docs.fluxe.xyz
- Discord: https://discord.gg/fluxe
- GitHub Issues: https://github.com/fluxe/fluxe/issues
