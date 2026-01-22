# FLUXE Multi-Chain L2 Deployment Roadmap

**Version**: 1.0
**Target Chains**: Ethereum (EVM) + Solana (SVM)
**Timeline**: 18-26 weeks for production deployment

---

## Executive Summary

This roadmap outlines the path to deploying FLUXE as a privacy-preserving L2 with **cross-chain deposit and withdrawal capabilities** between Ethereum and Solana. Users can deposit on one chain and withdraw on another, enabling true cross-chain privacy without requiring bridge rebalancing (future enhancement).

### Key Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   FLUXE SEQUENCER                        │
│  ┌────────────────────────┬────────────────────────┐    │
│  │   Ethereum Chain Mgr   │   Solana Chain Mgr     │    │
│  │   • CMT/NFT Trees      │   • CMT/NFT Trees      │    │
│  │   • Supply Tracking    │   • Supply Tracking    │    │
│  │   • State Roots        │   • State Roots        │    │
│  └────────────────────────┴────────────────────────┘    │
│                                                           │
│  [Cross-Chain State Coordination]                        │
│  • Global nullifier set (prevent double-spend)           │
│  • Global commitment tracking                            │
│  • Per-chain supply accounting                           │
│  • Cross-chain ingress/egress matching                   │
└─────────────────────────────────────────────────────────┘
         ↓                              ↓
    ┌────────────┐              ┌────────────┐
    │ Ethereum   │              │  Solana    │
    │ Bridge     │              │  Bridge    │
    │ Contract   │              │  Program   │
    │ (Solidity) │              │  (Anchor)  │
    └────────────┘              └────────────┘
```

### Cross-Chain Flow Example

**User deposits 100 USDC on Ethereum, withdraws 100 USDC on Solana:**

1. **Deposit (Ethereum)**:
   - User calls `EthereumBridge.deposit(USDC, 100, beneficiaryCm)`
   - Bridge locks 100 USDC, emits `DepositEvent`
   - Sequencer creates `IngressReceipt` with `source_chain = ETHEREUM`

2. **Private Transfer (FLUXE Layer)**:
   - User submits `MintCircuit` proof → creates commitment in global CMT
   - User can transfer privately within FLUXE (any number of times)
   - Commitments/nullifiers exist in global state, not chain-specific

3. **Withdrawal (Solana)**:
   - User submits `BurnCircuit` proof with `target_chain = SOLANA`
   - Creates `ExitReceipt` with `destination_chain = SOLANA`
   - Sequencer updates global NFT tree (nullifier spent)
   - Batch settles to both chains

4. **Claim (Solana)**:
   - User calls `SolanaBridge.withdraw(exitReceiptHash, proof)`
   - Bridge verifies receipt in finalized batch
   - Bridge releases 100 USDC from Solana pool
   - **Note**: Ethereum pool still has locked 100 USDC (rebalancing needed later)

---

## Current State Assessment

### What Exists ✅

| Component | Status | Readiness |
|-----------|--------|-----------|
| Core Circuits (Mint/Transfer/Burn/ObjectUpdate) | ✅ Complete | 95% |
| ZK Cryptography (Groth16/BN254, Poseidon, Schnorr) | ✅ Complete | 100% |
| Merkle Trees (IMT, S-IMT) | ✅ Complete | 100% |
| Compliance & Sanctions | ✅ Complete | 85% |
| Transaction Batching (basic) | ⚠️ Basic | 60% |
| State Management (single-chain) | ✅ Complete | 90% |
| Receipt Model (Ingress/Exit) | ✅ Complete | 95% |
| FluxeClient API | ⚠️ TODOs | 65% |

### Critical Gaps ❌

| Component | Status | Impact |
|-----------|--------|--------|
| Multi-Chain State Manager | ❌ Monolithic | 🔴 BLOCKING |
| Solana Program (Bridge) | ❌ Missing | 🔴 BLOCKING |
| Proof Aggregation (real SNARK) | ❌ Placeholder | 🔴 BLOCKING |
| Cross-Chain Coordination | ❌ Missing | 🔴 BLOCKING |
| Ethereum Settlement Contracts | ❌ Missing | 🔴 BLOCKING |
| Production Sequencer | ❌ Missing | 🔴 BLOCKING |
| Block Persistence | ❌ Missing | 🟡 HIGH |
| Global Supply Tracking | ❌ Missing | 🟡 HIGH |

---

## Core Requirements for Cross-Chain Support

### 1. Global vs Per-Chain State

**Global State** (shared across all chains):
- **Nullifier Set**: Prevent double-spending across chains
- **Commitment Set**: Track all notes regardless of source/destination
- **Object State**: Compliance objects (zk-promises)
- **Callback State**: Callback invocations

**Per-Chain State** (isolated):
- **Ingress Tree**: Deposits on this chain
- **Exit Tree**: Withdrawals to this chain
- **Supply Tracking**: Assets locked/released per chain
- **State Roots**: Committed to respective L1s

### 2. Chain Hint Enforcement

Notes are cryptographically bound to target chains via `chain_hint`:

```rust
pub struct Note {
    pub chain_hint: ChainHint,  // Target withdrawal chain
    // ... other fields
}

// Commitment includes chain_hint:
cm = Poseidon(DOM_NOTE || asset_type || v_comm || owner || psi ||
              chain_hint || compliance_hash || ...)
```

**BurnCircuit must enforce**:
- Exit receipt `destination_chain` matches note's `chain_hint`
- Prevents withdrawing on wrong chain

### 3. Cross-Chain Supply Invariant

```
Global Supply = Σ(all deposits) - Σ(all withdrawals)

Per-Chain:
  Ethereum Pool = Σ(ETH deposits) - Σ(ETH withdrawals)
  Solana Pool   = Σ(SOL deposits) - Σ(SOL withdrawals)

Invariant: Global Supply = ETH Pool + SOL Pool

⚠️ Pools can become imbalanced without rebalancing
```

**Example Imbalance**:
- 1000 USDC deposited on Ethereum → ETH pool = 1000
- 600 USDC withdrawn on Solana → SOL pool = -600 (needs liquidity!)

**Solution (Future)**: Automated bridge rebalancing to transfer liquidity between chains

---

## Implementation Roadmap

### PHASE 1: Core Multi-Chain Infrastructure (6-8 weeks)

#### 1.1 Global + Per-Chain State Architecture (3 weeks)

**Goal**: Refactor state management for cross-chain coordination

```rust
pub struct GlobalStateManager {
    // Global state (shared)
    pub global_nft_tree: SortedTree,      // All nullifiers
    pub global_cmt_tree: IncrementalTree, // All commitments
    pub global_obj_tree: IncrementalTree, // All compliance objects
    pub global_cb_tree: SortedTree,       // All callbacks

    // Per-chain state
    pub chains: HashMap<ChainId, ChainState>,

    // Cross-chain supply tracking
    pub global_supply: HashMap<AssetType, Amount>,
}

pub struct ChainState {
    pub chain_id: ChainId,
    pub chain_type: ChainType,  // EVM or SVM

    // Per-chain trees
    pub ingress_tree: IncrementalTree,  // Deposits to this chain
    pub exit_tree: IncrementalTree,     // Withdrawals from this chain

    // Per-chain supply
    pub deposited: HashMap<AssetType, Amount>,
    pub withdrawn: HashMap<AssetType, Amount>,

    // State roots for L1 settlement
    pub roots: ChainStateRoots,
}

pub enum ChainType {
    EVM,  // Ethereum, Arbitrum, Base, etc.
    SVM,  // Solana
}
```

**Tasks**:
- [ ] Design `GlobalStateManager` with global + per-chain state separation
- [ ] Implement cross-chain nullifier deduplication
- [ ] Add global supply accounting
- [ ] Create `ChainState` for per-chain ingress/exit tracking
- [ ] Update all state operations to use new architecture
- [ ] Write comprehensive integration tests

**Files to create/modify**:
- `fluxe-core/src/state_manager/global.rs` (new)
- `fluxe-core/src/state_manager/chain_state.rs` (new)
- `fluxe-core/src/state_manager/mod.rs` (refactor)
- `fluxe-core/src/server_verifier.rs` (update to use GlobalStateManager)

---

#### 1.2 Chain-Specific Configuration (1 week)

**Goal**: Support heterogeneous chains (EVM + SVM)

```rust
pub struct ChainConfig {
    pub chain_id: ChainId,
    pub chain_type: ChainType,
    pub name: String,

    // RPC configuration
    pub rpc_endpoint: String,
    pub ws_endpoint: Option<String>,

    // Contract/program addresses
    pub bridge_address: String,  // Contract (EVM) or Program ID (SVM)
    pub verifier_address: Option<String>,  // EVM only

    // Supported assets
    pub assets: Vec<AssetConfig>,

    // Chain parameters
    pub block_time_ms: u64,
    pub finality_blocks: u64,  // Confirmations needed
    pub max_batch_size: usize,

    // Fee configuration
    pub base_fee: Amount,
    pub gas_oracle: Option<String>,
}

pub struct AssetConfig {
    pub asset_type: AssetType,
    pub token_address: String,  // ERC20 address or SPL mint
    pub decimals: u8,
    pub min_deposit: Amount,
    pub max_deposit: Amount,
}

pub struct MultiChainConfig {
    pub chains: HashMap<ChainId, ChainConfig>,
    pub default_chain: ChainId,
}
```

**Configuration File** (`config/chains.toml`):

```toml
[chains.ethereum]
chain_id = 1
chain_type = "EVM"
name = "Ethereum Mainnet"
rpc_endpoint = "https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY"
bridge_address = "0x..." # FluxeBridge.sol
verifier_address = "0x..." # Groth16Verifier.sol
block_time_ms = 12000
finality_blocks = 32
max_batch_size = 100

[[chains.ethereum.assets]]
asset_type = 1
name = "USDC"
token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
decimals = 6
min_deposit = 1000000  # 1 USDC
max_deposit = 1000000000000  # 1M USDC

[chains.solana]
chain_id = 501
chain_type = "SVM"
name = "Solana Mainnet"
rpc_endpoint = "https://api.mainnet-beta.solana.com"
ws_endpoint = "wss://api.mainnet-beta.solana.com"
bridge_address = "FLUXEBridgeXXXXXXXXXXXXXXXXXXXXXXXXXXX"  # Program ID
block_time_ms = 400
finality_blocks = 32
max_batch_size = 100

[[chains.solana.assets]]
asset_type = 1
name = "USDC"
token_address = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # SPL USDC
decimals = 6
min_deposit = 1000000
max_deposit = 1000000000000
```

**Tasks**:
- [ ] Create `ChainConfig` and `AssetConfig` structures
- [ ] Implement TOML config parser
- [ ] Add chain validation on startup
- [ ] Support environment variable overrides
- [ ] Create config templates for mainnet/testnet

**Files to create/modify**:
- `fluxe-core/src/config/chains.rs` (new)
- `fluxe-core/src/config/mod.rs` (update)
- `config/chains.toml` (new)
- `config/chains.testnet.toml` (new)

---

#### 1.3 Verifier Contract Deployment (1 week)

**Architecture Note**: Circuit keys are **CHAIN-AGNOSTIC**. The same verification keys work on all chains. Only verifier contract deployments differ.

**Solution**: Deploy verifier contracts with embedded VKs to each chain

**What's Universal (Same for All Chains)**:
- Circuit definitions (Mint, Burn, Transfer, ObjectUpdate, Aggregation)
- Proving keys (used by clients)
- Verifying keys (embedded in verifier contracts)

**What's Chain-Specific**:
- Verifier contract CODE (Solidity for EVM, Rust for Solana)
- Verifier contract ADDRESS (different deployment on each chain)
- Bridge contract implementation (ERC20 vs SPL tokens)

**Key Management**:
```rust
pub struct CircuitSetupManager {
    // Single set of keys for ALL chains
    pub mint_keys: TrustedSetup,
    pub burn_keys: TrustedSetup,
    pub transfer_keys: TrustedSetup,
    pub object_update_keys: TrustedSetup,
    pub aggregation_keys: TrustedSetup,
}

impl CircuitSetupManager {
    pub fn load_all() -> Result<Self> {
        Ok(Self {
            mint_keys: TrustedSetup::load("keys/mint")?,
            burn_keys: TrustedSetup::load("keys/burn")?,
            transfer_keys: TrustedSetup::load("keys/transfer")?,
            object_update_keys: TrustedSetup::load("keys/object_update")?,
            aggregation_keys: TrustedSetup::load("keys/aggregation")?,
        })
    }

    // No chain_id parameter needed!
    pub fn get_vk(&self, circuit_type: CircuitType) -> &VerifyingKey<Bn254> {
        match circuit_type {
            CircuitType::Mint => &self.mint_keys.verifying_key,
            CircuitType::Burn => &self.burn_keys.verifying_key,
            CircuitType::Transfer => &self.transfer_keys.verifying_key,
            CircuitType::ObjectUpdate => &self.object_update_keys.verifying_key,
            CircuitType::Aggregation => &self.aggregation_keys.verifying_key,
        }
    }
}
```

**Directory Structure**:
```
keys/
  mint_pk.bin
  mint_vk.bin
  burn_pk.bin
  burn_vk.bin
  transfer_pk.bin
  transfer_vk.bin
  object_update_pk.bin
  object_update_vk.bin
  aggregation_pk.bin
  aggregation_vk.bin          # Most important - deployed to all chains
```

**Tasks**:
- [ ] Generate universal circuit keys (one-time trusted setup)
- [ ] Generate Ethereum Solidity verifier from aggregation VK
- [ ] Generate Solana Rust verifier from aggregation VK
- [ ] Deploy Ethereum verifier contract to Sepolia
- [ ] Deploy Solana verifier program to Devnet
- [ ] Store verifier addresses in ChainConfig

**Files to create**:
- `contracts/ethereum/AggregationVerifier.sol` (generated)
- `contracts/solana/verifier/src/lib.rs` (generated)
- `scripts/generate-verifiers.sh`
- `scripts/deploy-ethereum-verifier.ts`
- `scripts/deploy-solana-verifier.sh`

**Reference**: See `docs/CIRCUIT_KEY_ARCHITECTURE.md` for detailed explanation

---

#### 1.4 Multi-Chain API Routes (1 week)

**Goal**: Route requests to correct chain verifier

```rust
// New route structure:
POST /chain/:chain_id/submit/mint
POST /chain/:chain_id/submit/burn
POST /chain/:chain_id/submit/transfer
POST /chain/:chain_id/submit/object_update
POST /chain/:chain_id/batch/process

GET  /chain/:chain_id/state/roots
GET  /chain/:chain_id/state/supply/:asset_type
GET  /chain/:chain_id/batch/status/:batch_id

// Cross-chain queries:
GET  /chains                           # List all supported chains
GET  /state/global/supply/:asset_type  # Global supply across all chains
GET  /state/global/roots               # Global CMT/NFT/OBJ/CB roots
```

**Implementation**:

```rust
#[post("/chain/:chain_id/submit/mint")]
async fn submit_mint(
    State(api): State<Arc<FluxeApi>>,
    Path(chain_id): Path<u32>,
    Json(req): Json<SubmitMintRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // Validate chain exists
    let chain_config = api.config.chains.get(&chain_id)
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Get chain-specific verifier
    let verifier = api.global_state.get_chain_verifier(chain_id)?;

    // Verify ingress receipt is from this chain
    if req.ingress_receipt.source_chain != chain_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Verify and add to batch
    verifier.add_transaction(Transaction::Mint(req))?;

    Ok(Json(ApiResponse::success("Transaction added to batch")))
}

#[post("/chain/:chain_id/submit/burn")]
async fn submit_burn(
    State(api): State<Arc<FluxeApi>>,
    Path(chain_id): Path<u32>,
    Json(req): Json<SubmitBurnRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // Validate destination chain matches
    if req.exit_receipt.destination_chain != chain_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check global nullifier hasn't been spent
    if api.global_state.is_nullifier_spent(&req.nullifiers)? {
        return Err(StatusCode::CONFLICT); // Double-spend
    }

    let verifier = api.global_state.get_chain_verifier(chain_id)?;
    verifier.add_transaction(Transaction::Burn(req))?;

    Ok(Json(ApiResponse::success("Burn transaction added")))
}

#[get("/chains")]
async fn list_chains(
    State(api): State<Arc<FluxeApi>>,
) -> Json<Vec<ChainInfo>> {
    let chains = api.config.chains.values()
        .map(|c| ChainInfo {
            chain_id: c.chain_id,
            name: c.name.clone(),
            chain_type: c.chain_type,
            status: api.global_state.get_chain_status(c.chain_id),
            total_supply: api.global_state.get_chain_supply(c.chain_id),
        })
        .collect();

    Json(chains)
}
```

**Tasks**:
- [ ] Add `Path(chain_id)` extraction to all routes
- [ ] Implement chain validation middleware
- [ ] Add cross-chain query endpoints
- [ ] Update `FluxeClient` to accept `chain_id` parameter
- [ ] Fix 5 critical TODOs in `client.rs` (lines 105, 208, 341, 590, 619, 624)

**Files to modify**:
- `fluxe-api/src/api.rs`
- `fluxe-api/src/client.rs`
- `fluxe-api/src/middleware.rs` (new)
- `fluxe-api/src/errors.rs`

---

#### 1.5 Production Sequencer (2-3 weeks)

**Goal**: Automatic batch processing with cross-chain coordination

```rust
pub struct MultiChainSequencer {
    pub global_state: Arc<RwLock<GlobalStateManager>>,
    pub chains: HashMap<ChainId, ChainSequencer>,
    pub config: SequencerConfig,
}

pub struct ChainSequencer {
    pub chain_id: ChainId,
    pub pending_txs: PriorityQueue<PendingTransaction>,
    pub current_batch: TransactionBatch,
    pub last_finalized_batch_id: u64,
}

impl MultiChainSequencer {
    pub async fn run(&mut self) {
        // Start batch loops for each chain
        let mut handles = vec![];

        for (chain_id, sequencer) in &mut self.chains {
            let handle = tokio::spawn(async move {
                sequencer.auto_batch_loop().await
            });
            handles.push(handle);
        }

        // Wait for all chains
        futures::future::join_all(handles).await;
    }

    pub async fn coordinate_cross_chain_batch(&mut self) -> Result<()> {
        // 1. Collect batches from all chains
        // 2. Verify global nullifier uniqueness
        // 3. Update global state (CMT, NFT, OBJ, CB)
        // 4. Update per-chain state (Ingress, Exit, Supply)
        // 5. Generate aggregate proof
        // 6. Settle to all chains
    }
}

impl ChainSequencer {
    pub async fn auto_batch_loop(&mut self) {
        loop {
            // Wait for batch interval or size threshold
            tokio::select! {
                _ = sleep(self.config.batch_interval) => {},
                _ = self.batch_size_threshold_reached() => {},
            }

            self.create_batch().await?;
        }
    }

    pub async fn create_batch(&mut self) -> Result<BlockHeader> {
        // 1. Order transactions by fee
        // 2. Validate against global state
        // 3. Apply to chain state
        // 4. Return batch for aggregation
    }
}
```

**Features**:
- [ ] Automatic batch creation (time or size based)
- [ ] Transaction priority queue by fee
- [ ] Global nullifier deduplication across chains
- [ ] Cross-chain supply validation
- [ ] MEV-aware ordering (optional)
- [ ] Nonce tracking per account

**Files to create**:
- `fluxe-core/src/sequencer/multi_chain.rs` (new)
- `fluxe-core/src/sequencer/chain_sequencer.rs` (new)
- `fluxe-core/src/sequencer/batch_builder.rs` (new)
- `fluxe-core/src/sequencer/mempool.rs` (new)

---

### PHASE 2: Settlement & Proof Aggregation (5-7 weeks)

#### 2.1 Ethereum Settlement Contracts (2-3 weeks)

**Contracts**:

```solidity
// 1. Groth16 Verifier (auto-generated)
contract Groth16Verifier {
    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[] memory input
    ) public view returns (bool);
}

// 2. Fluxe Rollup Contract
contract FluxeRollup {
    struct StateRoots {
        bytes32 cmtRoot;      // Global
        bytes32 nftRoot;      // Global
        bytes32 objRoot;      // Global
        bytes32 cbRoot;       // Global
        bytes32 ingressRoot;  // Chain-specific
        bytes32 exitRoot;     // Chain-specific
        bytes32 sanctionsRoot;
        bytes32 poolRulesRoot;
    }

    mapping(uint64 => StateRoots) public finalizedBatches;
    uint64 public lastFinalizedBatchId;

    function submitBatch(
        uint64 batchId,
        StateRoots calldata prevRoots,
        StateRoots calldata newRoots,
        bytes calldata proof
    ) external onlySequencer {
        require(batchId == lastFinalizedBatchId + 1, "Invalid batch ID");
        require(keccak256(abi.encode(prevRoots)) ==
                keccak256(abi.encode(finalizedBatches[lastFinalizedBatchId])),
                "Invalid previous roots");

        // Verify aggregated proof
        require(verifier.verifyProof(parseProof(proof), publicInputs),
                "Invalid proof");

        // Store new roots
        finalizedBatches[batchId] = newRoots;
        lastFinalizedBatchId = batchId;

        emit BatchFinalized(batchId, newRoots);
    }
}

// 3. Ethereum Bridge Contract
contract FluxeBridge {
    mapping(bytes32 => bool) public processedDeposits;
    mapping(bytes32 => bool) public processedWithdrawals;
    mapping(uint32 => uint256) public poolBalances;  // Asset type => balance

    event Deposit(
        uint32 indexed assetType,
        uint256 amount,
        bytes32 beneficiaryCm,
        bytes32 ingressReceiptHash
    );

    event Withdrawal(
        uint32 indexed assetType,
        uint256 amount,
        address recipient,
        bytes32 exitReceiptHash
    );

    function deposit(
        uint32 assetType,
        uint256 amount,
        bytes32 beneficiaryCm
    ) external {
        // Transfer tokens from user
        IERC20(assetToToken[assetType]).transferFrom(
            msg.sender, address(this), amount
        );

        // Create ingress receipt hash
        bytes32 ingressHash = keccak256(abi.encodePacked(
            assetType, amount, beneficiaryCm, block.number
        ));

        // Track deposit
        processedDeposits[ingressHash] = true;
        poolBalances[assetType] += amount;

        emit Deposit(assetType, amount, beneficiaryCm, ingressHash);
    }

    function withdraw(
        bytes32 exitReceiptHash,
        uint32 assetType,
        uint256 amount,
        address recipient,
        bytes calldata merkleProof
    ) external {
        require(!processedWithdrawals[exitReceiptHash], "Already withdrawn");

        // Verify exit receipt is in finalized batch
        require(verifyExitReceipt(exitReceiptHash, merkleProof),
                "Invalid exit proof");

        // Check pool has liquidity
        require(poolBalances[assetType] >= amount,
                "Insufficient liquidity");

        // Transfer tokens
        IERC20(assetToToken[assetType]).transfer(recipient, amount);

        processedWithdrawals[exitReceiptHash] = true;
        poolBalances[assetType] -= amount;

        emit Withdrawal(assetType, amount, recipient, exitReceiptHash);
    }

    function verifyExitReceipt(
        bytes32 exitHash,
        bytes calldata merkleProof
    ) internal view returns (bool) {
        // Verify exit receipt is in latest finalized batch's exit tree
        StateRoots memory roots = rollup.finalizedBatches(
            rollup.lastFinalizedBatchId()
        );

        return MerkleProof.verify(
            merkleProof,
            roots.exitRoot,
            exitHash
        );
    }
}
```

**Tasks**:
- [ ] Write Solidity contracts
- [ ] Generate Groth16 verifier from aggregation circuit
- [ ] Write deployment scripts (Hardhat/Foundry)
- [ ] Write comprehensive tests
- [ ] Deploy to Sepolia testnet
- [ ] Gas optimization
- [ ] External audit (2-4 weeks)

**Files to create**:
- `contracts/ethereum/FluxeRollup.sol`
- `contracts/ethereum/FluxeBridge.sol`
- `contracts/ethereum/Groth16Verifier.sol` (generated)
- `contracts/ethereum/test/*.t.sol`
- `scripts/deploy-ethereum.ts`

---

#### 2.2 Solana Bridge Program (3-4 weeks)

**Architecture**:

```rust
// Anchor program structure
use anchor_lang::prelude::*;

#[program]
pub mod fluxe_bridge {
    pub fn initialize(
        ctx: Context<Initialize>,
        authority: Pubkey,
    ) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        bridge.authority = authority;
        bridge.last_finalized_batch = 0;
        Ok(())
    }

    pub fn deposit(
        ctx: Context<Deposit>,
        asset_type: u32,
        amount: u64,
        beneficiary_cm: [u8; 32],
    ) -> Result<()> {
        // Transfer SPL tokens to bridge vault
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.user_token_account.to_account_info(),
                to: ctx.accounts.bridge_vault.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        );
        transfer(cpi_ctx, amount)?;

        // Create ingress receipt
        let ingress_hash = hash_ingress_receipt(
            asset_type,
            amount,
            beneficiary_cm,
            Clock::get()?.slot,
        );

        // Track deposit
        let deposit_record = &mut ctx.accounts.deposit_record;
        deposit_record.ingress_hash = ingress_hash;
        deposit_record.processed = true;

        // Update pool balance
        let bridge = &mut ctx.accounts.bridge;
        bridge.pool_balances[asset_type as usize] += amount;

        emit!(DepositEvent {
            asset_type,
            amount,
            beneficiary_cm,
            ingress_hash,
        });

        Ok(())
    }

    pub fn submit_batch(
        ctx: Context<SubmitBatch>,
        batch_id: u64,
        new_roots: StateRoots,
        proof: Vec<u8>,
    ) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;

        require!(
            batch_id == bridge.last_finalized_batch + 1,
            ErrorCode::InvalidBatchId
        );

        // Verify proof (using on-chain verifier or CPI to verifier program)
        // Note: Groth16 verification on Solana is expensive
        // Consider using Groth16 verifier program or optimistic verification

        // Store new roots
        let batch_state = &mut ctx.accounts.batch_state;
        batch_state.roots = new_roots;
        batch_state.batch_id = batch_id;

        bridge.last_finalized_batch = batch_id;

        emit!(BatchFinalizedEvent {
            batch_id,
            roots: new_roots,
        });

        Ok(())
    }

    pub fn withdraw(
        ctx: Context<Withdraw>,
        exit_receipt_hash: [u8; 32],
        asset_type: u32,
        amount: u64,
        merkle_proof: Vec<[u8; 32]>,
    ) -> Result<()> {
        let withdrawal = &mut ctx.accounts.withdrawal_record;
        require!(!withdrawal.processed, ErrorCode::AlreadyWithdrawn);

        // Verify exit receipt in finalized batch
        let bridge = &ctx.accounts.bridge;
        let batch_state = &ctx.accounts.batch_state;

        require!(
            verify_merkle_proof(
                &merkle_proof,
                batch_state.roots.exit_root,
                exit_receipt_hash,
            ),
            ErrorCode::InvalidExitProof
        );

        // Check liquidity
        require!(
            bridge.pool_balances[asset_type as usize] >= amount,
            ErrorCode::InsufficientLiquidity
        );

        // Transfer tokens from vault to user
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.bridge_vault.to_account_info(),
                to: ctx.accounts.user_token_account.to_account_info(),
                authority: ctx.accounts.bridge.to_account_info(),
            },
            &[&[b"bridge", &[ctx.bumps.bridge]]],
        );
        transfer(cpi_ctx, amount)?;

        // Mark as processed
        withdrawal.processed = true;
        withdrawal.exit_hash = exit_receipt_hash;

        // Update pool balance
        let bridge = &mut ctx.accounts.bridge;
        bridge.pool_balances[asset_type as usize] -= amount;

        emit!(WithdrawalEvent {
            asset_type,
            amount,
            recipient: ctx.accounts.user.key(),
            exit_hash: exit_receipt_hash,
        });

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + BridgeState::LEN,
        seeds = [b"bridge"],
        bump
    )]
    pub bridge: Account<'info, BridgeState>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[account]
pub struct BridgeState {
    pub authority: Pubkey,
    pub last_finalized_batch: u64,
    pub pool_balances: [u64; 256],  // Max 256 asset types
}

#[account]
pub struct StateRoots {
    pub cmt_root: [u8; 32],
    pub nft_root: [u8; 32],
    pub obj_root: [u8; 32],
    pub cb_root: [u8; 32],
    pub ingress_root: [u8; 32],
    pub exit_root: [u8; 32],
    pub sanctions_root: [u8; 32],
    pub pool_rules_root: [u8; 32],
}
```

**Challenges**:
1. **Groth16 verification on Solana is expensive** (~2M CU)
   - **Solution**: Use optimistic verification with fraud proofs
   - **Alternative**: Use Solana verifier program with batched verification

2. **Account size limits**
   - **Solution**: Use PDA trees for large state

3. **No native Poseidon hash**
   - **Solution**: Implement Poseidon in Rust (syscall overhead)

**Tasks**:
- [ ] Write Anchor program (2 weeks)
- [ ] Implement Merkle proof verification
- [ ] Deploy Groth16 verifier program (or use optimistic)
- [ ] Write integration tests
- [ ] Deploy to Solana devnet
- [ ] Optimize compute units
- [ ] Security audit

**Files to create**:
- `contracts/solana/programs/fluxe-bridge/src/lib.rs`
- `contracts/solana/programs/fluxe-bridge/src/state.rs`
- `contracts/solana/programs/fluxe-bridge/src/instructions/*.rs`
- `contracts/solana/tests/*.ts`

---

#### 2.3 Proof Aggregation System (2-3 weeks)

**Current Issue**: `generate_aggregate_proof()` returns dummy data

**Solution**: Implement real SNARK aggregation

**Recommended Approach: Groth16 Recursive Proving**

```rust
pub struct ProofAggregator {
    pub aggregation_pk: ProvingKey<Bn254>,
    pub aggregation_vk: VerifyingKey<Bn254>,
}

impl ProofAggregator {
    pub fn aggregate_batch(
        &self,
        transactions: &[VerifiedTransaction],
        old_roots: &StateRoots,
        new_roots: &StateRoots,
    ) -> Result<AggregatedProof> {
        // Create aggregation circuit
        let circuit = AggregationCircuit {
            transaction_proofs: transactions.iter()
                .map(|tx| tx.proof.clone())
                .collect(),
            transaction_vks: transactions.iter()
                .map(|tx| self.get_vk_for_tx(tx))
                .collect(),
            old_roots: old_roots.clone(),
            new_roots: new_roots.clone(),
        };

        // Generate proof
        let proof = Groth16::<Bn254>::prove(
            &self.aggregation_pk,
            circuit,
            &mut OsRng,
        )?;

        Ok(AggregatedProof {
            proof,
            public_inputs: vec![
                old_roots.to_field_elements(),
                new_roots.to_field_elements(),
            ].concat(),
        })
    }
}

// Aggregation circuit in arkworks
pub struct AggregationCircuit {
    pub transaction_proofs: Vec<Proof<Bn254>>,
    pub transaction_vks: Vec<VerifyingKey<Bn254>>,
    pub old_roots: StateRoots,
    pub new_roots: StateRoots,
}

impl ConstraintSynthesizer<Fr> for AggregationCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<()> {
        // For each transaction proof:
        // 1. Allocate proof as witness
        // 2. Verify proof in-circuit using verifying key
        // 3. Enforce state transition: old_roots -> new_roots

        for (proof, vk) in self.transaction_proofs.iter()
            .zip(&self.transaction_vks)
        {
            let proof_var = ProofVar::new_witness(cs.clone(), || Ok(proof))?;
            let vk_var = VkVar::new_constant(cs.clone(), vk)?;

            // Verify proof in-circuit
            Groth16VerifierGadget::verify(&vk_var, &proof_var)?;
        }

        // Enforce root transitions
        let old_roots_var = StateRootsVar::new_witness(
            cs.clone(), || Ok(&self.old_roots)
        )?;
        let new_roots_var = StateRootsVar::new_witness(
            cs.clone(), || Ok(&self.new_roots)
        )?;

        // Constrain public inputs
        old_roots_var.enforce_equal(&cs.public_inputs[0..8])?;
        new_roots_var.enforce_equal(&cs.public_inputs[8..16])?;

        Ok(())
    }
}
```

**Alternative: SP1 zkVM** (aligns with FLUXE.md spec)

```rust
use sp1_sdk::{SP1Prover, SP1Stdin};

pub struct SP1Aggregator {
    pub prover: SP1Prover,
    pub elf: &'static [u8],  // Compiled SP1 program
}

impl SP1Aggregator {
    pub fn aggregate_batch(
        &self,
        transactions: &[VerifiedTransaction],
        old_roots: &StateRoots,
        new_roots: &StateRoots,
    ) -> Result<SP1Proof> {
        let mut stdin = SP1Stdin::new();

        // Write inputs
        stdin.write(&transactions);
        stdin.write(old_roots);
        stdin.write(new_roots);

        // Generate proof
        let proof = self.prover.prove_plonk(self.elf, stdin)?;

        Ok(proof)
    }
}

// SP1 guest program (runs in zkVM)
#[sp1_derive::entrypoint]
fn aggregate_batch() {
    // Read inputs
    let transactions: Vec<VerifiedTransaction> = sp1_zkvm::io::read();
    let old_roots: StateRoots = sp1_zkvm::io::read();
    let new_roots: StateRoots = sp1_zkvm::io::read();

    // Verify each Groth16 proof using precompile
    for tx in &transactions {
        sp1_zkvm::precompiles::groth16_bn254::verify(
            &tx.proof,
            &tx.public_inputs,
            &tx.verifying_key,
        );
    }

    // Verify state transitions
    let computed_roots = apply_transactions(&transactions, &old_roots);
    assert_eq!(computed_roots, new_roots);

    // Commit public outputs
    sp1_zkvm::io::commit(&old_roots);
    sp1_zkvm::io::commit(&new_roots);
}
```

**Decision**: Start with **Groth16 recursive** for faster deployment, plan migration to **SP1** for better scalability.

**Tasks**:
- [ ] Design aggregation circuit (1 week)
- [ ] Implement Groth16 verifier gadget
- [ ] Generate aggregation keys via trusted setup
- [ ] Integrate with `ServerVerifier`
- [ ] Test gas costs on Ethereum
- [ ] Benchmark proving time

**Files to create**:
- `fluxe-circuits/src/aggregation/mod.rs`
- `fluxe-circuits/src/aggregation/circuit.rs`
- `fluxe-circuits/src/aggregation/gadgets.rs`
- `fluxe-core/src/aggregator.rs`

---

### PHASE 3: Cross-Chain Coordination (3-4 weeks)

#### 3.1 Deposit Event Monitoring (1 week)

**Goal**: Watch for deposits on both chains and create ingress receipts

```rust
pub struct DepositMonitor {
    pub chains: HashMap<ChainId, ChainMonitor>,
}

pub struct ChainMonitor {
    pub chain_id: ChainId,
    pub chain_type: ChainType,
    pub rpc_client: Box<dyn RpcClient>,
    pub bridge_address: String,
    pub last_processed_block: u64,
}

#[async_trait]
pub trait RpcClient: Send + Sync {
    async fn get_latest_block(&self) -> Result<u64>;
    async fn get_deposit_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<DepositEvent>>;
}

// Ethereum implementation
pub struct EthereumRpcClient {
    pub provider: Provider<Http>,
    pub bridge_contract: FluxeBridge,
}

#[async_trait]
impl RpcClient for EthereumRpcClient {
    async fn get_deposit_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<DepositEvent>> {
        let filter = self.bridge_contract
            .event::<DepositFilter>()
            .from_block(from_block)
            .to_block(to_block);

        let logs = filter.query().await?;

        logs.into_iter().map(|log| {
            DepositEvent {
                source_chain: self.chain_id,
                asset_type: log.asset_type,
                amount: log.amount,
                beneficiary_cm: log.beneficiary_cm,
                ingress_hash: log.ingress_receipt_hash,
                block_number: log.block_number,
            }
        }).collect()
    }
}

// Solana implementation
pub struct SolanaRpcClient {
    pub rpc: RpcClient,
    pub bridge_program_id: Pubkey,
}

#[async_trait]
impl RpcClient for SolanaRpcClient {
    async fn get_deposit_events(
        &self,
        from_slot: u64,
        to_slot: u64,
    ) -> Result<Vec<DepositEvent>> {
        // Query Solana for DepositEvent logs
        let signatures = self.rpc.get_signatures_for_address_with_config(
            &self.bridge_program_id,
            GetSignaturesForAddressConfig {
                before: None,
                until: None,
                limit: Some(1000),
                ..Default::default()
            },
        ).await?;

        // Parse transaction logs for DepositEvent
        // ...
    }
}

impl DepositMonitor {
    pub async fn poll_loop(&mut self) {
        loop {
            for (chain_id, monitor) in &mut self.chains {
                match monitor.check_for_deposits().await {
                    Ok(deposits) => {
                        for deposit in deposits {
                            self.process_deposit(deposit).await?;
                        }
                    }
                    Err(e) => {
                        error!("Failed to check deposits on chain {}: {}",
                               chain_id, e);
                    }
                }
            }

            sleep(Duration::from_secs(5)).await;
        }
    }

    async fn process_deposit(&mut self, deposit: DepositEvent) -> Result<()> {
        // Create IngressReceipt
        let ingress = IngressReceipt {
            source_chain: deposit.source_chain,
            asset_type: deposit.asset_type,
            amount: deposit.amount,
            beneficiary_cm: deposit.beneficiary_cm,
            nonce: deposit.block_number,
            aux: deposit.ingress_hash.into(),
        };

        // Add to ingress queue for this chain
        let chain_state = self.global_state
            .get_chain_mut(deposit.source_chain)?;
        chain_state.add_ingress_receipt(ingress)?;

        info!("Processed deposit on chain {}: {} of asset {}",
              deposit.source_chain, deposit.amount, deposit.asset_type);

        Ok(())
    }
}
```

**Tasks**:
- [ ] Implement `DepositMonitor` with multi-chain support
- [ ] Create Ethereum event listener (ethers-rs)
- [ ] Create Solana event listener (solana-sdk)
- [ ] Add retry logic and error handling
- [ ] Implement event deduplication
- [ ] Add monitoring metrics

**Files to create**:
- `fluxe-core/src/bridge/deposit_monitor.rs`
- `fluxe-core/src/bridge/ethereum_client.rs`
- `fluxe-core/src/bridge/solana_client.rs`
- `fluxe-core/src/bridge/events.rs`

---

#### 3.2 Withdrawal Processing (1 week)

**Goal**: Process exit receipts and enable withdrawals on target chains

```rust
pub struct WithdrawalProcessor {
    pub chains: HashMap<ChainId, ChainWithdrawalHandler>,
}

pub struct ChainWithdrawalHandler {
    pub chain_id: ChainId,
    pub pending_withdrawals: Vec<ExitReceipt>,
}

impl WithdrawalProcessor {
    pub async fn process_finalized_batch(
        &mut self,
        batch_id: u64,
        batch_header: &BlockHeader,
    ) -> Result<()> {
        // For each chain, extract exit receipts
        for (chain_id, handler) in &mut self.chains {
            let chain_state = self.global_state.get_chain(chain_id)?;
            let exit_receipts = chain_state.get_exit_receipts_for_batch(batch_id)?;

            for exit in exit_receipts {
                // Generate Merkle proof for exit receipt
                let proof = chain_state.exit_tree.generate_proof(exit.hash())?;

                // Store for user claim
                handler.pending_withdrawals.push(PendingWithdrawal {
                    exit_receipt: exit,
                    merkle_proof: proof,
                    batch_id,
                    ready: true,
                });
            }
        }

        Ok(())
    }

    pub fn get_withdrawal_proof(
        &self,
        chain_id: ChainId,
        exit_hash: &[u8; 32],
    ) -> Result<WithdrawalProof> {
        let handler = self.chains.get(&chain_id)
            .ok_or(FluxeError::UnknownChain)?;

        let withdrawal = handler.pending_withdrawals.iter()
            .find(|w| w.exit_receipt.hash() == *exit_hash)
            .ok_or(FluxeError::WithdrawalNotFound)?;

        Ok(WithdrawalProof {
            exit_receipt: withdrawal.exit_receipt.clone(),
            merkle_proof: withdrawal.merkle_proof.clone(),
            batch_id: withdrawal.batch_id,
        })
    }
}
```

**API Endpoint**:

```rust
#[get("/chain/:chain_id/withdrawal/proof/:exit_hash")]
async fn get_withdrawal_proof(
    State(api): State<Arc<FluxeApi>>,
    Path((chain_id, exit_hash)): Path<(u32, String)>,
) -> Result<Json<WithdrawalProof>, StatusCode> {
    let exit_hash_bytes = hex::decode(exit_hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let proof = api.withdrawal_processor
        .get_withdrawal_proof(chain_id, &exit_hash_bytes)?;

    Ok(Json(proof))
}
```

**Tasks**:
- [ ] Implement `WithdrawalProcessor`
- [ ] Generate Merkle proofs for exit receipts
- [ ] Create withdrawal claim API
- [ ] Add withdrawal status tracking
- [ ] Handle failed withdrawals

**Files to create**:
- `fluxe-core/src/bridge/withdrawal_processor.rs`
- `fluxe-api/src/routes/withdrawals.rs`

---

#### 3.3 Cross-Chain Supply Accounting (1 week)

**Goal**: Track per-chain and global supply, detect imbalances

```rust
pub struct SupplyTracker {
    pub global_supply: HashMap<AssetType, Amount>,
    pub chain_supply: HashMap<ChainId, HashMap<AssetType, ChainSupply>>,
}

pub struct ChainSupply {
    pub deposited: Amount,
    pub withdrawn: Amount,
    pub net_balance: Amount,  // deposited - withdrawn
}

impl SupplyTracker {
    pub fn record_deposit(
        &mut self,
        chain_id: ChainId,
        asset: AssetType,
        amount: Amount,
    ) {
        // Update global supply
        *self.global_supply.entry(asset).or_insert(0) += amount;

        // Update chain supply
        let chain = self.chain_supply.entry(chain_id)
            .or_default();
        let supply = chain.entry(asset).or_default();
        supply.deposited += amount;
        supply.net_balance += amount;
    }

    pub fn record_withdrawal(
        &mut self,
        chain_id: ChainId,
        asset: AssetType,
        amount: Amount,
    ) {
        // Update global supply
        *self.global_supply.entry(asset).or_insert(0) -= amount;

        // Update chain supply
        let chain = self.chain_supply.entry(chain_id)
            .or_default();
        let supply = chain.entry(asset).or_default();
        supply.withdrawn += amount;
        supply.net_balance -= amount;
    }

    pub fn check_invariants(&self) -> Result<()> {
        for (asset, global_amount) in &self.global_supply {
            let chain_total: Amount = self.chain_supply.values()
                .filter_map(|c| c.get(asset))
                .map(|s| s.net_balance)
                .sum();

            if *global_amount != chain_total {
                return Err(FluxeError::SupplyMismatch {
                    asset: *asset,
                    global: *global_amount,
                    chain_total,
                });
            }
        }

        Ok(())
    }

    pub fn get_imbalance(
        &self,
        asset: AssetType,
    ) -> HashMap<ChainId, i64> {
        let mut imbalances = HashMap::new();

        for (chain_id, chain_supply) in &self.chain_supply {
            if let Some(supply) = chain_supply.get(&asset) {
                imbalances.insert(*chain_id, supply.net_balance as i64);
            }
        }

        imbalances
    }
}
```

**Monitoring Dashboard Data**:

```json
{
  "asset_type": 1,  // USDC
  "global_supply": 1000000000000,  // 1M USDC
  "chains": {
    "1": {  // Ethereum
      "deposited": 800000000000,
      "withdrawn": 200000000000,
      "net_balance": 600000000000,
      "imbalance_percent": 60
    },
    "501": {  // Solana
      "deposited": 200000000000,
      "withdrawn": 600000000000,
      "net_balance": -400000000000,  // ⚠️ Negative!
      "imbalance_percent": -40
    }
  },
  "rebalancing_needed": true,
  "recommended_transfer": {
    "from_chain": 1,
    "to_chain": 501,
    "amount": 400000000000
  }
}
```

**Tasks**:
- [ ] Implement `SupplyTracker`
- [ ] Add supply monitoring endpoints
- [ ] Create imbalance alerts
- [ ] Design rebalancing strategy (future phase)

**Files to create**:
- `fluxe-core/src/supply/tracker.rs`
- `fluxe-core/src/supply/monitoring.rs`

---

#### 3.4 Fee Collection & Distribution (1 week)

**Current**: Transfer circuit has fee field, but not collected

**Goal**: Accumulate fees and enable sequencer withdrawal

```rust
pub struct FeeCollector {
    pub per_chain_fees: HashMap<ChainId, HashMap<AssetType, Amount>>,
    pub sequencer_address: Address,
}

impl FeeCollector {
    pub fn collect_fee(
        &mut self,
        chain_id: ChainId,
        asset: AssetType,
        amount: Amount,
    ) {
        let chain_fees = self.per_chain_fees.entry(chain_id)
            .or_default();
        *chain_fees.entry(asset).or_insert(0) += amount;
    }

    pub fn create_fee_withdrawal(
        &mut self,
        chain_id: ChainId,
    ) -> Result<Vec<ExitReceipt>> {
        let chain_fees = self.per_chain_fees.get_mut(&chain_id)
            .ok_or(FluxeError::NoFeesCollected)?;

        let mut exits = vec![];

        for (asset, amount) in chain_fees.drain() {
            if amount == 0 { continue; }

            let exit = ExitReceipt {
                destination_chain: chain_id,
                asset_type: asset,
                amount,
                burned_nf: Nullifier::fee_nullifier(),
                nonce: Clock::now(),
                aux: F::zero(),
            };

            exits.push(exit);
        }

        Ok(exits)
    }
}
```

**Tasks**:
- [ ] Track fees per chain per asset
- [ ] Add fee to `BlockHeader`
- [ ] Create sequencer withdrawal mechanism
- [ ] Add fee distribution logic

**Files to modify/create**:
- `fluxe-core/src/fees/collector.rs`
- `fluxe-core/src/types.rs` (update BlockHeader)

---

### PHASE 4: Testing & Deployment (3-4 weeks)

#### 4.1 Integration Testing (2 weeks)

**Test Scenarios**:

1. **Basic Cross-Chain Flow**:
   ```
   Deposit 100 USDC on Ethereum
   → Mint note on FLUXE
   → Transfer privately
   → Burn note with Solana target
   → Withdraw 100 USDC on Solana
   ```

2. **Multi-Chain Parallel Deposits**:
   ```
   Deposit 50 USDC on Ethereum + 50 USDC on Solana
   → Mint two notes
   → Merge via Transfer (2 inputs, 1 output)
   → Burn to Ethereum
   → Withdraw 100 USDC on Ethereum
   ```

3. **Supply Imbalance**:
   ```
   Deposit 1000 USDC on Ethereum
   → Withdraw 600 USDC on Solana (leaves -600 imbalance)
   → Withdraw 400 USDC on Solana (should fail - insufficient liquidity)
   → Alert for rebalancing
   ```

4. **Compliance Callback Cross-Chain**:
   ```
   Deposit on Ethereum with compliance object
   → Callback invoked (FreezeAssets)
   → Attempt burn to Solana (should fail - frozen)
   → UnfreezeAssets callback
   → Burn succeeds
   ```

**Tasks**:
- [ ] Write end-to-end integration tests
- [ ] Deploy to Ethereum Sepolia + Solana Devnet
- [ ] Test proof aggregation gas costs
- [ ] Load testing (1000+ transactions)
- [ ] Reorg handling tests
- [ ] Fee market stress tests

**Files to create**:
- `tests/integration/cross_chain_flow.rs`
- `tests/integration/supply_tracking.rs`
- `tests/integration/compliance_cross_chain.rs`

---

#### 4.2 Security Audit (2-4 weeks, external)

**Scope**:
- Smart contracts (Ethereum + Solana)
- Proof aggregation circuit
- Cross-chain state coordination
- Supply accounting invariants
- Bridge security (reentrancy, access control)

**Recommended Auditors**:
- Trail of Bits
- OpenZeppelin
- Zellic
- Runtime Verification

---

#### 4.3 Testnet Deployment (1 week)

**Deployment Checklist**:

- [ ] Deploy Ethereum contracts to Sepolia
- [ ] Deploy Solana program to Devnet
- [ ] Start sequencer with both chains
- [ ] Deploy monitoring dashboard
- [ ] Set up alerting (PagerDuty, Discord)
- [ ] Create user documentation
- [ ] Run testnet beta (2-4 weeks)
- [ ] Collect feedback and fix bugs

**Infrastructure**:
- Sequencer: 2x 16GB RAM servers (redundancy)
- RPC providers: Alchemy (Ethereum) + Helius (Solana)
- Monitoring: Grafana + Prometheus
- Block explorer: Custom indexer

---

## Timeline Summary

### Total: 18-26 weeks (4.5 - 6.5 months)

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| **Phase 1**: Core Infrastructure | 6-8 weeks | Multi-chain state manager, config system, API routing, production sequencer |
| **Phase 2**: Settlement & Aggregation | 5-7 weeks | Ethereum contracts, Solana program, proof aggregation |
| **Phase 3**: Cross-Chain Coordination | 3-4 weeks | Deposit monitoring, withdrawal processing, supply tracking |
| **Phase 4**: Testing & Deployment | 3-4 weeks | Integration tests, security audit, testnet deployment |
| **Security Audit** | 2-4 weeks | External audit (can overlap with Phase 4) |

---

## Resource Requirements

### Team (Minimum)

- **2 Rust Engineers** - Core infrastructure, sequencer
- **1 Solidity Engineer** - Ethereum contracts
- **1 Solana/Rust Engineer** - Solana program
- **1 Cryptography Engineer** - Proof aggregation
- **1 DevOps Engineer** - Deployment, monitoring
- **1 QA Engineer** - Testing, security

### Infrastructure Costs

**Testnet** (~$1,500/month):
- RPC providers: $500
- Servers: $400
- Storage: $200
- Monitoring: $200
- Miscellaneous: $200

**Mainnet** (~$8,000-15,000/month):
- RPC providers: $3,000-5,000
- Sequencers (redundant): $1,500-2,500
- Archive nodes: $2,000-4,000
- DA layer: $500-1,500
- Monitoring: $500-1,000
- Security: $500-1,000

---

## Critical Risks & Mitigation

### Technical Risks

1. **Proof Aggregation Complexity**
   - Risk: May take longer than 2-3 weeks
   - Mitigation: Start with simple batching, iterate to full aggregation

2. **Solana Groth16 Verification Cost**
   - Risk: On-chain verification too expensive (>2M CU)
   - Mitigation: Use optimistic verification with fraud proofs

3. **Cross-Chain State Synchronization**
   - Risk: Race conditions, double-spends
   - Mitigation: Global nullifier set, rigorous testing

4. **Bridge Liquidity Imbalance**
   - Risk: Solana pool depleted, withdrawals fail
   - Mitigation: Monitoring alerts, manual rebalancing (automated in future)

### Economic Risks

1. **L1 Gas Costs**
   - Risk: Ethereum gas makes system uneconomical
   - Mitigation: Optimize batch size, use L2s (Arbitrum/Base)

2. **Fee Market Failure**
   - Risk: Sequencer can't sustain operations
   - Mitigation: Dynamic fee estimation, minimum viable fees

### Security Risks

1. **Bridge Exploit**
   - Risk: High-value attack vector
   - Mitigation: Multi-sig governance, insurance fund, audits

2. **Proof System Bug**
   - Risk: Invalid proofs accepted
   - Mitigation: Extensive testing, formal verification

---

## Future Enhancements (Post-Launch)

### 1. Automated Bridge Rebalancing

**Goal**: Automatically move liquidity between chains to prevent imbalances

```rust
pub struct BridgeRebalancer {
    pub target_distribution: HashMap<ChainId, f64>,  // Target %
    pub rebalance_threshold: f64,  // e.g., 20% deviation
}

impl BridgeRebalancer {
    pub async fn check_and_rebalance(&mut self) -> Result<()> {
        for asset in self.tracked_assets {
            let imbalances = self.supply_tracker.get_imbalance(asset);

            if self.needs_rebalancing(&imbalances) {
                let transfers = self.compute_rebalancing_transfers(&imbalances);

                for transfer in transfers {
                    self.execute_bridge_transfer(
                        transfer.from_chain,
                        transfer.to_chain,
                        asset,
                        transfer.amount,
                    ).await?;
                }
            }
        }

        Ok(())
    }

    async fn execute_bridge_transfer(
        &self,
        from: ChainId,
        to: ChainId,
        asset: AssetType,
        amount: Amount,
    ) -> Result<()> {
        // 1. Withdraw from 'from' chain's bridge
        // 2. Use cross-chain messaging (CCTP, LayerZero)
        // 3. Deposit to 'to' chain's bridge
        // 4. Update supply accounting
    }
}
```

**Timeline**: 3-4 weeks
**Dependencies**: Cross-chain messaging integration (CCTP/LayerZero)

---

### 2. Additional Chain Support

**Candidates**:
- Arbitrum One (EVM, low gas)
- Base (EVM, Coinbase ecosystem)
- Polygon PoS (EVM, broad adoption)
- Optimism (EVM, Superchain)
- Avalanche C-Chain (EVM)

**Per-chain effort**: 1-2 weeks (EVM chains are nearly identical)

---

### 3. Cross-Chain Direct Transfers

**Current**: Deposit on chain A, withdraw on chain B
**Future**: Transfer from note on chain A to note on chain B in single transaction

**Implementation**:
- New `CrossChainTransferCircuit`
- Burns nullifier on source chain, creates commitment on destination
- Requires bridge coordination in single batch

**Timeline**: 4-6 weeks

---

### 4. Decentralized Sequencer

**Current**: Single sequencer (centralized)
**Future**: Multi-party sequencer with consensus

**Approaches**:
- Shared sequencer (Espresso, Astria)
- Threshold encryption (Ferveo)
- Leader rotation with BFT

**Timeline**: 8-12 weeks

---

### 5. zkEVM Integration

**Goal**: Support Ethereum smart contract deposits/withdrawals

**Benefit**: Users can interact with DeFi directly via zk proofs

**Timeline**: 12-16 weeks (major architectural change)

---

## Immediate Next Steps (Week 1-2)

### Critical Path

1. **Fix FluxeClient TODOs** (3 days):
   - `client.rs` lines 105, 208, 341 - public inputs extraction
   - `api.rs` lines 590, 619, 624 - proof parsing

2. **Design GlobalStateManager** (2 days):
   - Create architecture document
   - Define interfaces for global vs per-chain state
   - Review with team

3. **Implement GlobalStateManager** (1 week):
   - Write `global.rs` and `chain_state.rs`
   - Update `ServerVerifier` to use new architecture
   - Write migration tests

4. **Create Multi-Chain Config** (2 days):
   - Design `chains.toml` format
   - Implement `ChainConfig` parser
   - Add validation

---

## Success Metrics

### Testnet Launch (Month 4-5)

- [ ] 2 chains operational (Ethereum Sepolia + Solana Devnet)
- [ ] 100+ cross-chain transactions
- [ ] <$1 average cost per transaction
- [ ] <30s finality time
- [ ] 99.9% uptime

### Mainnet Launch (Month 6-7)

- [ ] Security audit passed
- [ ] $1M+ TVL in first month
- [ ] 1000+ unique users
- [ ] <$5 average cost per transaction
- [ ] 99.95% uptime

---

## Conclusion

This roadmap provides a **concrete path to deploying FLUXE as a cross-chain privacy L2** with initial support for Ethereum and Solana. The architecture supports **cross-chain deposits and withdrawals** from day one, with automated bridge rebalancing planned as a future enhancement.

**Key Differentiators**:
- True cross-chain privacy (deposit on one chain, withdraw on another)
- Heterogeneous chain support (EVM + SVM)
- Compliance-friendly (zk-promises, sanctions screening)
- Groth16 proofs (Ethereum-compatible, fast verification)

**Estimated Timeline**: 18-26 weeks to production
**Estimated Cost**: $150K-250K (team + infrastructure)
**Risk Level**: Medium (depends on proof aggregation complexity)

---

**Next Steps**: Review with team, prioritize tasks, begin Phase 1 implementation.
