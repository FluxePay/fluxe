/**
 * FLUXE SDK Type Definitions
 */

// ============ Core Types ============

export type Hex = `0x${string}`;
export type Address = Hex;
export type TxHash = Hex;
export type BigIntString = string;

// ============ Transaction Types ============

export type TxType = 'mint' | 'burn' | 'transfer' | 'object_update';

export interface SignedTransaction {
  txType: TxType;
  proof: Hex;
  publicInputs: Hex;
  chainId?: number;
}

export interface TransactionStatus {
  txHash: TxHash;
  status: 'pending' | 'processing' | 'included' | 'finalized' | 'failed';
  queuePosition?: number;
  batchId?: number;
  l1TxHash?: TxHash;
  reason?: string;
}

export interface TransactionReceipt {
  txHash: TxHash;
  batchId: number;
  index: number;
  blockNumber: number;
  timestamp: number;
  status: 'success' | 'failed';
  txType: TxType;
}

// ============ Block Types ============

export interface BlockHeader {
  batchId: number;
  timestamp: number;
  txCount: number;
  prevRootsHash: Hex;
  newRootsHash: Hex;
  proofHash: Hex;
}

export interface Block {
  header: BlockHeader;
  stateRoots: StateRoots;
  txHashes: TxHash[];
}

// ============ State Types ============

export interface StateRoots {
  cmtRoot: Hex;      // Commitment tree root
  nftRoot: Hex;      // Nullifier tree root
  objRoot: Hex;      // Object tree root
  cbRoot: Hex;       // Callback tree root
  ingressRoot: Hex;  // Ingress tree root
  exitRoot: Hex;     // Exit tree root
  sanctionsRoot: Hex;
  poolRulesRoot: Hex;
}

export interface MerkleProof {
  leaf: Hex;
  leafIndex: number;
  siblings: Hex[];
  root: Hex;
}

// ============ Note Types ============

export interface Note {
  commitment: Hex;
  assetType: number;
  amount: bigint;
  ownerAddr: Hex;
  psi: Hex;          // Per-note entropy
  chainHint: number;
  poolId: number;
}

export interface EncryptedNote {
  ciphertext: Hex;
  ephemeralPubKey: Hex;
  nonce: Hex;
}

export interface Nullifier {
  hash: Hex;
  spent: boolean;
  batchId?: number;
}

// ============ Bridge Types ============

export interface DepositReceipt {
  ingressHash: Hex;
  nonce: number;
  assetType: number;
  amount: bigint;
  beneficiaryCm: Hex;
  sourceChain: number;
  status: 'pending' | 'processed';
}

export interface ExitReceipt {
  exitHash: Hex;
  assetType: number;
  amount: bigint;
  recipient: Address;
  destChain: number;
  batchId: number;
  processed: boolean;
}

export interface ExitProof {
  exitHash: Hex;
  merkleProof: Hex[];
  leafIndex: number;
  exitRoot: Hex;
  batchId: number;
}

export interface WithdrawalStatus {
  exitHash: Hex;
  status: 'pending' | 'provable' | 'claimed';
  batchId?: number;
  exitProof?: ExitProof;
}

// ============ Asset Types ============

export interface Asset {
  assetType: number;
  symbol: string;
  decimals: number;
  minDeposit: bigint;
  maxDeposit: bigint;
  enabled: boolean;
  chains: ChainConfig[];
}

export interface ChainConfig {
  chainId: number;
  chainName: string;
  tokenAddress: Address;
  bridgeAddress: Address;
}

// ============ Fee Types ============

export interface FeeEstimate {
  baseFee: bigint;
  priorityFee: bigint;
  totalFee: bigint;
  assetType: number;
}

// ============ Network Types ============

export interface NetworkInfo {
  l2ChainId: number;
  networkName: string;
  settlementChains: SettlementChain[];
  latestBatch: number;
  genesisFinalized: boolean;
}

export interface SettlementChain {
  chainId: number;
  chainName: string;
  bridgeAddress: Address;
  status: 'active' | 'paused' | 'disabled';
}

export interface SequencerInfo {
  address: Address;
  pendingTxCount: number;
  lastBatchTime: number;
  status: 'active' | 'paused';
}

// ============ Pool Types ============

export interface PoolBalance {
  chainId: number;
  assetType: number;
  balance: bigint;
  pendingWithdrawals: bigint;
}

// ============ Wallet Types ============

export interface WalletKeys {
  spendingKey: Uint8Array;
  viewingKey: Uint8Array;
  address: Hex;
}

export interface EncryptedKeystore {
  version: number;
  address: Hex;
  crypto: {
    cipher: string;
    ciphertext: Hex;
    cipherparams: { iv: Hex };
    kdf: string;
    kdfparams: Record<string, unknown>;
    mac: Hex;
  };
}

// ============ Prover Types ============

export interface ProofInput {
  witness: Record<string, unknown>;
  wasmPath: string;
  zkeyPath: string;
}

export interface ProofOutput {
  proof: {
    pi_a: [string, string, string];
    pi_b: [[string, string], [string, string], [string, string]];
    pi_c: [string, string, string];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
}

// ============ RPC Types ============

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  method: string;
  params: unknown[];
  id: number | string;
}

export interface JsonRpcResponse<T = unknown> {
  jsonrpc: '2.0';
  result?: T;
  error?: JsonRpcError;
  id: number | string;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

// ============ SDK Options ============

export interface FluxeSDKOptions {
  rpcUrl: string;
  timeout?: number;
  retries?: number;
}

export interface WalletOptions {
  password: string;
  mnemonic?: string;
}
