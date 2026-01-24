/**
 * FLUXE JSON-RPC Client
 *
 * Provides typed methods for all FLUXE JSON-RPC endpoints.
 */

import type {
  Block,
  BlockHeader,
  StateRoots,
  SignedTransaction,
  TransactionStatus,
  TransactionReceipt,
  MerkleProof,
  EncryptedNote,
  Nullifier,
  DepositReceipt,
  ExitReceipt,
  ExitProof,
  WithdrawalStatus,
  Asset,
  PoolBalance,
  NetworkInfo,
  SequencerInfo,
  FeeEstimate,
  TxType,
  TxHash,
  Hex,
  JsonRpcRequest,
  JsonRpcResponse,
  JsonRpcError,
} from '../types';

export class FluxeClientError extends Error {
  constructor(
    message: string,
    public code: number,
    public data?: unknown
  ) {
    super(message);
    this.name = 'FluxeClientError';
  }
}

export interface FluxeClientOptions {
  timeout?: number;
  retries?: number;
}

export class FluxeClient {
  private rpcUrl: string;
  private timeout: number;
  private retries: number;
  private requestId = 0;

  constructor(rpcUrl: string, options: FluxeClientOptions = {}) {
    this.rpcUrl = rpcUrl;
    this.timeout = options.timeout ?? 30000;
    this.retries = options.retries ?? 3;
  }

  // ============ Low-level RPC ============

  private async call<T>(method: string, params: unknown[] = []): Promise<T> {
    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method,
      params,
      id: ++this.requestId,
    };

    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        const response = await fetch(this.rpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(request),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }

        const json: JsonRpcResponse<T> = await response.json();

        if (json.error) {
          throw new FluxeClientError(
            json.error.message,
            json.error.code,
            json.error.data
          );
        }

        return json.result as T;
      } catch (error) {
        lastError = error as Error;
        if (attempt < this.retries - 1) {
          await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
        }
      }
    }

    throw lastError;
  }

  // ============ Transaction Methods ============

  /**
   * Submit a signed transaction with proof
   */
  async fluxe_submitTransaction(tx: SignedTransaction): Promise<{
    txHash: TxHash;
    queuePosition: number;
    estimatedBatch?: number;
  }> {
    return this.call('fluxe_submitTransaction', [
      {
        proof: tx.proof,
        public_inputs: tx.publicInputs,
        tx_type: tx.txType,
        chain_id: tx.chainId,
      },
    ]);
  }

  /**
   * Get transaction status by hash
   */
  async fluxe_getTransactionStatus(txHash: TxHash): Promise<TransactionStatus> {
    const result = await this.call<{
      tx_hash: string;
      status: unknown;
      submitted_at: number;
      tx_type: string;
    }>('fluxe_getTransactionStatus', [txHash]);

    return this.parseTransactionStatus(result);
  }

  /**
   * Get multiple transaction statuses
   */
  async fluxe_getTransactionStatuses(txHashes: TxHash[]): Promise<TransactionStatus[]> {
    const results = await this.call<unknown[]>('fluxe_getTransactionStatuses', [txHashes]);
    return results.map((r) => this.parseTransactionStatus(r as Record<string, unknown>));
  }

  /**
   * Get transaction receipt (after finalization)
   */
  async fluxe_getTransactionReceipt(txHash: TxHash): Promise<TransactionReceipt | null> {
    return this.call('fluxe_getTransactionReceipt', [txHash]);
  }

  // ============ Block Methods ============

  /**
   * Get latest finalized block number
   */
  async fluxe_blockNumber(): Promise<number> {
    const info = await this.fluxe_chainInfo();
    return info.latestBatch;
  }

  /**
   * Get block by batch ID
   */
  async fluxe_getBlock(batchId: number): Promise<Block | null> {
    try {
      return await this.call<Block>('fluxe_getBlock', [batchId]);
    } catch (error) {
      if ((error as FluxeClientError).code === -32004) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Get block header only (lighter)
   */
  async fluxe_getBlockHeader(batchId: number): Promise<BlockHeader | null> {
    try {
      return await this.call<BlockHeader>('fluxe_getBlockHeader', [batchId]);
    } catch (error) {
      if ((error as FluxeClientError).code === -32004) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Get latest finalized block
   */
  async fluxe_getLatestBlock(): Promise<Block> {
    return this.call('fluxe_getLatestBlock', []);
  }

  /**
   * Get range of blocks
   */
  async fluxe_getBlocks(fromBatch: number, toBatch: number): Promise<Block[]> {
    return this.call('fluxe_getBlocks', [fromBatch, toBatch]);
  }

  // ============ State Methods ============

  /**
   * Get current state roots
   */
  async fluxe_getStateRoots(): Promise<StateRoots> {
    const result = await this.call<{
      cmt_root: string;
      nft_root: string;
      obj_root: string;
      cb_root: string;
      ingress_root: string;
      exit_root: string;
      sanctions_root: string;
      pool_rules_root: string;
    }>('fluxe_getStateRoots', []);

    return {
      cmtRoot: result.cmt_root as Hex,
      nftRoot: result.nft_root as Hex,
      objRoot: result.obj_root as Hex,
      cbRoot: result.cb_root as Hex,
      ingressRoot: result.ingress_root as Hex,
      exitRoot: result.exit_root as Hex,
      sanctionsRoot: result.sanctions_root as Hex,
      poolRulesRoot: result.pool_rules_root as Hex,
    };
  }

  /**
   * Get current state root hash
   */
  async fluxe_getStateRoot(): Promise<Hex> {
    const info = await this.call<{ latest_batch: number }>('fluxe_chainInfo', []);
    const block = await this.fluxe_getBlock(info.latest_batch);
    return block?.header.newRootsHash ?? ('0x' + '0'.repeat(64)) as Hex;
  }

  /**
   * Get historical roots buffer (64 slots)
   */
  async fluxe_getHistoricalRoots(): Promise<{ roots: Hex[]; currentIndex: number }> {
    const result = await this.call<{
      roots: string[];
      current_index: number;
      size: number;
    }>('fluxe_getHistoricalRoots', []);

    return {
      roots: result.roots as Hex[],
      currentIndex: result.current_index,
    };
  }

  /**
   * Check if root exists in historical buffer
   */
  async fluxe_containsHistoricalRoot(rootHash: Hex): Promise<boolean> {
    return this.call('fluxe_isValidRoot', [rootHash]);
  }

  /**
   * Get merkle proof for commitment
   */
  async fluxe_getNoteProof(commitment: Hex): Promise<MerkleProof | null> {
    const result = await this.call<{
      exists: boolean;
      root: string;
      merkle_path: string[] | null;
      leaf_index: number | null;
    }>('fluxe_getNoteProof', [commitment]);

    if (!result.exists || !result.merkle_path) {
      return null;
    }

    return {
      leaf: commitment,
      leafIndex: result.leaf_index!,
      siblings: result.merkle_path as Hex[],
      root: result.root as Hex,
    };
  }

  // ============ Account/Note Methods ============

  /**
   * Check if nullifier has been spent
   */
  async fluxe_isNullifierSpent(nullifier: Hex): Promise<boolean> {
    const result = await this.call<{ spent: boolean }>('fluxe_checkNullifier', [nullifier]);
    return result.spent;
  }

  /**
   * Check multiple nullifiers
   */
  async fluxe_checkNullifiers(nullifiers: Hex[]): Promise<Nullifier[]> {
    const results = await this.call<{ spent: boolean; batch_id: number | null }[]>(
      'fluxe_checkNullifiers',
      [nullifiers]
    );

    return results.map((r, i) => ({
      hash: nullifiers[i],
      spent: r.spent,
      batchId: r.batch_id ?? undefined,
    }));
  }

  // ============ Bridge Methods ============

  /**
   * Get deposit receipt by nonce
   */
  async fluxe_getDeposit(chainId: number, nonce: number): Promise<DepositReceipt | null> {
    return this.call('fluxe_getDeposit', [chainId, nonce]);
  }

  /**
   * Get pending deposits for a chain
   */
  async fluxe_getPendingDeposits(chainId: number): Promise<DepositReceipt[]> {
    return this.call('fluxe_getPendingDeposits', [chainId]);
  }

  /**
   * Get exit proof for withdrawal
   */
  async fluxe_getExitProof(exitHash: Hex): Promise<ExitProof> {
    const result = await this.call<{
      exit_hash: string;
      merkle_proof: string[];
      leaf_index: number;
      exit_root: string;
      batch_id: number;
    }>('fluxe_getExitProof', [exitHash]);

    return {
      exitHash: result.exit_hash as Hex,
      merkleProof: result.merkle_proof as Hex[],
      leafIndex: result.leaf_index,
      exitRoot: result.exit_root as Hex,
      batchId: result.batch_id,
    };
  }

  /**
   * Get pool balances across chains
   */
  async fluxe_getPoolBalances(): Promise<PoolBalance[]> {
    const results = await this.call<{
      chain_id: number;
      asset_type: number;
      balance: string;
      pending_withdrawals: string;
    }[]>('fluxe_getPoolBalances', []);

    return results.map((r) => ({
      chainId: r.chain_id,
      assetType: r.asset_type,
      balance: BigInt(r.balance),
      pendingWithdrawals: BigInt(r.pending_withdrawals),
    }));
  }

  // ============ Chain Info Methods ============

  /**
   * Get chain info
   */
  async fluxe_chainInfo(): Promise<{
    chainId: number;
    chainName: string;
    latestBatch: number;
    pendingTxs: number;
    genesisFinalized: boolean;
  }> {
    const result = await this.call<{
      chain_id: number;
      chain_name: string;
      latest_batch: number;
      pending_txs: number;
      genesis_finalized: boolean;
    }>('fluxe_chainInfo', []);

    return {
      chainId: result.chain_id,
      chainName: result.chain_name,
      latestBatch: result.latest_batch,
      pendingTxs: result.pending_txs,
      genesisFinalized: result.genesis_finalized,
    };
  }

  /**
   * Get L2 chain ID
   */
  async fluxe_chainId(): Promise<number> {
    const info = await this.fluxe_chainInfo();
    return info.chainId;
  }

  /**
   * Get sync status
   */
  async fluxe_syncStatus(): Promise<{
    isSyncing: boolean;
    currentBatch: number;
    highestBatch: number;
  }> {
    const result = await this.call<{
      is_syncing: boolean;
      current_batch: number;
      highest_batch: number;
    }>('fluxe_syncStatus', []);

    return {
      isSyncing: result.is_syncing,
      currentBatch: result.current_batch,
      highestBatch: result.highest_batch,
    };
  }

  /**
   * Estimate fee for transaction type
   */
  async fluxe_estimateFee(txType: TxType, assetType: number): Promise<FeeEstimate> {
    const result = await this.call<{
      base_fee: string;
      priority_fee: string;
      total_fee: string;
      asset_type: number;
    }>('fluxe_estimateFee', [{ tx_type: txType, asset_type: assetType }]);

    return {
      baseFee: BigInt(result.base_fee),
      priorityFee: BigInt(result.priority_fee),
      totalFee: BigInt(result.total_fee),
      assetType: result.asset_type,
    };
  }

  /**
   * Health check
   */
  async fluxe_health(): Promise<boolean> {
    return this.call('fluxe_health', []);
  }

  // ============ Ethereum-compatible Methods ============

  /**
   * Get chain ID (eth_chainId compatible)
   */
  async eth_chainId(): Promise<string> {
    return this.call('eth_chainId', []);
  }

  /**
   * Get block number (eth_blockNumber compatible)
   */
  async eth_blockNumber(): Promise<string> {
    return this.call('eth_blockNumber', []);
  }

  // ============ Helper Methods ============

  private parseTransactionStatus(result: Record<string, unknown>): TransactionStatus {
    const status = result.status as Record<string, unknown>;
    let parsedStatus: TransactionStatus['status'];
    let extra: Partial<TransactionStatus> = {};

    if ('pending' in status) {
      parsedStatus = 'pending';
      extra.queuePosition = (status.pending as Record<string, number>).queue_position;
    } else if ('processing' in status) {
      parsedStatus = 'processing';
    } else if ('included' in status) {
      parsedStatus = 'included';
      const included = status.included as Record<string, number>;
      extra.batchId = included.batch_id;
    } else if ('finalized' in status) {
      parsedStatus = 'finalized';
      const finalized = status.finalized as Record<string, unknown>;
      extra.batchId = finalized.batch_id as number;
      extra.l1TxHash = finalized.l1_tx_hash as TxHash | undefined;
    } else if ('failed' in status) {
      parsedStatus = 'failed';
      extra.reason = (status.failed as Record<string, string>).reason;
    } else {
      parsedStatus = 'pending';
    }

    return {
      txHash: result.tx_hash as TxHash,
      status: parsedStatus,
      ...extra,
    };
  }
}
