/**
 * FLUXE SDK - Main entry point
 *
 * High-level SDK for interacting with FLUXE L2.
 */

import { FluxeClient, type FluxeClientOptions } from './client/FluxeClient';
import { FluxeWallet } from './wallet/FluxeWallet';
import {
  generateMintProof,
  generateBurnProof,
  generateTransferProof,
  type MintWitness,
  type BurnWitness,
  type TransferWitness,
} from './prover';
import type {
  FluxeSDKOptions,
  TxHash,
  TransactionStatus,
  DepositReceipt,
  Block,
  Hex,
  Note,
} from './types';
import { hexToField, fieldToHex, poseidonHash } from './utils/poseidon';
import { randomBytes } from '@noble/hashes/utils';
import { bytesToBigint } from './utils/encoding';

export interface TransferParams {
  to: Hex;
  amount: bigint;
  assetType: number;
  fee?: bigint;
}

export interface WithdrawParams {
  amount: bigint;
  assetType: number;
  destinationChain: number;
  destinationAddress: Hex;
}

export class FluxeSDK {
  public readonly client: FluxeClient;
  private wallet: FluxeWallet | null = null;

  constructor(options: FluxeSDKOptions) {
    this.client = new FluxeClient(options.rpcUrl, {
      timeout: options.timeout,
      retries: options.retries,
    });
  }

  /**
   * Connect a wallet to the SDK
   */
  connect(wallet: FluxeWallet): void {
    this.wallet = wallet;
  }

  /**
   * Disconnect wallet
   */
  disconnect(): void {
    this.wallet = null;
  }

  /**
   * Get connected wallet
   */
  getWallet(): FluxeWallet {
    if (!this.wallet) {
      throw new Error('No wallet connected');
    }
    return this.wallet;
  }

  /**
   * Check if wallet is connected
   */
  isConnected(): boolean {
    return this.wallet !== null;
  }

  // ============ Deposit Flow ============

  /**
   * Get pending deposits that can be claimed
   */
  async getPendingDeposits(chainId?: number): Promise<DepositReceipt[]> {
    const chain = chainId ?? (await this.client.fluxe_chainId());
    return this.client.fluxe_getPendingDeposits(chain);
  }

  /**
   * Claim a deposit by generating a mint proof
   */
  async claimDeposit(deposit: DepositReceipt): Promise<{ txHash: TxHash }> {
    const wallet = this.getWallet();

    // Get current state for merkle paths
    const stateRoots = await this.client.fluxe_getStateRoots();
    const historicalRoots = await this.client.fluxe_getHistoricalRoots();

    // Generate random values for the new note
    const psi = bytesToBigint(randomBytes(31));
    const valueBlinding = bytesToBigint(randomBytes(31));

    // Build mint witness
    const witness: MintWitness = {
      ownerPrivKey: hexToField(wallet.getSpendingKey()),
      valueBlinding,
      psi,
      assetType: BigInt(deposit.assetType),
      amount: deposit.amount,
      ingressReceipt: {
        sourceChain: BigInt(deposit.sourceChain),
        nonce: BigInt(deposit.nonce),
        aux: 0n, // TODO: Get from deposit
      },
      // Merkle paths would need to be fetched from sequencer
      cmtTreePath: [],
      cmtTreeIndices: [],
      ingressTreePath: [],
      ingressTreeIndices: [],
    };

    // Generate proof
    const { proof, publicInputs } = await generateMintProof(witness);

    // Submit transaction
    const result = await this.client.fluxe_submitTransaction({
      txType: 'mint',
      proof,
      publicInputs,
      chainId: deposit.sourceChain,
    });

    // Add note to wallet (optimistically)
    const noteCommitment = wallet.createNoteCommitment(
      deposit.assetType,
      poseidonHash([deposit.amount, valueBlinding]),
      psi,
      0,
      0
    );

    wallet.addNote({
      commitment: noteCommitment,
      assetType: deposit.assetType,
      amount: deposit.amount,
      ownerAddr: wallet.address,
      psi: fieldToHex(psi),
      chainHint: 0,
      poolId: 0,
    });

    return { txHash: result.txHash as TxHash };
  }

  // ============ Transfer Flow ============

  /**
   * Transfer value to another address
   */
  async transfer(params: TransferParams): Promise<{ txHash: TxHash }> {
    const wallet = this.getWallet();

    // Find notes to spend
    const availableNotes = wallet.getNotesByAsset(params.assetType);
    const fee = params.fee ?? 1000n;
    const totalNeeded = params.amount + fee;

    // Select notes (simple greedy selection)
    let selectedAmount = 0n;
    const selectedNotes: Note[] = [];
    for (const note of availableNotes) {
      if (selectedAmount >= totalNeeded) break;
      selectedNotes.push(note);
      selectedAmount += note.amount;
    }

    if (selectedAmount < totalNeeded) {
      throw new Error(`Insufficient balance: have ${selectedAmount}, need ${totalNeeded}`);
    }

    // Get current state roots
    const stateRoots = await this.client.fluxe_getStateRoots();

    // Build witness
    const witness: TransferWitness = {
      inputNotes: selectedNotes.map((note) => ({
        ownerPrivKey: hexToField(wallet.getSpendingKey()),
        value: note.amount,
        valueBlinding: bytesToBigint(randomBytes(31)),
        psi: hexToField(note.psi),
        assetType: BigInt(note.assetType),
        path: [], // TODO: Fetch from sequencer
        indices: [],
      })),
      outputNotes: [
        // Output to recipient
        {
          ownerPubKey: hexToField(params.to),
          value: params.amount,
          valueBlinding: bytesToBigint(randomBytes(31)),
          psi: bytesToBigint(randomBytes(31)),
        },
        // Change back to self (if any)
        ...(selectedAmount > totalNeeded
          ? [
              {
                ownerPubKey: hexToField(wallet.address),
                value: selectedAmount - totalNeeded,
                valueBlinding: bytesToBigint(randomBytes(31)),
                psi: bytesToBigint(randomBytes(31)),
              },
            ]
          : []),
      ],
      fee,
      cmtRoot: hexToField(stateRoots.cmtRoot),
      nftRoot: hexToField(stateRoots.nftRoot),
      sanctionsRoot: hexToField(stateRoots.sanctionsRoot),
      poolRulesRoot: hexToField(stateRoots.poolRulesRoot),
    };

    // Generate proof
    const { proof, publicInputs } = await generateTransferProof(witness);

    // Submit transaction
    const result = await this.client.fluxe_submitTransaction({
      txType: 'transfer',
      proof,
      publicInputs,
    });

    // Remove spent notes from wallet
    for (const note of selectedNotes) {
      wallet.removeNote(note.commitment);
    }

    return { txHash: result.txHash as TxHash };
  }

  // ============ Withdrawal Flow ============

  /**
   * Withdraw to L1
   */
  async withdraw(params: WithdrawParams): Promise<{ txHash: TxHash; exitHash: Hex }> {
    const wallet = this.getWallet();

    // Find notes to spend
    const availableNotes = wallet.getNotesByAsset(params.assetType);
    const fee = 1500n; // Burn fee is higher
    const totalNeeded = params.amount + fee;

    // Select notes
    let selectedAmount = 0n;
    const selectedNotes: Note[] = [];
    for (const note of availableNotes) {
      if (selectedAmount >= totalNeeded) break;
      selectedNotes.push(note);
      selectedAmount += note.amount;
    }

    if (selectedAmount < totalNeeded) {
      throw new Error(`Insufficient balance for withdrawal`);
    }

    // Get current state roots
    const stateRoots = await this.client.fluxe_getStateRoots();

    // For simplicity, use first note (in production, would need proper UTXO selection)
    const note = selectedNotes[0];

    const witness: BurnWitness = {
      ownerPrivKey: hexToField(wallet.getSpendingKey()),
      noteValue: note.amount,
      valueBlinding: bytesToBigint(randomBytes(31)),
      psi: hexToField(note.psi),
      notePath: [], // TODO: Fetch from sequencer
      noteIndices: [],
      assetType: BigInt(params.assetType),
      amount: params.amount,
      recipient: hexToField(params.destinationAddress),
      destChain: BigInt(params.destinationChain),
      cmtRoot: hexToField(stateRoots.cmtRoot),
      nftRoot: hexToField(stateRoots.nftRoot),
    };

    // Generate proof
    const { proof, publicInputs, publicSignals } = await generateBurnProof(witness);

    // Submit transaction
    const result = await this.client.fluxe_submitTransaction({
      txType: 'burn',
      proof,
      publicInputs,
      chainId: params.destinationChain,
    });

    // Compute exit hash from public signals (typically includes nullifier and amount)
    const exitHash = fieldToHex(poseidonHash([
      BigInt(publicSignals[0] || '0'),
      params.amount,
      BigInt(params.destinationChain),
    ]));

    // Remove spent note
    wallet.removeNote(note.commitment);

    return { txHash: result.txHash as TxHash, exitHash };
  }

  // ============ Transaction Tracking ============

  /**
   * Wait for a transaction to be finalized
   */
  async waitForTransaction(
    txHash: TxHash,
    options: { timeout?: number; pollInterval?: number } = {}
  ): Promise<TransactionStatus> {
    const timeout = options.timeout ?? 120000; // 2 minutes
    const pollInterval = options.pollInterval ?? 2000; // 2 seconds

    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const status = await this.client.fluxe_getTransactionStatus(txHash);

      if (status.status === 'finalized' || status.status === 'failed') {
        return status;
      }

      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }

    throw new Error(`Transaction ${txHash} timed out`);
  }

  // ============ Balance Queries ============

  /**
   * Get balance for an asset type
   */
  getBalance(assetType: number): bigint {
    const wallet = this.getWallet();
    return wallet.getBalance(assetType);
  }

  /**
   * Get all balances
   */
  getBalances(): Map<number, bigint> {
    const wallet = this.getWallet();
    const notes = wallet.getNotes();
    const balances = new Map<number, bigint>();

    for (const note of notes) {
      const current = balances.get(note.assetType) ?? 0n;
      balances.set(note.assetType, current + note.amount);
    }

    return balances;
  }
}
