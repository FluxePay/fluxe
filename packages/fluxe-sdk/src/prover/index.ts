/**
 * FLUXE Proof Generation using snarkjs
 *
 * Generates Groth16 proofs for FLUXE circuits in the browser.
 */

import type { ProofOutput, TxType, Hex } from '../types';
import { encodeProof, encodePublicInputs } from '../utils/encoding';

// Dynamic import for snarkjs (works in browser and Node.js)
let snarkjs: typeof import('snarkjs') | null = null;

async function getSnarkjs(): Promise<typeof import('snarkjs')> {
  if (!snarkjs) {
    snarkjs = await import('snarkjs');
  }
  return snarkjs;
}

export interface CircuitPaths {
  wasmPath: string;
  zkeyPath: string;
}

export interface ProverConfig {
  circuitsBaseUrl: string;
}

const DEFAULT_CONFIG: ProverConfig = {
  circuitsBaseUrl: '/circuits',
};

let globalConfig = DEFAULT_CONFIG;

/**
 * Configure the prover with custom circuit paths
 */
export function configureProver(config: Partial<ProverConfig>): void {
  globalConfig = { ...globalConfig, ...config };
}

/**
 * Get circuit paths for a given transaction type
 */
function getCircuitPaths(txType: TxType): CircuitPaths {
  const base = globalConfig.circuitsBaseUrl;
  return {
    wasmPath: `${base}/${txType}.wasm`,
    zkeyPath: `${base}/${txType}.zkey`,
  };
}

/**
 * Generate a Groth16 proof
 */
async function generateProof(
  txType: TxType,
  witness: Record<string, unknown>
): Promise<ProofOutput> {
  const snarks = await getSnarkjs();
  const paths = getCircuitPaths(txType);

  // Fetch circuit files
  const [wasmBuffer, zkeyBuffer] = await Promise.all([
    fetch(paths.wasmPath).then((r) => r.arrayBuffer()),
    fetch(paths.zkeyPath).then((r) => r.arrayBuffer()),
  ]);

  // Generate the proof
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { proof, publicSignals } = await snarks.groth16.fullProve(
    witness as any,
    new Uint8Array(wasmBuffer),
    new Uint8Array(zkeyBuffer)
  );

  // Cast proof to our expected format
  return {
    proof: proof as unknown as ProofOutput['proof'],
    publicSignals
  };
}

// ============ Mint Circuit ============

export interface MintWitness {
  // Private inputs
  ownerPrivKey: bigint;
  valueBlinding: bigint;
  psi: bigint; // Per-note entropy
  // Public inputs
  assetType: bigint;
  amount: bigint;
  ingressReceipt: {
    sourceChain: bigint;
    nonce: bigint;
    aux: bigint;
  };
  // Merkle paths
  cmtTreePath: bigint[];
  cmtTreeIndices: number[];
  ingressTreePath: bigint[];
  ingressTreeIndices: number[];
}

export async function generateMintProof(witness: MintWitness): Promise<{
  proof: Hex;
  publicInputs: Hex;
  publicSignals: string[];
}> {
  const result = await generateProof('mint', witness as unknown as Record<string, unknown>);

  return {
    proof: encodeProof(result.proof),
    publicInputs: encodePublicInputs(result.publicSignals),
    publicSignals: result.publicSignals,
  };
}

// ============ Burn Circuit ============

export interface BurnWitness {
  // Private inputs
  ownerPrivKey: bigint;
  noteValue: bigint;
  valueBlinding: bigint;
  psi: bigint;
  notePath: bigint[];
  noteIndices: number[];
  // Public inputs
  assetType: bigint;
  amount: bigint;
  recipient: bigint; // Destination address (L1)
  destChain: bigint;
  // State roots
  cmtRoot: bigint;
  nftRoot: bigint;
}

export async function generateBurnProof(witness: BurnWitness): Promise<{
  proof: Hex;
  publicInputs: Hex;
  publicSignals: string[];
}> {
  const result = await generateProof('burn', witness as unknown as Record<string, unknown>);

  return {
    proof: encodeProof(result.proof),
    publicInputs: encodePublicInputs(result.publicSignals),
    publicSignals: result.publicSignals,
  };
}

// ============ Transfer Circuit ============

export interface TransferWitness {
  // Private inputs for input notes
  inputNotes: Array<{
    ownerPrivKey: bigint;
    value: bigint;
    valueBlinding: bigint;
    psi: bigint;
    assetType: bigint;
    path: bigint[];
    indices: number[];
  }>;
  // Private inputs for output notes
  outputNotes: Array<{
    ownerPubKey: bigint;
    value: bigint;
    valueBlinding: bigint;
    psi: bigint;
  }>;
  // Public inputs
  fee: bigint;
  // State roots
  cmtRoot: bigint;
  nftRoot: bigint;
  sanctionsRoot: bigint;
  poolRulesRoot: bigint;
}

export async function generateTransferProof(witness: TransferWitness): Promise<{
  proof: Hex;
  publicInputs: Hex;
  publicSignals: string[];
}> {
  const result = await generateProof('transfer', witness as unknown as Record<string, unknown>);

  return {
    proof: encodeProof(result.proof),
    publicInputs: encodePublicInputs(result.publicSignals),
    publicSignals: result.publicSignals,
  };
}

// ============ Object Update Circuit ============

export interface ObjectUpdateWitness {
  // Private inputs
  oldObjectData: bigint[];
  newObjectData: bigint[];
  updateProof: bigint[];
  // Public inputs
  oldObjectCm: bigint;
  newObjectCm: bigint;
  currentTime: bigint;
  // State roots
  objRoot: bigint;
  cbRoot: bigint;
}

export async function generateObjectUpdateProof(witness: ObjectUpdateWitness): Promise<{
  proof: Hex;
  publicInputs: Hex;
  publicSignals: string[];
}> {
  const result = await generateProof('object_update', witness as unknown as Record<string, unknown>);

  return {
    proof: encodeProof(result.proof),
    publicInputs: encodePublicInputs(result.publicSignals),
    publicSignals: result.publicSignals,
  };
}

/**
 * Verify a proof locally (for testing)
 */
export async function verifyProof(
  txType: TxType,
  proof: ProofOutput['proof'],
  publicSignals: string[]
): Promise<boolean> {
  const snarks = await getSnarkjs();
  const paths = getCircuitPaths(txType);

  // Fetch verification key
  const vkeyResponse = await fetch(paths.zkeyPath.replace('.zkey', '_vkey.json'));
  const vkey = await vkeyResponse.json();

  return snarks.groth16.verify(vkey, publicSignals, proof);
}
