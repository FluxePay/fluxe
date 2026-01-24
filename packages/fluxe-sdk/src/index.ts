/**
 * FLUXE SDK - Privacy-preserving L2 SDK
 *
 * @packageDocumentation
 */

// Main SDK class
export { FluxeSDK, type TransferParams, type WithdrawParams } from './FluxeSDK';

// Wallet
export { FluxeWallet } from './wallet';

// Client
export { FluxeClient, FluxeClientError, type FluxeClientOptions } from './client';

// Prover
export {
  generateMintProof,
  generateBurnProof,
  generateTransferProof,
  generateObjectUpdateProof,
  verifyProof,
  configureProver,
  type MintWitness,
  type BurnWitness,
  type TransferWitness,
  type ObjectUpdateWitness,
  type CircuitPaths,
  type ProverConfig,
} from './prover';

// Utils
export {
  poseidonHash,
  hashStateRoots,
  computeNoteCommitment,
  computeNullifier,
  hexToField,
  fieldToHex,
  BN254_SCALAR_FIELD,
  toField,
} from './utils/poseidon';

export {
  bytesToHex,
  hexToBytes,
  bigintToBytes,
  bytesToBigint,
  concatBytes,
  padBytes,
  bytesEqual,
  encodeProof,
  encodePublicInputs,
} from './utils/encoding';

// Types
export * from './types';
