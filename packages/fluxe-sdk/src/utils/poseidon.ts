/**
 * Poseidon hash utilities for FLUXE circuits
 *
 * Uses poseidon-lite which is compatible with circomlib's Poseidon.
 */

import { poseidon1, poseidon2, poseidon3, poseidon4, poseidon5, poseidon6 } from 'poseidon-lite';

export type Field = bigint;

/**
 * Poseidon hash with variable number of inputs
 */
export function poseidonHash(inputs: Field[]): Field {
  switch (inputs.length) {
    case 1:
      return poseidon1(inputs);
    case 2:
      return poseidon2(inputs);
    case 3:
      return poseidon3(inputs);
    case 4:
      return poseidon4(inputs);
    case 5:
      return poseidon5(inputs);
    case 6:
      return poseidon6(inputs);
    default:
      // For larger inputs, chain hashes
      if (inputs.length > 6) {
        const mid = Math.ceil(inputs.length / 2);
        const left = poseidonHash(inputs.slice(0, mid));
        const right = poseidonHash(inputs.slice(mid));
        return poseidon2([left, right]);
      }
      throw new Error(`Unsupported number of inputs: ${inputs.length}`);
  }
}

/**
 * Hash state roots (8 roots) into a single commitment
 */
export function hashStateRoots(roots: Field[]): Field {
  if (roots.length !== 8) {
    throw new Error('State roots must have exactly 8 elements');
  }
  // Hash in pairs: ((0,1), (2,3)), ((4,5), (6,7))
  const h01 = poseidon2([roots[0], roots[1]]);
  const h23 = poseidon2([roots[2], roots[3]]);
  const h45 = poseidon2([roots[4], roots[5]]);
  const h67 = poseidon2([roots[6], roots[7]]);
  const h0123 = poseidon2([h01, h23]);
  const h4567 = poseidon2([h45, h67]);
  return poseidon2([h0123, h4567]);
}

/**
 * Compute note commitment
 */
export function computeNoteCommitment(
  assetType: Field,
  valueCommitment: Field,
  ownerAddr: Field,
  psi: Field,
  chainHint: Field,
  poolId: Field
): Field {
  return poseidon6([assetType, valueCommitment, ownerAddr, psi, chainHint, poolId]);
}

/**
 * Compute nullifier from spending key and commitment
 */
export function computeNullifier(spendingKey: Field, commitment: Field): Field {
  return poseidon2([spendingKey, commitment]);
}

/**
 * Convert hex string to bigint field element
 */
export function hexToField(hex: string): Field {
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  return BigInt('0x' + normalized);
}

/**
 * Convert bigint field element to hex string
 */
export function fieldToHex(field: Field): `0x${string}` {
  return `0x${field.toString(16).padStart(64, '0')}` as `0x${string}`;
}

/**
 * BN254 scalar field modulus
 */
export const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Reduce value to field
 */
export function toField(value: bigint): Field {
  return ((value % BN254_SCALAR_FIELD) + BN254_SCALAR_FIELD) % BN254_SCALAR_FIELD;
}
