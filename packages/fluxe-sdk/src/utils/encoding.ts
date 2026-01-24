/**
 * Encoding utilities for FLUXE SDK
 */

import type { Hex } from '../types';

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): Hex {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}` as Hex;
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert bigint to fixed-size bytes (big-endian)
 */
export function bigintToBytes(value: bigint, size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  let v = value;
  for (let i = size - 1; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

/**
 * Convert bytes to bigint (big-endian)
 */
export function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Concatenate multiple byte arrays
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Pad or truncate bytes to fixed size
 */
export function padBytes(bytes: Uint8Array, size: number, padLeft = true): Uint8Array {
  if (bytes.length === size) return bytes;
  if (bytes.length > size) {
    return padLeft ? bytes.slice(bytes.length - size) : bytes.slice(0, size);
  }
  const padded = new Uint8Array(size);
  if (padLeft) {
    padded.set(bytes, size - bytes.length);
  } else {
    padded.set(bytes, 0);
  }
  return padded;
}

/**
 * Compare two byte arrays for equality
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Encode proof for submission
 */
export function encodeProof(proof: {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
}): Hex {
  // Encode as concatenated G1/G2 points
  // pi_a (64 bytes) + pi_b (128 bytes) + pi_c (64 bytes) = 256 bytes
  const parts: Uint8Array[] = [];

  // pi_a: G1 point (x, y) - 2 x 32 bytes
  parts.push(bigintToBytes(BigInt(proof.pi_a[0]), 32));
  parts.push(bigintToBytes(BigInt(proof.pi_a[1]), 32));

  // pi_b: G2 point (x, y) where each coord is (real, imag) - 4 x 32 bytes
  // Note: G2 in snarkjs is [[x_imag, x_real], [y_imag, y_real]]
  parts.push(bigintToBytes(BigInt(proof.pi_b[0][1]), 32)); // x_real
  parts.push(bigintToBytes(BigInt(proof.pi_b[0][0]), 32)); // x_imag
  parts.push(bigintToBytes(BigInt(proof.pi_b[1][1]), 32)); // y_real
  parts.push(bigintToBytes(BigInt(proof.pi_b[1][0]), 32)); // y_imag

  // pi_c: G1 point (x, y) - 2 x 32 bytes
  parts.push(bigintToBytes(BigInt(proof.pi_c[0]), 32));
  parts.push(bigintToBytes(BigInt(proof.pi_c[1]), 32));

  return bytesToHex(concatBytes(...parts));
}

/**
 * Encode public inputs for submission
 */
export function encodePublicInputs(signals: string[]): Hex {
  const parts = signals.map((s) => bigintToBytes(BigInt(s), 32));
  return bytesToHex(concatBytes(...parts));
}
