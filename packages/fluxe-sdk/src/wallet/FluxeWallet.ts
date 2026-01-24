/**
 * FLUXE Wallet - Privacy-preserving wallet for FLUXE L2
 *
 * Manages spending keys, viewing keys, and note encryption.
 */

import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { get, set, del } from 'idb-keyval';
import { poseidonHash, computeNullifier, computeNoteCommitment, fieldToHex, hexToField } from '../utils/poseidon';
import { bytesToHex, hexToBytes, bytesToBigint, bigintToBytes } from '../utils/encoding';
import type { Note, EncryptedNote, WalletKeys, EncryptedKeystore, Hex } from '../types';

const WALLET_STORAGE_KEY = 'fluxe-wallet';
const PBKDF2_ITERATIONS = 100000;

export class FluxeWallet {
  private spendingKey: bigint;
  private viewingKey: bigint;
  private _address: Hex;
  private notes: Map<string, Note> = new Map();

  private constructor(spendingKey: bigint) {
    this.spendingKey = spendingKey;
    // Viewing key = hash(spending_key, "viewing")
    this.viewingKey = poseidonHash([spendingKey, BigInt('0x766965776B6579')]); // "viewkey" as hex
    // Address = hash(viewing_key)
    this._address = fieldToHex(poseidonHash([this.viewingKey]));
  }

  // ============ Factory Methods ============

  /**
   * Create a new wallet with random keys
   */
  static async create(password: string): Promise<FluxeWallet> {
    const mnemonic = generateMnemonic(wordlist, 256);
    return FluxeWallet.fromMnemonic(mnemonic, password);
  }

  /**
   * Create wallet from mnemonic
   */
  static async fromMnemonic(mnemonic: string, password: string): Promise<FluxeWallet> {
    if (!validateMnemonic(mnemonic, wordlist)) {
      throw new Error('Invalid mnemonic');
    }

    const seed = mnemonicToSeedSync(mnemonic, '');
    // Derive spending key from seed using FLUXE path
    const path = "m/44'/989278'/0'/0/0"; // 989278 = FLUXE chain ID
    const spendingKey = FluxeWallet.deriveKeyFromSeed(seed, path);

    const wallet = new FluxeWallet(spendingKey);

    // Store encrypted keystore
    await wallet.saveToStorage(password);

    return wallet;
  }

  /**
   * Load wallet from encrypted storage
   */
  static async load(password: string): Promise<FluxeWallet | null> {
    const keystoreJson = await get<string>(WALLET_STORAGE_KEY);
    if (!keystoreJson) {
      return null;
    }

    const keystore: EncryptedKeystore = JSON.parse(keystoreJson);
    const spendingKey = await FluxeWallet.decryptKeystore(keystore, password);

    return new FluxeWallet(spendingKey);
  }

  /**
   * Import wallet from private key
   */
  static fromPrivateKey(privateKey: Hex): FluxeWallet {
    const spendingKey = hexToField(privateKey);
    return new FluxeWallet(spendingKey);
  }

  // ============ Key Derivation ============

  private static deriveKeyFromSeed(seed: Uint8Array, _path: string): bigint {
    // Simplified key derivation - in production use proper BIP32
    const hash = sha256(seed);
    return bytesToBigint(hash) % (2n ** 251n); // Fit in BN254 scalar field
  }

  // ============ Storage ============

  private async saveToStorage(password: string): Promise<void> {
    const keystore = await this.encryptKeystore(password);
    await set(WALLET_STORAGE_KEY, JSON.stringify(keystore));
  }

  private async encryptKeystore(password: string): Promise<EncryptedKeystore> {
    const salt = randomBytes(32);
    const iv = randomBytes(16);

    // Derive encryption key using PBKDF2
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    const aesKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt.buffer as ArrayBuffer,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    // Encrypt spending key
    const plaintext = bigintToBytes(this.spendingKey, 32);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      aesKey,
      plaintext.buffer as ArrayBuffer
    );

    // Compute MAC
    const mac = sha256(new Uint8Array([...Array.from(new Uint8Array(ciphertext)), ...iv]));

    return {
      version: 1,
      address: this._address,
      crypto: {
        cipher: 'aes-256-gcm',
        ciphertext: bytesToHex(new Uint8Array(ciphertext)),
        cipherparams: { iv: bytesToHex(iv) },
        kdf: 'pbkdf2',
        kdfparams: {
          c: PBKDF2_ITERATIONS,
          dklen: 32,
          prf: 'hmac-sha256',
          salt: bytesToHex(salt),
        },
        mac: bytesToHex(mac),
      },
    };
  }

  private static async decryptKeystore(keystore: EncryptedKeystore, password: string): Promise<bigint> {
    const salt = hexToBytes(keystore.crypto.kdfparams.salt as string);
    const iv = hexToBytes(keystore.crypto.cipherparams.iv);
    const ciphertext = hexToBytes(keystore.crypto.ciphertext);

    // Derive decryption key
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    const aesKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt.buffer as ArrayBuffer,
        iterations: keystore.crypto.kdfparams.c as number,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Decrypt
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
        aesKey,
        ciphertext.buffer as ArrayBuffer
      );

      return bytesToBigint(new Uint8Array(plaintext));
    } catch {
      throw new Error('Invalid password');
    }
  }

  /**
   * Delete wallet from storage
   */
  static async deleteFromStorage(): Promise<void> {
    await del(WALLET_STORAGE_KEY);
  }

  // ============ Key Access ============

  get address(): Hex {
    return this._address;
  }

  getViewingKey(): Hex {
    return fieldToHex(this.viewingKey);
  }

  getSpendingKey(): Hex {
    return fieldToHex(this.spendingKey);
  }

  // ============ Note Management ============

  /**
   * Compute nullifier for a note
   */
  computeNullifier(noteCommitment: Hex): Hex {
    const cm = hexToField(noteCommitment);
    const nullifier = computeNullifier(this.spendingKey, cm);
    return fieldToHex(nullifier);
  }

  /**
   * Create a note commitment
   */
  createNoteCommitment(
    assetType: number,
    valueCommitment: bigint,
    psi: bigint,
    chainHint: number,
    poolId: number
  ): Hex {
    const ownerAddr = poseidonHash([this.viewingKey]);
    const commitment = computeNoteCommitment(
      BigInt(assetType),
      valueCommitment,
      ownerAddr,
      psi,
      BigInt(chainHint),
      BigInt(poolId)
    );
    return fieldToHex(commitment);
  }

  /**
   * Add a note to the wallet
   */
  addNote(note: Note): void {
    this.notes.set(note.commitment, note);
  }

  /**
   * Get all notes
   */
  getNotes(): Note[] {
    return Array.from(this.notes.values());
  }

  /**
   * Get notes for a specific asset
   */
  getNotesByAsset(assetType: number): Note[] {
    return this.getNotes().filter((n) => n.assetType === assetType);
  }

  /**
   * Get total balance for an asset
   */
  getBalance(assetType: number): bigint {
    return this.getNotesByAsset(assetType).reduce((sum, note) => sum + note.amount, 0n);
  }

  /**
   * Remove a note (after spending)
   */
  removeNote(commitment: Hex): void {
    this.notes.delete(commitment);
  }

  // ============ Encryption ============

  /**
   * Encrypt a note for the recipient
   */
  encryptNote(_note: Note, _recipientViewingKey: Hex): EncryptedNote {
    // Simplified - in production use proper ECDH + ChaCha20Poly1305
    const ephemeralKey = randomBytes(32);
    const nonce = randomBytes(12);

    // Placeholder encryption
    return {
      ciphertext: bytesToHex(new Uint8Array(128)),
      ephemeralPubKey: bytesToHex(ephemeralKey),
      nonce: bytesToHex(nonce),
    };
  }

  /**
   * Try to decrypt a note
   */
  tryDecryptNote(_encrypted: EncryptedNote): Note | null {
    // Simplified - in production use proper decryption
    return null;
  }
}
