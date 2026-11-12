/**
 * @module @polisdk/poliauth/interfaces/crypto-port
 * Cryptographic and TOTP Generator Ports.
 */

import type {
  TotpOptions,
  StableTotpOptions,
  StableTotpResult,
  TotpGeneratorPort
} from '../domain/totp.js';

export type {
  TotpOptions,
  StableTotpOptions,
  StableTotpResult,
  TotpGeneratorPort
};

export interface EncryptedPayload {
  version: number;
  iv: string; // Base64 (12-byte IV)
  ciphertext: string; // Base64 (Web Crypto AES-GCM ciphertext + 128-bit auth tag)
  updatedAt: number;
}

export interface VaultMetadata {
  salt: string; // Base64 (16-byte random salt)
  version: number;
}
