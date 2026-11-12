/**
 * @module @polisdk/poliauth/interfaces/crypto-port
 * Cryptographic and TOTP Generator Ports.
 */

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

export interface TotpOptions {
  /** Timestamp in milliseconds. Defaults to Date.now(). */
  timestampMs?: number;
  /** Time step in seconds. Default 30. */
  timeStepSeconds?: number;
  /** Number of OTP digits. Default 6. */
  digits?: number;
}

export interface StableTotpOptions extends TotpOptions {
  /**
   * Minimum remaining validity window in seconds before generating a code.
   * If the current window has `<= minRemainingSeconds` left, `generateStable`
   * waits for the next time step so the code never expires mid-request.
   * Default: 2 seconds.
   */
  minRemainingSeconds?: number;
}

/**
 * Port for RFC 6238 / RFC 4226 TOTP generation and Base32 validation.
 */
export interface TotpGeneratorPort {
  cleanSecret(input: string): string;
  isValidSecret(input: string): boolean;
  decodeBase32(base32Str: string): Uint8Array;
  generate(secret: string, options?: TotpOptions): Promise<string>;
  generateStable(
    secret: string,
    options?: StableTotpOptions
  ): Promise<{ code: string; remainingSeconds: number; waitedMs: number }>;
  getRemainingSeconds(timestampMs?: number, timeStepSeconds?: number): number;
}
