import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import type { AuthLoggerPort } from '../interfaces/logger-port.js';

export interface MasterKeyOptions {
  /**
   * Filename used to store the auto-generated master key inside `dataDir`.
   * Defaults to `.vault_master_key` (compatible with `polirecord`).
   */
  keyFileName?: string;
  /**
   * Minimum required character length for an explicitly configured master key.
   * Defaults to `32`.
   */
  minKeyLength?: number;
  /**
   * Optional logger for diagnostic warnings when auto-generating a local key.
   */
  logger?: AuthLoggerPort;
}

/**
 * Resolves the master encryption key for server/bot credential vaults:
 * 1. If `envKey` is provided and has at least `minKeyLength` (32) characters, returns it.
 * 2. Otherwise checks `<dataDir>/.vault_master_key`; if present and valid, returns it.
 * 3. Otherwise generates a cryptographically random 32-byte (64-hex-char) key,
 *    persists it to `<dataDir>/.vault_master_key` with `0o600` permissions, and returns it.
 */
export function resolveMasterEncryptionKey(
  envKey: string | undefined,
  dataDir: string,
  options: MasterKeyOptions = {}
): string {
  const minKeyLength = options.minKeyLength ?? 32;
  const keyFileName = options.keyFileName ?? '.vault_master_key';

  if (envKey && envKey.trim().length > 0) {
    const trimmed = envKey.trim();
    if (trimmed.length < minKeyLength) {
      throw new Error(`MASTER_ENCRYPTION_KEY must be at least ${minKeyLength} characters long.`);
    }
    return trimmed;
  }

  fs.mkdirSync(dataDir, { recursive: true });
  const keyFilePath = path.join(dataDir, keyFileName);
  if (fs.existsSync(keyFilePath)) {
    const existing = fs.readFileSync(keyFilePath, 'utf8').trim();
    if (existing.length >= minKeyLength) {
      return existing;
    }
  }

  const generated = randomBytes(32).toString('hex');
  fs.writeFileSync(keyFilePath, `${generated}\n`, { encoding: 'utf8', mode: 0o600 });
  options.logger?.warn(
    `MASTER_ENCRYPTION_KEY was not set; generated persistent local master key at ${keyFilePath}. Set MASTER_ENCRYPTION_KEY in production.`
  );
  return generated;
}
