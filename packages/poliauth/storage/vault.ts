import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import type { SavedVaultCredentials, IdentityId } from '../domain/entities.js';
import { mergeVaultCredentials } from '../domain/credentials.js';
import type { EncryptedPayload, VaultMetadata } from '../interfaces/crypto-port.js';
import type { VaultStoragePort, UserVaultStorageFactoryPort } from '../interfaces/storage-port.js';
import type { AuthLoggerPort } from '../interfaces/logger-port.js';

export const VAULT_STORAGE_KEY = 'polirecord_secure_vault_v1';
export const VAULT_META_KEY = 'polirecord_vault_meta_v1';
export const PLAYWRIGHT_STORAGE_STATE_KEY = 'polirecord_playwright_storage_state_v1';

const PBKDF2_ITERATIONS = 100_000;
const KEY_LENGTH_BITS = 256;
const SALT_BYTES = 16;
const IV_BYTES = 12;

export interface VaultCryptoOptions {
  /**
   * Optional custom master secret material for key derivation.
   */
  secretMaterial?: string;
  /**
   * Optional logger for diagnostic output on decryption errors.
   */
  logger?: AuthLoggerPort;
}

/**
 * Legacy Node `crypto` encrypted payload format used by `polirecord` for Playwright `storageState`.
 * Retained for 100% backward compatibility with existing `user_vault_kv` rows.
 */
export interface LegacyNodeEncryptedPayload {
  iv: string;
  authTag: string;
  ciphertext: string;
  updatedAt: number;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function normalizeKeyArray(keys: string | string[]): string[] {
  return Array.isArray(keys) ? keys : [keys];
}

function getExtensionKeyMaterial(overrideSecret?: string): string {
  if (overrideSecret && overrideSecret.trim().length > 0) {
    if (overrideSecret.startsWith('PoliRecord::VaultKey::v1::')) {
      return overrideSecret;
    }
    return `PoliRecord::VaultKey::v1::${overrideSecret}::AES-256-GCM`;
  }
  const runtimeId =
    typeof chrome !== 'undefined' && chrome?.runtime?.id
      ? chrome.runtime.id
      : 'polirecord-local-dev-vault-key';
  return `PoliRecord::VaultKey::v1::${runtimeId}::AES-256-GCM`;
}

async function deriveAesKey(salt: Uint8Array, secretOverride?: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const rawMaterial = encoder.encode(getExtensionKeyMaterial(secretOverride));

  const baseKey = await crypto.subtle.importKey(
    'raw',
    rawMaterial as BufferSource,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: KEY_LENGTH_BITS
    },
    false,
    ['encrypt', 'decrypt']
  );
}

async function getOrCreateSalt(storage: VaultStoragePort): Promise<Uint8Array> {
  const data = await storage.get([VAULT_META_KEY]);
  const existingMeta = data[VAULT_META_KEY] as VaultMetadata | undefined;
  if (existingMeta?.salt && existingMeta.version === 1) {
    return base64ToBytes(existingMeta.salt);
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const meta: VaultMetadata = {
    salt: bytesToBase64(salt),
    version: 1
  };
  await storage.set({ [VAULT_META_KEY]: meta });
  return salt;
}

/**
 * Resolves the default storage backend for current execution context:
 * - `chrome.storage.local` when running inside a Chromium extension
 * - `localStorage` fallback for web/JSDOM contexts
 * - ephemeral in-memory map fallback for headless/Node environments
 */
export function getDefaultStorageBackend(): VaultStoragePort {
  if (typeof chrome !== 'undefined' && chrome?.storage?.local) {
    return {
      async get(keys: string | string[]) {
        return await chrome.storage.local.get(normalizeKeyArray(keys));
      },
      async set(items: Record<string, unknown>) {
        await chrome.storage.local.set(items);
      },
      async remove(keys: string | string[]) {
        await chrome.storage.local.remove(normalizeKeyArray(keys));
      }
    };
  }

  const memoryFallback = new Map<string, unknown>();
  return {
    async get(keys: string | string[]) {
      const result: Record<string, unknown> = {};
      for (const k of normalizeKeyArray(keys)) {
        if (typeof localStorage !== 'undefined') {
          const raw = localStorage.getItem(k);
          if (raw !== null) {
            try {
              result[k] = JSON.parse(raw);
            } catch {
              result[k] = raw;
            }
          }
        } else if (memoryFallback.has(k)) {
          result[k] = memoryFallback.get(k);
        }
      }
      return result;
    },
    async set(items: Record<string, unknown>) {
      for (const [k, v] of Object.entries(items)) {
        if (typeof localStorage !== 'undefined') {
          localStorage.setItem(k, JSON.stringify(v));
        } else {
          memoryFallback.set(k, v);
        }
      }
    },
    async remove(keys: string | string[]) {
      for (const k of normalizeKeyArray(keys)) {
        if (typeof localStorage !== 'undefined') {
          localStorage.removeItem(k);
        } else {
          memoryFallback.delete(k);
        }
      }
    }
  };
}

/**
 * Encrypts and persists `SavedVaultCredentials` (merging with any already-stored fields)
 * using PBKDF2-HMAC-SHA256 (100,000 iterations) + AES-256-GCM.
 */
export async function saveEncryptedCredentials(
  creds: Partial<SavedVaultCredentials>,
  storage: VaultStoragePort = getDefaultStorageBackend(),
  options?: VaultCryptoOptions
): Promise<SavedVaultCredentials> {
  const existing = await loadEncryptedCredentials(storage, options);
  const merged = mergeVaultCredentials(existing, creds, Date.now());

  const effectiveSecret = options?.secretMaterial ?? storage.getSecretMaterial?.();
  const salt = await getOrCreateSalt(storage);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveAesKey(salt, effectiveSecret);

  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(merged));
  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    plaintext as BufferSource
  );

  const payload: EncryptedPayload = {
    version: 1,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(encryptedBuffer)),
    updatedAt: merged.updatedAt
  };

  await storage.set({
    [VAULT_STORAGE_KEY]: payload
  });

  return merged;
}

/**
 * Loads and decrypts `SavedVaultCredentials` from a `VaultStoragePort`.
 * Returns `null` if no credentials are stored or if decryption fails (e.g., rotated key).
 */
export async function loadEncryptedCredentials(
  storage: VaultStoragePort = getDefaultStorageBackend(),
  options?: VaultCryptoOptions
): Promise<SavedVaultCredentials | null> {
  const data = await storage.get([VAULT_STORAGE_KEY, VAULT_META_KEY]);
  const payload = data[VAULT_STORAGE_KEY] as EncryptedPayload | undefined;
  const meta = data[VAULT_META_KEY] as VaultMetadata | undefined;

  if (!payload || payload.version !== 1 || !payload.iv || !payload.ciphertext || !meta?.salt) {
    return null;
  }

  try {
    const effectiveSecret = options?.secretMaterial ?? storage.getSecretMaterial?.();
    const salt = base64ToBytes(meta.salt);
    const iv = base64ToBytes(payload.iv);
    const ciphertext = base64ToBytes(payload.ciphertext);
    const key = await deriveAesKey(salt, effectiveSecret);

    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      ciphertext as BufferSource
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decryptedBuffer)) as SavedVaultCredentials;
  } catch (err) {
    options?.logger?.warn('Failed to decrypt saved credentials vault', err);
    return null;
  }
}

/**
 * Removes encrypted credentials and metadata from the given storage backend.
 */
export async function clearEncryptedCredentials(
  storage: VaultStoragePort = getDefaultStorageBackend()
): Promise<void> {
  await storage.remove([VAULT_STORAGE_KEY, VAULT_META_KEY]);
}

/**
 * Encrypts and stores serialized browser session state (e.g., Playwright `storageState`)
 * using AES-256-GCM derived from `secretMaterial`.
 */
export async function saveEncryptedSessionState(
  storage: VaultStoragePort,
  storageState: unknown,
  secretMaterial?: string
): Promise<void> {
  const effectiveSecret =
    secretMaterial ?? storage.getSecretMaterial?.() ?? getExtensionKeyMaterial();
  const key = createHash('sha256').update(`PoliRecord::StorageState::${effectiveSecret}`).digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(storageState), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const payload: LegacyNodeEncryptedPayload = {
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
    updatedAt: Date.now()
  };

  await storage.set({
    [PLAYWRIGHT_STORAGE_STATE_KEY]: payload
  });
}

/**
 * Loads and decrypts serialized browser session state (e.g., Playwright `storageState`).
 */
export async function loadEncryptedSessionState<T = unknown>(
  storage: VaultStoragePort,
  secretMaterial?: string
): Promise<T | null> {
  const data = await storage.get([PLAYWRIGHT_STORAGE_STATE_KEY]);
  const raw = data[PLAYWRIGHT_STORAGE_STATE_KEY] as
    | LegacyNodeEncryptedPayload
    | EncryptedPayload
    | undefined;

  if (!raw) {
    return null;
  }

  const effectiveSecret =
    secretMaterial ?? storage.getSecretMaterial?.() ?? getExtensionKeyMaterial();

  try {
    if ('authTag' in raw && raw.iv && raw.authTag && raw.ciphertext) {
      const key = createHash('sha256')
        .update(`PoliRecord::StorageState::${effectiveSecret}`)
        .digest();
      const iv = Buffer.from(raw.iv, 'base64');
      const authTag = Buffer.from(raw.authTag, 'base64');
      const ciphertext = Buffer.from(raw.ciphertext, 'base64');

      const decipher = createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return JSON.parse(decrypted.toString('utf8')) as T;
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Removes encrypted browser session state from the given storage backend.
 */
export async function clearEncryptedSessionState(storage: VaultStoragePort): Promise<void> {
  await storage.remove([PLAYWRIGHT_STORAGE_STATE_KEY]);
}

/**
 * High-level object-oriented wrapper for managing encrypted user credentials
 * and session states in either single-tenant or multi-tenant setups.
 */
export class EncryptedCredentialVault {
  private readonly singleStorage?: VaultStoragePort;
  private readonly userFactory?: UserVaultStorageFactoryPort;
  private readonly cryptoOptions?: VaultCryptoOptions;

  constructor(options: {
    storage?: VaultStoragePort;
    userFactory?: UserVaultStorageFactoryPort;
    cryptoOptions?: VaultCryptoOptions;
  } = {}) {
    this.singleStorage = options.storage;
    this.userFactory = options.userFactory;
    this.cryptoOptions = options.cryptoOptions;
  }

  private resolveStorage(identityId?: IdentityId, secretOverride?: string): {
    storage: VaultStoragePort;
    cryptoOptions?: VaultCryptoOptions;
  } {
    const mergedOptions: VaultCryptoOptions | undefined = secretOverride
      ? { ...this.cryptoOptions, secretMaterial: secretOverride }
      : this.cryptoOptions;

    if (identityId !== undefined && this.userFactory) {
      return {
        storage: this.userFactory.createForUser(identityId),
        cryptoOptions: mergedOptions
      };
    }

    return {
      storage: this.singleStorage ?? getDefaultStorageBackend(),
      cryptoOptions: mergedOptions
    };
  }

  async saveCredentials(
    creds: Partial<SavedVaultCredentials>,
    identityId?: IdentityId,
    secretOverride?: string
  ): Promise<SavedVaultCredentials> {
    const { storage, cryptoOptions } = this.resolveStorage(identityId, secretOverride);
    return saveEncryptedCredentials(creds, storage, cryptoOptions);
  }

  async loadCredentials(
    identityId?: IdentityId,
    secretOverride?: string
  ): Promise<SavedVaultCredentials | null> {
    const { storage, cryptoOptions } = this.resolveStorage(identityId, secretOverride);
    return loadEncryptedCredentials(storage, cryptoOptions);
  }

  async clearCredentials(identityId?: IdentityId, secretOverride?: string): Promise<void> {
    const { storage } = this.resolveStorage(identityId, secretOverride);
    await clearEncryptedCredentials(storage);
  }

  async saveSessionState<T = unknown>(
    state: T,
    identityId?: IdentityId,
    secretOverride?: string
  ): Promise<void> {
    const { storage, cryptoOptions } = this.resolveStorage(identityId, secretOverride);
    await saveEncryptedSessionState(storage, state, cryptoOptions?.secretMaterial);
  }

  async loadSessionState<T = unknown>(
    identityId?: IdentityId,
    secretOverride?: string
  ): Promise<T | null> {
    const { storage, cryptoOptions } = this.resolveStorage(identityId, secretOverride);
    return loadEncryptedSessionState<T>(storage, cryptoOptions?.secretMaterial);
  }

  async clearSessionState(identityId?: IdentityId, secretOverride?: string): Promise<void> {
    const { storage } = this.resolveStorage(identityId, secretOverride);
    await clearEncryptedSessionState(storage);
  }
}
