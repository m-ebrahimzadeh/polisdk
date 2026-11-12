import type { SavedVaultCredentials, IdentityId } from '../domain/entities.js';
import { mergeVaultCredentials } from '../domain/credentials.js';
import type { EncryptedPayload, VaultMetadata } from '../interfaces/crypto-port.js';
import type { VaultStoragePort, UserVaultStorageFactoryPort } from '../interfaces/storage-port.js';
import type { AuthLoggerPort } from '../interfaces/logger-port.js';

export const VAULT_STORAGE_KEY = 'poliauth_credentials_vault_v1';
export const VAULT_META_KEY = 'poliauth_vault_meta_v1';
export const SESSION_STATE_STORAGE_KEY = 'poliauth_session_state_v1';
export const SESSION_STATE_META_KEY = 'poliauth_session_state_meta_v1';

const PBKDF2_ITERATIONS = 100_000;
const KEY_LENGTH_BITS = 256;
const SALT_BYTES = 16;
const IV_BYTES = 12;

export interface VaultCryptoOptions {
  /**
   * Custom master secret material for PBKDF2 key derivation.
   */
  secretMaterial?: string;
  /**
   * Optional logger for diagnostic output on decryption errors.
   */
  logger?: AuthLoggerPort;
}

function getWebCrypto(): Crypto {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  throw new Error('Web Crypto API (globalThis.crypto.subtle) is required by PoliAuth Vault.');
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

function formatScopedKeyMaterial(domain: string, overrideSecret?: string): string {
  const secret =
    overrideSecret && overrideSecret.trim().length > 0
      ? overrideSecret.trim()
      : 'poliauth-default-local-secret-v1';
  return `PoliAuth::${domain}::v1::${secret}::AES-256-GCM`;
}

async function deriveAesKey(
  salt: Uint8Array,
  domain: string,
  secretOverride?: string
): Promise<CryptoKey> {
  const webCrypto = getWebCrypto();
  const encoder = new TextEncoder();
  const rawMaterial = encoder.encode(formatScopedKeyMaterial(domain, secretOverride));

  const baseKey = await webCrypto.subtle.importKey(
    'raw',
    rawMaterial as BufferSource,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return webCrypto.subtle.deriveKey(
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

async function getOrCreateSalt(
  storage: VaultStoragePort,
  metaKey: string
): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  const data = await storage.get([metaKey]);
  const existingMeta = data[metaKey] as VaultMetadata | undefined;
  if (existingMeta?.salt && existingMeta.version === 1) {
    return base64ToBytes(existingMeta.salt);
  }

  const salt = webCrypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const meta: VaultMetadata = {
    salt: bytesToBase64(salt),
    version: 1
  };
  await storage.set({ [metaKey]: meta });
  return salt;
}

/**
 * Resolves a default platform-agnostic storage backend (`localStorage` when available,
 * otherwise an ephemeral in-memory map).
 */
export function getDefaultStorageBackend(): VaultStoragePort {
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

async function encryptJsonValue(
  value: unknown,
  storage: VaultStoragePort,
  payloadKey: string,
  metaKey: string,
  domain: string,
  secretMaterial?: string
): Promise<void> {
  const webCrypto = getWebCrypto();
  const effectiveSecret = secretMaterial ?? storage.getSecretMaterial?.();
  const salt = await getOrCreateSalt(storage, metaKey);
  const iv = webCrypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveAesKey(salt, domain, effectiveSecret);

  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(value));
  const encryptedBuffer = await webCrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    plaintext as BufferSource
  );

  const payload: EncryptedPayload = {
    version: 1,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(encryptedBuffer)),
    updatedAt: Date.now()
  };

  await storage.set({
    [payloadKey]: payload
  });
}

async function decryptJsonValue<T>(
  storage: VaultStoragePort,
  payloadKey: string,
  metaKey: string,
  domain: string,
  options?: VaultCryptoOptions
): Promise<T | null> {
  const webCrypto = getWebCrypto();
  const data = await storage.get([payloadKey, metaKey]);
  const payload = data[payloadKey] as EncryptedPayload | undefined;
  const meta = data[metaKey] as VaultMetadata | undefined;

  if (!payload || payload.version !== 1 || !payload.iv || !payload.ciphertext || !meta?.salt) {
    return null;
  }

  try {
    const effectiveSecret = options?.secretMaterial ?? storage.getSecretMaterial?.();
    const salt = base64ToBytes(meta.salt);
    const iv = base64ToBytes(payload.iv);
    const ciphertext = base64ToBytes(payload.ciphertext);
    const key = await deriveAesKey(salt, domain, effectiveSecret);

    const decryptedBuffer = await webCrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      ciphertext as BufferSource
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decryptedBuffer)) as T;
  } catch (err) {
    options?.logger?.warn(`Failed to decrypt vault payload (${payloadKey})`, err);
    return null;
  }
}

/**
 * Encrypts and persists `SavedVaultCredentials` (merging with any already-stored fields)
 * using Web Crypto PBKDF2-HMAC-SHA256 (100,000 iterations) + AES-256-GCM.
 */
export async function saveEncryptedCredentials(
  creds: Partial<SavedVaultCredentials>,
  storage: VaultStoragePort = getDefaultStorageBackend(),
  options?: VaultCryptoOptions
): Promise<SavedVaultCredentials> {
  const existing = await loadEncryptedCredentials(storage, options);
  const merged = mergeVaultCredentials(existing, creds, Date.now());

  await encryptJsonValue(
    merged,
    storage,
    VAULT_STORAGE_KEY,
    VAULT_META_KEY,
    'VaultKey',
    options?.secretMaterial
  );

  return merged;
}

/**
 * Loads and decrypts `SavedVaultCredentials` from a `VaultStoragePort`.
 * Returns `null` if no credentials are stored or if decryption fails.
 */
export async function loadEncryptedCredentials(
  storage: VaultStoragePort = getDefaultStorageBackend(),
  options?: VaultCryptoOptions
): Promise<SavedVaultCredentials | null> {
  return decryptJsonValue<SavedVaultCredentials>(
    storage,
    VAULT_STORAGE_KEY,
    VAULT_META_KEY,
    'VaultKey',
    options
  );
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
 * Encrypts and stores serialized session state using Web Crypto PBKDF2-HMAC-SHA256 + AES-256-GCM.
 */
export async function saveEncryptedSessionState(
  storage: VaultStoragePort,
  sessionState: unknown,
  secretMaterial?: string
): Promise<void> {
  await encryptJsonValue(
    sessionState,
    storage,
    SESSION_STATE_STORAGE_KEY,
    SESSION_STATE_META_KEY,
    'SessionStateKey',
    secretMaterial
  );
}

/**
 * Loads and decrypts serialized session state using Web Crypto PBKDF2-HMAC-SHA256 + AES-256-GCM.
 */
export async function loadEncryptedSessionState<T = unknown>(
  storage: VaultStoragePort,
  secretMaterial?: string,
  logger?: AuthLoggerPort
): Promise<T | null> {
  return decryptJsonValue<T>(
    storage,
    SESSION_STATE_STORAGE_KEY,
    SESSION_STATE_META_KEY,
    'SessionStateKey',
    { secretMaterial, logger }
  );
}

/**
 * Removes encrypted session state and metadata from the given storage backend.
 */
export async function clearEncryptedSessionState(storage: VaultStoragePort): Promise<void> {
  await storage.remove([SESSION_STATE_STORAGE_KEY, SESSION_STATE_META_KEY]);
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
    return loadEncryptedSessionState<T>(
      storage,
      cryptoOptions?.secretMaterial,
      cryptoOptions?.logger
    );
  }

  async clearSessionState(identityId?: IdentityId, secretOverride?: string): Promise<void> {
    const { storage } = this.resolveStorage(identityId, secretOverride);
    await clearEncryptedSessionState(storage);
  }
}
