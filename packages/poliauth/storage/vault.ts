import type { SavedVaultCredentials, IdentityId } from '../domain/entities.js';
import { mergeVaultCredentials } from '../domain/credentials.js';
import { redactSensitiveErrorText } from '../domain/redaction.js';
import type { EncryptedPayload, VaultMetadata } from '../interfaces/crypto-port.js';
import type { VaultStoragePort, UserVaultStorageFactoryPort, VaultSecretMaterialPort } from '../interfaces/storage-port.js';
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
   * When true, refuse encryption or decryption if no non-empty secret material
   * is supplied via `options.secretMaterial` or `VaultSecretMaterialPort`.
   */
  requireSecretMaterial?: boolean;
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

function normalizeSecretMaterial(secret?: string): string | undefined {
  if (typeof secret !== 'string') {
    return undefined;
  }
  const trimmed = secret.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function formatScopedKeyMaterial(
  domain: string,
  overrideSecret?: string,
  requireSecretMaterial = false
): string {
  const normalized = normalizeSecretMaterial(overrideSecret);
  if (!normalized && requireSecretMaterial) {
    throw new Error(
      `Missing non-empty secret material for AES-256-GCM key derivation (${domain}). Refusing to fall back to the default local secret.`
    );
  }
  const secret = normalized ?? 'poliauth-default-local-secret-v1';
  return `PoliAuth::${domain}::v1::${secret}::AES-256-GCM`;
}

async function deriveAesKey(
  salt: Uint8Array,
  domain: string,
  secretOverride?: string,
  requireSecretMaterial = false
): Promise<CryptoKey> {
  const webCrypto = getWebCrypto();
  const encoder = new TextEncoder();
  const rawMaterial = encoder.encode(
    formatScopedKeyMaterial(domain, secretOverride, requireSecretMaterial)
  );

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

const storageMutationQueues = new WeakMap<VaultStoragePort, Promise<void>>();

async function withStorageMutationLock<T>(
  storage: VaultStoragePort,
  task: () => Promise<T>
): Promise<T> {
  const previous = storageMutationQueues.get(storage) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const chained = previous.then(() => current, () => current);
  storageMutationQueues.set(storage, chained);

  await previous;
  try {
    return await task();
  } finally {
    release();
    if (storageMutationQueues.get(storage) === chained) {
      storageMutationQueues.delete(storage);
    }
  }
}

async function resolveSaltAndMeta(
  storage: VaultStoragePort,
  metaKey: string
): Promise<{ salt: Uint8Array; metaToPersist?: VaultMetadata }> {
  const webCrypto = getWebCrypto();
  const data = await storage.get([metaKey]);
  const existingMeta = data[metaKey] as VaultMetadata | undefined;
  if (existingMeta?.salt && existingMeta.version === 1) {
    return { salt: base64ToBytes(existingMeta.salt) };
  }

  const salt = webCrypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const metaToPersist: VaultMetadata = {
    salt: bytesToBase64(salt),
    version: 1
  };
  return { salt, metaToPersist };
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

function resolveEffectiveSecretMaterial(
  storage: VaultStoragePort,
  options?: VaultCryptoOptions
): { secretMaterial?: string; requireSecretMaterial: boolean } {
  const secretPort = storage as Partial<VaultSecretMaterialPort>;
  const secretMaterial =
    normalizeSecretMaterial(options?.secretMaterial) ??
    normalizeSecretMaterial(secretPort.getSecretMaterial?.());
  const requireSecretMaterial = Boolean(
    options?.requireSecretMaterial || secretPort.requiresSecretMaterial
  );
  if (requireSecretMaterial && !secretMaterial) {
    throw new Error(
      'Missing non-empty secret material for vault operation. Refusing to fall back to the default local secret.'
    );
  }
  return { secretMaterial, requireSecretMaterial };
}

function normalizeCryptoOptions(
  secretOrOptions?: string | VaultCryptoOptions,
  logger?: AuthLoggerPort
): VaultCryptoOptions | undefined {
  if (typeof secretOrOptions === 'string') {
    return { secretMaterial: secretOrOptions, logger };
  }
  if (secretOrOptions) {
    return logger && !secretOrOptions.logger
      ? { ...secretOrOptions, logger }
      : secretOrOptions;
  }
  return logger ? { logger } : undefined;
}

async function encryptJsonValue(
  value: unknown,
  storage: VaultStoragePort,
  payloadKey: string,
  metaKey: string,
  domain: string,
  options?: VaultCryptoOptions
): Promise<void> {
  const webCrypto = getWebCrypto();
  const { secretMaterial, requireSecretMaterial } = resolveEffectiveSecretMaterial(
    storage,
    options
  );
  const { salt, metaToPersist } = await resolveSaltAndMeta(storage, metaKey);
  const iv = webCrypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveAesKey(salt, domain, secretMaterial, requireSecretMaterial);

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

  const itemsToSet: Record<string, unknown> = {
    [payloadKey]: payload
  };
  if (metaToPersist) {
    itemsToSet[metaKey] = metaToPersist;
  }

  await storage.set(itemsToSet);
}

type DecryptJsonResult<T> =
  | { status: 'ok'; value: T }
  | { status: 'empty' }
  | { status: 'corrupt'; reason: string }
  | { status: 'decryption_failed'; reason: string };

async function decryptJsonValueDetailed<T>(
  storage: VaultStoragePort,
  payloadKey: string,
  metaKey: string,
  domain: string,
  options?: VaultCryptoOptions
): Promise<DecryptJsonResult<T>> {
  const webCrypto = getWebCrypto();
  const { secretMaterial, requireSecretMaterial } = resolveEffectiveSecretMaterial(
    storage,
    options
  );
  const data = await storage.get([payloadKey, metaKey]);
  const payload = data[payloadKey] as EncryptedPayload | undefined;
  const meta = data[metaKey] as VaultMetadata | undefined;

  if (payload === undefined) {
    return { status: 'empty' };
  }

  if (
    !payload ||
    typeof payload !== 'object' ||
    payload.version !== 1 ||
    typeof payload.iv !== 'string' ||
    !payload.iv ||
    typeof payload.ciphertext !== 'string' ||
    !payload.ciphertext ||
    !meta ||
    typeof meta !== 'object' ||
    typeof meta.salt !== 'string' ||
    !meta.salt
  ) {
    const reason = 'Corrupted or incomplete encrypted vault envelope.';
    options?.logger?.warn(`Corrupted vault payload (${payloadKey}): ${reason}`);
    return { status: 'corrupt', reason };
  }

  try {
    const salt = base64ToBytes(meta.salt);
    const iv = base64ToBytes(payload.iv);
    const ciphertext = base64ToBytes(payload.ciphertext);
    const key = await deriveAesKey(salt, domain, secretMaterial, requireSecretMaterial);

    const decryptedBuffer = await webCrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      ciphertext as BufferSource
    );

    const decoder = new TextDecoder();
    return {
      status: 'ok',
      value: JSON.parse(decoder.decode(decryptedBuffer)) as T
    };
  } catch (err) {
    const reason = redactSensitiveErrorText(err);
    options?.logger?.warn(`Failed to decrypt vault payload (${payloadKey}): ${reason}`);
    return { status: 'decryption_failed', reason };
  }
}

async function decryptJsonValue<T>(
  storage: VaultStoragePort,
  payloadKey: string,
  metaKey: string,
  domain: string,
  options?: VaultCryptoOptions
): Promise<T | null> {
  const result = await decryptJsonValueDetailed<T>(storage, payloadKey, metaKey, domain, options);
  return result.status === 'ok' ? result.value : null;
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
  return withStorageMutationLock(storage, async () => {
    const existingResult = await decryptJsonValueDetailed<SavedVaultCredentials>(
      storage,
      VAULT_STORAGE_KEY,
      VAULT_META_KEY,
      'VaultKey',
      options
    );
    if (existingResult.status === 'corrupt' || existingResult.status === 'decryption_failed') {
      throw new Error(
        `Refusing to overwrite existing encrypted vault (${VAULT_STORAGE_KEY}): ${existingResult.reason}. Call clearEncryptedCredentials() before saving new credentials.`
      );
    }

    const existing = existingResult.status === 'ok' ? existingResult.value : null;
    const merged = mergeVaultCredentials(existing, creds, Date.now());

    await encryptJsonValue(
      merged,
      storage,
      VAULT_STORAGE_KEY,
      VAULT_META_KEY,
      'VaultKey',
      options
    );

    return merged;
  });
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
  await withStorageMutationLock(storage, async () => {
    await storage.remove([VAULT_STORAGE_KEY, VAULT_META_KEY]);
  });
}

/**
 * Encrypts and stores serialized session state using Web Crypto PBKDF2-HMAC-SHA256 + AES-256-GCM.
 */
export async function saveEncryptedSessionState(
  storage: VaultStoragePort,
  sessionState: unknown,
  secretOrOptions?: string | VaultCryptoOptions
): Promise<void> {
  await withStorageMutationLock(storage, async () => {
    await encryptJsonValue(
      sessionState,
      storage,
      SESSION_STATE_STORAGE_KEY,
      SESSION_STATE_META_KEY,
      'SessionStateKey',
      normalizeCryptoOptions(secretOrOptions)
    );
  });
}

/**
 * Loads and decrypts serialized session state using Web Crypto PBKDF2-HMAC-SHA256 + AES-256-GCM.
 */
export async function loadEncryptedSessionState<T = unknown>(
  storage: VaultStoragePort,
  secretOrOptions?: string | VaultCryptoOptions,
  logger?: AuthLoggerPort
): Promise<T | null> {
  return decryptJsonValue<T>(
    storage,
    SESSION_STATE_STORAGE_KEY,
    SESSION_STATE_META_KEY,
    'SessionStateKey',
    normalizeCryptoOptions(secretOrOptions, logger)
  );
}

/**
 * Removes encrypted session state and metadata from the given storage backend.
 */
export async function clearEncryptedSessionState(storage: VaultStoragePort): Promise<void> {
  await withStorageMutationLock(storage, async () => {
    await storage.remove([SESSION_STATE_STORAGE_KEY, SESSION_STATE_META_KEY]);
  });
}

/**
 * High-level object-oriented wrapper for managing encrypted user credentials
 * and session states in either single-tenant or multi-tenant setups.
 */
export class EncryptedCredentialVault {
  private readonly singleStorage?: VaultStoragePort;
  private readonly userFactory?: UserVaultStorageFactoryPort;
  private readonly cryptoOptions?: VaultCryptoOptions;
  private readonly identityMutationQueues = new Map<string, Promise<void>>();

  constructor(options: {
    storage?: VaultStoragePort;
    userFactory?: UserVaultStorageFactoryPort;
    cryptoOptions?: VaultCryptoOptions;
  } = {}) {
    this.singleStorage = options.storage;
    this.userFactory = options.userFactory;
    this.cryptoOptions = options.cryptoOptions;
  }

  private async withIdentityMutationLock<T>(
    identityId: IdentityId | undefined,
    task: () => Promise<T>
  ): Promise<T> {
    const lockKey = identityId === undefined ? '__single__' : `user:${String(identityId)}`;
    const previous = this.identityMutationQueues.get(lockKey) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    const chained = previous.then(() => current, () => current);
    this.identityMutationQueues.set(lockKey, chained);

    await previous;
    try {
      return await task();
    } finally {
      release();
      if (this.identityMutationQueues.get(lockKey) === chained) {
        this.identityMutationQueues.delete(lockKey);
      }
    }
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
    return this.withIdentityMutationLock(identityId, () => {
      const { storage, cryptoOptions } = this.resolveStorage(identityId, secretOverride);
      return saveEncryptedCredentials(creds, storage, cryptoOptions);
    });
  }

  async loadCredentials(
    identityId?: IdentityId,
    secretOverride?: string
  ): Promise<SavedVaultCredentials | null> {
    const { storage, cryptoOptions } = this.resolveStorage(identityId, secretOverride);
    return loadEncryptedCredentials(storage, cryptoOptions);
  }

  async clearCredentials(identityId?: IdentityId, secretOverride?: string): Promise<void> {
    await this.withIdentityMutationLock(identityId, async () => {
      const { storage } = this.resolveStorage(identityId, secretOverride);
      await clearEncryptedCredentials(storage);
    });
  }

  async saveSessionState<T = unknown>(
    state: T,
    identityId?: IdentityId,
    secretOverride?: string
  ): Promise<void> {
    await this.withIdentityMutationLock(identityId, async () => {
      const { storage, cryptoOptions } = this.resolveStorage(identityId, secretOverride);
      await saveEncryptedSessionState(storage, state, cryptoOptions);
    });
  }

  async loadSessionState<T = unknown>(
    identityId?: IdentityId,
    secretOverride?: string
  ): Promise<T | null> {
    const { storage, cryptoOptions } = this.resolveStorage(identityId, secretOverride);
    return loadEncryptedSessionState<T>(storage, cryptoOptions);
  }

  async clearSessionState(identityId?: IdentityId, secretOverride?: string): Promise<void> {
    await this.withIdentityMutationLock(identityId, async () => {
      const { storage } = this.resolveStorage(identityId, secretOverride);
      await clearEncryptedSessionState(storage);
    });
  }
}
