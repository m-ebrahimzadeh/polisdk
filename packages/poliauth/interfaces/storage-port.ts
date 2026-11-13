/**
 * @module @polisdk/poliauth/interfaces/storage-port
 * Segregated Storage, Vault, Session State, and User Identity Persistence Ports.
 */

import type {
  IdentityId,
  LoginFlowStatus,
  UserIdentity,
  UserIdentityPatch
} from '../domain/entities.js';
import type { MaybePromise } from './maybe-promise.js';

/**
 * Low-level key-value storage port used by the AES-256-GCM Encrypted Vault.
 *
 * Pure persistence: implementations know nothing about keys or cryptography.
 */
export interface VaultStoragePort {
  get(keys: string | string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

/**
 * Optional role interface supplying custom secret material for PBKDF2 key derivation
 * (e.g. a server master key fingerprint combined with a tenant/user identifier).
 *
 * Storage adapters that are also scoped key holders implement both
 * `VaultStoragePort` and `VaultSecretMaterialPort`.
 */
export interface VaultSecretMaterialPort {
  getSecretMaterial(): string | undefined;
  readonly requiresSecretMaterial?: boolean;
}

/**
 * Abstract factory port that creates a user-scoped `VaultStoragePort`.
 */
export interface UserVaultStorageFactoryPort {
  createForUser(userId: IdentityId): VaultStoragePort;
}

/**
 * Port for persisting and restoring encrypted browser session state
 * (such as serialized cookies and localStorage origins).
 */
export interface SessionStateStorePort<TState = unknown> {
  saveSessionState(userId: IdentityId, state: TState): Promise<void>;
  loadSessionState(userId: IdentityId): Promise<TState | null>;
  clearSessionState(userId: IdentityId): Promise<void>;
}

/**
 * Defaults applied when provisioning a user identity for the first time.
 */
export interface UserIdentityDefaults {
  username?: string | null;
  displayName?: string | null;
  roles?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Idempotent user provisioning (used by auth middleware on every authorized request).
 */
export interface UserIdentityProvisionerPort {
  ensureUser(userId: IdentityId, defaults?: UserIdentityDefaults): MaybePromise<UserIdentity>;
}

/**
 * Read-side user identity queries.
 */
export interface UserIdentityReaderPort {
  getUser(userId: IdentityId): MaybePromise<UserIdentity | null>;
  listUsers(): MaybePromise<UserIdentity[]>;
}

/**
 * Write-side user identity commands.
 */
export interface UserIdentityWriterPort {
  updateUser(userId: IdentityId, patch: UserIdentityPatch): MaybePromise<UserIdentity>;
  updateLoginStatus(
    userId: IdentityId,
    status: LoginFlowStatus,
    error?: string | null
  ): MaybePromise<UserIdentity>;
  deleteUser(userId: IdentityId): MaybePromise<boolean>;
}

/**
 * Full repository contract implemented by persistence adapters
 * (`InMemoryUserIdentityRepository`, `PoliAuthSqliteDatabase`, ...).
 */
export interface UserIdentityRepositoryPort
  extends UserIdentityProvisionerPort,
    UserIdentityReaderPort,
    UserIdentityWriterPort {}
