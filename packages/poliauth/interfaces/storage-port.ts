/**
 * @module @polisdk/poliauth/interfaces/storage-port
 * Storage, Vault, Session State, and User Identity Persistence Ports.
 */

import type {
  IdentityId,
  LoginFlowStatus,
  UserIdentity,
  UserIdentityPatch
} from '../domain/entities';

/**
 * Low-level key-value storage port used by the AES-256-GCM Encrypted Vault.
 * Backward-compatible with `StorageBackend` in PoliRecord (`src/shared/vault.ts`).
 */
export interface VaultStoragePort {
  get(keys: string | string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
  /**
   * Optional custom secret material for PBKDF2 key derivation
   * (e.g., server master key + tenant/user identifier).
   */
  getSecretMaterial?(): string | undefined;
}

/**
 * Backward-compatible alias for `VaultStoragePort`.
 */
export type StorageBackend = VaultStoragePort;

/**
 * Factory port that creates a user-scoped `VaultStoragePort`.
 */
export interface UserVaultStorageFactoryPort {
  createForUser(userId: IdentityId): VaultStoragePort;
}

/**
 * Port for persisting and restoring encrypted browser session state
 * (such as Playwright `storageState` cookies and localStorage origins).
 */
export interface SessionStateStorePort<TState = unknown> {
  saveSessionState(userId: IdentityId, state: TState): Promise<void>;
  loadSessionState<T extends TState = TState>(userId: IdentityId): Promise<T | null>;
  clearSessionState(userId: IdentityId): Promise<void>;
}

/**
 * Repository port for managing user identities and authentication state.
 * Cleanly decoupled from application-specific tables (queues, caches, etc.).
 */
export interface UserIdentityRepositoryPort {
  ensureUser(
    userId: IdentityId,
    defaults?: {
      username?: string | null;
      displayName?: string | null;
      roles?: string[];
      metadata?: Record<string, unknown>;
    }
  ): Promise<UserIdentity> | UserIdentity;

  getUser(userId: IdentityId): Promise<UserIdentity | null> | UserIdentity | null;

  updateUser(
    userId: IdentityId,
    patch: UserIdentityPatch
  ): Promise<UserIdentity> | UserIdentity;

  updateLoginStatus(
    userId: IdentityId,
    status: LoginFlowStatus,
    error?: string | null
  ): Promise<UserIdentity> | UserIdentity;

  listUsers(): Promise<UserIdentity[]> | UserIdentity[];

  deleteUser(userId: IdentityId): Promise<boolean> | boolean;
}
