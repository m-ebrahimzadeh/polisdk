import {
  type IdentityId,
  type LoginFlowStatus,
  normalizeIdentityId,
  type UserIdentity,
  type UserIdentityPatch
} from '../domain/entities.js';
import type {
  VaultStoragePort,
  UserVaultStorageFactoryPort,
  SessionStateStorePort,
  UserIdentityRepositoryPort
} from '../interfaces/storage-port.js';
import {
  saveEncryptedSessionState,
  loadEncryptedSessionState,
  clearEncryptedSessionState
} from './vault.js';

/**
 * In-memory `VaultStoragePort` implementation suitable for unit tests,
 * ephemeral CLI sessions, or single-tenant in-memory execution.
 */
export class InMemoryVaultStorage implements VaultStoragePort {
  private readonly store = new Map<string, unknown>();
  private readonly secretMaterial?: string;

  constructor(secretMaterial?: string) {
    this.secretMaterial = secretMaterial;
  }

  getSecretMaterial(): string | undefined {
    return this.secretMaterial;
  }

  async get(keys: string | string[]): Promise<Record<string, unknown>> {
    const keyList = Array.isArray(keys) ? keys : [keys];
    const result: Record<string, unknown> = {};
    for (const key of keyList) {
      if (this.store.has(key)) {
        result[key] = structuredClone(this.store.get(key));
      }
    }
    return result;
  }

  async set(items: Record<string, unknown>): Promise<void> {
    for (const [key, val] of Object.entries(items)) {
      this.store.set(key, structuredClone(val));
    }
  }

  async remove(keys: string | string[]): Promise<void> {
    const keyList = Array.isArray(keys) ? keys : [keys];
    for (const key of keyList) {
      this.store.delete(key);
    }
  }

  clearAll(): void {
    this.store.clear();
  }
}

/**
 * Multi-tenant in-memory `UserVaultStorageFactoryPort` isolating each `IdentityId`
 * into its own `InMemoryVaultStorage` namespace.
 */
export class InMemoryUserVaultStorageFactory implements UserVaultStorageFactoryPort {
  private readonly perUserStores = new Map<string, InMemoryVaultStorage>();
  private readonly baseSecret: string;

  constructor(baseSecret = 'poliauth-in-memory-master-key-v1') {
    this.baseSecret = baseSecret;
  }

  createForUser(userId: IdentityId): VaultStoragePort {
    const key = normalizeIdentityId(userId);
    let store = this.perUserStores.get(key);
    if (!store) {
      store = new InMemoryVaultStorage(`${this.baseSecret}::user::${key}`);
      this.perUserStores.set(key, store);
    }
    return store;
  }
}

/**
 * In-memory `SessionStateStorePort` for persisting serialized browser session states
 * (encrypted via `InMemoryUserVaultStorageFactory`).
 */
export class InMemorySessionStateStore<TState = unknown> implements SessionStateStorePort<TState> {
  private readonly factory: UserVaultStorageFactoryPort;
  private readonly secretMaterial: string;

  constructor(
    factory: UserVaultStorageFactoryPort = new InMemoryUserVaultStorageFactory(),
    secretMaterial = 'poliauth-in-memory-session-secret-key-v1'
  ) {
    this.factory = factory;
    this.secretMaterial = secretMaterial;
  }

  async loadSessionState<T extends TState = TState>(userId: IdentityId): Promise<T | null> {
    const storage = this.factory.createForUser(userId);
    return loadEncryptedSessionState<T>(
      storage,
      `${this.secretMaterial}::${normalizeIdentityId(userId)}`
    );
  }

  async saveSessionState(userId: IdentityId, state: TState): Promise<void> {
    const storage = this.factory.createForUser(userId);
    await saveEncryptedSessionState(
      storage,
      state,
      `${this.secretMaterial}::${normalizeIdentityId(userId)}`
    );
  }

  async clearSessionState(userId: IdentityId): Promise<void> {
    const storage = this.factory.createForUser(userId);
    await clearEncryptedSessionState(storage);
  }
}

/**
 * In-memory `UserIdentityRepositoryPort` for user profile and auth status management.
 */
export class InMemoryUserIdentityRepository implements UserIdentityRepositoryPort {
  private readonly users = new Map<string, UserIdentity>();

  ensureUser(
    userId: IdentityId,
    defaults?: {
      username?: string | null;
      displayName?: string | null;
      roles?: string[];
      metadata?: Record<string, unknown>;
    }
  ): UserIdentity {
    const key = normalizeIdentityId(userId);
    const now = Date.now();
    const existing = this.users.get(key);

    if (existing) {
      const updated: UserIdentity = {
        ...existing,
        username: defaults?.username !== undefined ? defaults.username : existing.username,
        displayName:
          defaults?.displayName !== undefined ? defaults.displayName : existing.displayName,
        updatedAt: now
      };
      this.users.set(key, updated);
      return structuredClone(updated);
    }

    const created: UserIdentity = {
      userId,
      username: defaults?.username ?? null,
      displayName: defaults?.displayName ?? null,
      personCode: '',
      polimiEmail: '',
      loginStatus: 'idle',
      loginError: null,
      roles: defaults?.roles ? [...defaults.roles] : [],
      metadata: defaults?.metadata ? { ...defaults.metadata } : {},
      createdAt: now,
      updatedAt: now
    };
    this.users.set(key, created);
    return structuredClone(created);
  }

  getUser(userId: IdentityId): UserIdentity | null {
    const found = this.users.get(normalizeIdentityId(userId));
    return found ? structuredClone(found) : null;
  }

  updateUser(userId: IdentityId, patch: UserIdentityPatch): UserIdentity {
    const key = normalizeIdentityId(userId);
    const existing = this.users.get(key) ?? this.ensureUser(userId);
    const updated: UserIdentity = {
      ...existing,
      username: patch.username !== undefined ? patch.username : existing.username,
      displayName: patch.displayName !== undefined ? patch.displayName : existing.displayName,
      personCode: patch.personCode !== undefined ? patch.personCode : existing.personCode,
      polimiEmail: patch.polimiEmail !== undefined ? patch.polimiEmail : existing.polimiEmail,
      loginStatus: patch.loginStatus !== undefined ? patch.loginStatus : existing.loginStatus,
      loginError: patch.loginError !== undefined ? patch.loginError : existing.loginError,
      roles: patch.roles ? [...patch.roles] : existing.roles,
      metadata: patch.metadata
        ? { ...existing.metadata, ...patch.metadata }
        : existing.metadata,
      updatedAt: Date.now()
    };
    this.users.set(key, updated);
    return structuredClone(updated);
  }

  updateLoginStatus(
    userId: IdentityId,
    status: LoginFlowStatus,
    error: string | null = null
  ): UserIdentity {
    return this.updateUser(userId, { loginStatus: status, loginError: error });
  }

  listUsers(): UserIdentity[] {
    return Array.from(this.users.values()).map((u) => structuredClone(u));
  }

  deleteUser(userId: IdentityId): boolean {
    return this.users.delete(normalizeIdentityId(userId));
  }
}
