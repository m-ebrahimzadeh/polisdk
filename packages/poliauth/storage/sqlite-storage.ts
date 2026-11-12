import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import Database from 'better-sqlite3';
import {
  type IdentityId,
  type LoginFlowStatus,
  normalizeIdentityId,
  type SavedVaultCredentials,
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
  saveEncryptedCredentials,
  loadEncryptedCredentials,
  clearEncryptedCredentials,
  saveEncryptedSessionState,
  loadEncryptedSessionState,
  clearEncryptedSessionState,
  PLAYWRIGHT_STORAGE_STATE_KEY
} from './vault.js';

/**
 * Minimal structural interface required to read/write per-user key-value entries
 * in a relational or embedded database.
 * Compatible out-of-the-box with both `PoliAuthSqliteDatabase` and `polirecord`'s `BotDatabase`.
 */
export interface UserVaultKvStorePort {
  getVaultKey(identityId: any, key: string): string | undefined;
  setVaultKey(identityId: any, key: string, valueJson: string): void;
  removeVaultKeys(identityId: any, keys: string[]): void;
}

/**
 * Derives the per-user key material string used by `saveEncryptedCredentials` and `loadEncryptedCredentials`.
 * Preserves byte-for-byte key derivation compatibility with `polirecord`'s `withUserScopedVaultRuntime`.
 */
export function deriveUserScopedVaultSecret(masterKey: string, identityId: IdentityId): string {
  const idStr = normalizeIdentityId(identityId);
  const keyFingerprint = createHash('sha256')
    .update(`${masterKey}::user::${idStr}`)
    .digest('hex');
  return `polirecord-telegram-bot-user-${idStr}-${keyFingerprint}`;
}

/**
 * Derives the per-user key material string used for encrypting Playwright `storageState`.
 * Preserves byte-for-byte key derivation compatibility with `polirecord`'s `saveUserBrowserStorageState`.
 */
export function deriveUserSessionStateSecret(masterKey: string, identityId: IdentityId): string {
  const idStr = normalizeIdentityId(identityId);
  return `${masterKey}::user::${idStr}`;
}

/**
 * `VaultStoragePort` adapter backed by a `UserVaultKvStorePort` (such as SQLite `user_vault_kv`).
 */
export class SqliteVaultStorageBackend implements VaultStoragePort {
  constructor(
    private readonly db: UserVaultKvStorePort,
    private readonly identityId: IdentityId,
    private readonly masterKey?: string
  ) {}

  getSecretMaterial(): string | undefined {
    return this.masterKey
      ? deriveUserScopedVaultSecret(this.masterKey, this.identityId)
      : undefined;
  }

  private coerceId(): string | number {
    if (typeof this.identityId === 'number') {
      return this.identityId;
    }
    const parsed = Number(this.identityId);
    return Number.isSafeInteger(parsed) && String(parsed) === this.identityId.trim()
      ? parsed
      : this.identityId;
  }

  async get(keys: string | string[]): Promise<Record<string, unknown>> {
    const keyList = Array.isArray(keys) ? keys : [keys];
    const result: Record<string, unknown> = {};
    const id = this.coerceId();
    for (const key of keyList) {
      const raw = this.db.getVaultKey(id, key);
      if (raw !== undefined) {
        try {
          result[key] = JSON.parse(raw);
        } catch {
          result[key] = raw;
        }
      }
    }
    return result;
  }

  async set(items: Record<string, unknown>): Promise<void> {
    const id = this.coerceId();
    for (const [key, value] of Object.entries(items)) {
      this.db.setVaultKey(id, key, JSON.stringify(value));
    }
  }

  async remove(keys: string | string[]): Promise<void> {
    const keyList = Array.isArray(keys) ? keys : [keys];
    const id = this.coerceId();
    this.db.removeVaultKeys(id, keyList);
  }
}

/**
 * Multi-tenant factory producing per-user `SqliteVaultStorageBackend` instances.
 */
export class SqliteUserVaultStorageFactory implements UserVaultStorageFactoryPort {
  constructor(
    private readonly db: UserVaultKvStorePort,
    private readonly masterKey?: string
  ) {}

  createForUser(userId: IdentityId): VaultStoragePort {
    return new SqliteVaultStorageBackend(this.db, userId, this.masterKey);
  }
}

/**
 * `SessionStateStorePort` backed by SQLite `user_vault_kv` using AES-256-GCM encryption.
 */
export class SqliteSessionStateStore<TState = unknown> implements SessionStateStorePort<TState> {
  constructor(
    private readonly db: UserVaultKvStorePort,
    private readonly masterKey: string
  ) {}

  async loadSessionState<T extends TState = TState>(userId: IdentityId): Promise<T | null> {
    return loadUserBrowserStorageState<T>(this.db, userId, this.masterKey);
  }

  async saveSessionState(userId: IdentityId, state: TState): Promise<void> {
    await saveUserBrowserStorageState(this.db, userId, this.masterKey, state);
  }

  async clearSessionState(userId: IdentityId): Promise<void> {
    const backend = new SqliteVaultStorageBackend(this.db, userId, this.masterKey);
    await clearEncryptedSessionState(backend);
  }
}

/**
 * Encrypts and saves partial or full credentials into SQLite `user_vault_kv` for a specific user.
 * Drop-in replacement for `polirecord`'s `saveUserVaultCredentials`.
 */
export async function saveUserVaultCredentials(
  db: UserVaultKvStorePort,
  identityId: IdentityId,
  masterKey: string,
  patch: Partial<SavedVaultCredentials>
): Promise<SavedVaultCredentials> {
  const backend = new SqliteVaultStorageBackend(db, identityId, masterKey);
  const secretMaterial = deriveUserScopedVaultSecret(masterKey, identityId);
  return saveEncryptedCredentials(patch, backend, { secretMaterial });
}

/**
 * Loads and decrypts credentials from SQLite `user_vault_kv` for a specific user.
 * Returns `null` if no credentials exist or if the master key does not match.
 * Drop-in replacement for `polirecord`'s `loadUserVaultCredentials`.
 */
export async function loadUserVaultCredentials(
  db: UserVaultKvStorePort,
  identityId: IdentityId,
  masterKey: string
): Promise<SavedVaultCredentials | null> {
  const backend = new SqliteVaultStorageBackend(db, identityId, masterKey);
  const secretMaterial = deriveUserScopedVaultSecret(masterKey, identityId);
  return loadEncryptedCredentials(backend, { secretMaterial });
}

/**
 * Deletes encrypted credentials and metadata from SQLite `user_vault_kv` for a specific user.
 * Drop-in replacement for `polirecord`'s `clearUserVaultCredentials`.
 */
export async function clearUserVaultCredentials(
  db: UserVaultKvStorePort,
  identityId: IdentityId
): Promise<void> {
  const backend = new SqliteVaultStorageBackend(db, identityId);
  await clearEncryptedCredentials(backend);
  db.removeVaultKeys(
    typeof identityId === 'number' ? identityId : normalizeIdentityId(identityId),
    [PLAYWRIGHT_STORAGE_STATE_KEY]
  );
}

/**
 * Encrypts and saves a Playwright `storageState` snapshot for a specific user in SQLite.
 * Drop-in replacement for `polirecord`'s `saveUserBrowserStorageState`.
 */
export async function saveUserBrowserStorageState(
  db: UserVaultKvStorePort,
  identityId: IdentityId,
  masterKey: string,
  storageState: unknown
): Promise<void> {
  const backend = new SqliteVaultStorageBackend(db, identityId, masterKey);
  const secret = deriveUserSessionStateSecret(masterKey, identityId);
  await saveEncryptedSessionState(backend, storageState, secret);
}

/**
 * Loads and decrypts a Playwright `storageState` snapshot for a specific user from SQLite.
 * Drop-in replacement for `polirecord`'s `loadUserBrowserStorageState`.
 */
export async function loadUserBrowserStorageState<T = unknown>(
  db: UserVaultKvStorePort,
  identityId: IdentityId,
  masterKey: string
): Promise<T | null> {
  const backend = new SqliteVaultStorageBackend(db, identityId, masterKey);
  const secret = deriveUserSessionStateSecret(masterKey, identityId);
  return loadEncryptedSessionState<T>(backend, secret);
}

interface RawUserRow {
  telegram_user_id: number | string;
  telegram_username: string | null;
  first_name: string | null;
  person_code: string;
  polimi_email: string;
  login_status: LoginFlowStatus;
  login_error: string | null;
  roles_json: string;
  metadata_json: string;
  onboarding_done: number;
  default_delivery_mode: string;
  created_at: number;
  updated_at: number;
}

/**
 * Standalone SQLite database adapter for PoliAuth (`users` and `user_vault_kv` tables).
 * Can either open its own SQLite file (WAL mode) or wrap an existing `better-sqlite3` `Database` connection.
 */
export class PoliAuthSqliteDatabase implements UserIdentityRepositoryPort, UserVaultKvStorePort {
  public readonly db: Database.Database;
  private readonly ownsConnection: boolean;

  constructor(dbOrPath: string | Database.Database) {
    if (typeof dbOrPath === 'string') {
      fs.mkdirSync(path.dirname(dbOrPath), { recursive: true });
      this.db = new Database(dbOrPath);
      this.ownsConnection = true;
      this.db.pragma('journal_mode = WAL');
      this.db.pragma('foreign_keys = ON');
      this.db.pragma('synchronous = NORMAL');
    } else {
      this.db = dbOrPath;
      this.ownsConnection = false;
    }
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        telegram_user_id INTEGER PRIMARY KEY,
        telegram_username TEXT,
        first_name TEXT,
        person_code TEXT NOT NULL DEFAULT '',
        polimi_email TEXT NOT NULL DEFAULT '',
        login_status TEXT NOT NULL DEFAULT 'idle',
        login_error TEXT,
        roles_json TEXT NOT NULL DEFAULT '[]',
        metadata_json TEXT NOT NULL DEFAULT '{}',
        onboarding_done INTEGER NOT NULL DEFAULT 0,
        default_delivery_mode TEXT NOT NULL DEFAULT 'telegram',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS user_vault_kv (
        telegram_user_id INTEGER NOT NULL,
        vault_key TEXT NOT NULL,
        vault_value_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (telegram_user_id, vault_key),
        FOREIGN KEY (telegram_user_id) REFERENCES users(telegram_user_id) ON DELETE CASCADE
      );
    `);
  }

  private toRowId(identityId: IdentityId): number | string {
    if (typeof identityId === 'number') {
      return identityId;
    }
    const parsed = Number(identityId);
    return Number.isSafeInteger(parsed) && String(parsed) === identityId.trim()
      ? parsed
      : identityId;
  }

  private mapUserRow(row: RawUserRow): UserIdentity {
    let roles: string[] = [];
    let metadata: Record<string, unknown> = {};
    try {
      roles = JSON.parse(row.roles_json || '[]');
    } catch {
      roles = [];
    }
    try {
      metadata = JSON.parse(row.metadata_json || '{}');
    } catch {
      metadata = {};
    }

    return {
      userId: row.telegram_user_id,
      username: row.telegram_username,
      displayName: row.first_name,
      personCode: row.person_code || '',
      polimiEmail: row.polimi_email || '',
      loginStatus: row.login_status || 'idle',
      loginError: row.login_error ?? null,
      roles,
      metadata: {
        onboardingDone: Boolean(row.onboarding_done),
        defaultDeliveryMode: row.default_delivery_mode,
        ...metadata
      },
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  ensureUser(
    userId: IdentityId,
    defaults?: {
      username?: string | null;
      displayName?: string | null;
      roles?: string[];
      metadata?: Record<string, unknown>;
    }
  ): UserIdentity {
    const id = this.toRowId(userId);
    const now = Date.now();
    const existing = this.getUser(id);
    if (existing) {
      this.db
        .prepare(
          `UPDATE users
           SET telegram_username = COALESCE(?, telegram_username),
               first_name = COALESCE(?, first_name),
               updated_at = ?
           WHERE telegram_user_id = ?`
        )
        .run(defaults?.username ?? null, defaults?.displayName ?? null, now, id);
      return this.getUser(id)!;
    }

    const rolesJson = JSON.stringify(defaults?.roles ?? []);
    const metadataJson = JSON.stringify(defaults?.metadata ?? {});

    this.db
      .prepare(
        `INSERT INTO users (
          telegram_user_id, telegram_username, first_name, roles_json, metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(id, defaults?.username ?? null, defaults?.displayName ?? null, rolesJson, metadataJson, now, now);

    return this.getUser(id)!;
  }

  getUser(userId: IdentityId): UserIdentity | null {
    const id = this.toRowId(userId);
    const row = this.db
      .prepare(`SELECT * FROM users WHERE telegram_user_id = ?`)
      .get(id) as RawUserRow | undefined;
    return row ? this.mapUserRow(row) : null;
  }

  updateUser(userId: IdentityId, patch: UserIdentityPatch): UserIdentity {
    const id = this.toRowId(userId);
    const current = this.getUser(id) ?? this.ensureUser(id);
    const nextUsername = patch.username !== undefined ? patch.username : current.username;
    const nextDisplayName =
      patch.displayName !== undefined ? patch.displayName : current.displayName;
    const nextPersonCode =
      patch.personCode !== undefined ? patch.personCode : current.personCode;
    const nextPolimiEmail =
      patch.polimiEmail !== undefined ? patch.polimiEmail : current.polimiEmail;
    const nextStatus = patch.loginStatus !== undefined ? patch.loginStatus : current.loginStatus;
    const nextError = patch.loginError !== undefined ? patch.loginError : current.loginError;
    const nextRoles = patch.roles !== undefined ? patch.roles : current.roles;
    const nextMetadata = patch.metadata
      ? { ...current.metadata, ...patch.metadata }
      : current.metadata;

    this.db
      .prepare(
        `UPDATE users
         SET telegram_username = ?,
             first_name = ?,
             person_code = ?,
             polimi_email = ?,
             login_status = ?,
             login_error = ?,
             roles_json = ?,
             metadata_json = ?,
             updated_at = ?
         WHERE telegram_user_id = ?`
      )
      .run(
        nextUsername,
        nextDisplayName,
        nextPersonCode,
        nextPolimiEmail,
        nextStatus,
        nextError,
        JSON.stringify(nextRoles),
        JSON.stringify(nextMetadata),
        Date.now(),
        id
      );

    return this.getUser(id)!;
  }

  updateLoginStatus(
    userId: IdentityId,
    status: LoginFlowStatus,
    error: string | null = null
  ): UserIdentity {
    return this.updateUser(userId, { loginStatus: status, loginError: error });
  }

  listUsers(): UserIdentity[] {
    const rows = this.db.prepare(`SELECT * FROM users ORDER BY created_at ASC`).all() as RawUserRow[];
    return rows.map((r) => this.mapUserRow(r));
  }

  deleteUser(userId: IdentityId): boolean {
    const id = this.toRowId(userId);
    const res = this.db.prepare(`DELETE FROM users WHERE telegram_user_id = ?`).run(id);
    return res.changes > 0;
  }

  getVaultKey(identityId: IdentityId, key: string): string | undefined {
    const id = this.toRowId(identityId);
    const row = this.db
      .prepare(
        `SELECT vault_value_json FROM user_vault_kv WHERE telegram_user_id = ? AND vault_key = ?`
      )
      .get(id, key) as { vault_value_json: string } | undefined;
    return row?.vault_value_json;
  }

  setVaultKey(identityId: IdentityId, key: string, valueJson: string): void {
    const id = this.toRowId(identityId);
    this.ensureUser(id);
    this.db
      .prepare(
        `INSERT INTO user_vault_kv (telegram_user_id, vault_key, vault_value_json, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(telegram_user_id, vault_key) DO UPDATE SET
           vault_value_json = excluded.vault_value_json,
           updated_at = excluded.updated_at`
      )
      .run(id, key, valueJson, Date.now());
  }

  removeVaultKeys(identityId: IdentityId, keys: string[]): void {
    if (keys.length === 0) return;
    const id = this.toRowId(identityId);
    const stmt = this.db.prepare(
      `DELETE FROM user_vault_kv WHERE telegram_user_id = ? AND vault_key = ?`
    );
    const tx = this.db.transaction((targetKeys: string[]) => {
      for (const k of targetKeys) {
        stmt.run(id, k);
      }
    });
    tx(keys);
  }

  close(): void {
    if (this.ownsConnection) {
      this.db.close();
    }
  }
}
