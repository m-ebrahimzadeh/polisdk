/**
 * @module @polisdk/storage-sqlite
 * SQLite storage adapter implementing:
 * - `VaultStoragePort` (`SqliteVaultStorageBackend`)
 * - `UserVaultStorageFactoryPort` (`SqliteUserVaultStorageFactory`)
 * - `UserIdentityRepositoryPort` (`PoliAuthSqliteDatabase`)
 * - `SessionStateStorePort` (`SqliteSessionStateStore`)
 */

import Database from "better-sqlite3";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  SESSION_STATE_META_KEY,
  SESSION_STATE_STORAGE_KEY,
  VAULT_META_KEY,
  VAULT_STORAGE_KEY,
  loadEncryptedCredentials,
  loadEncryptedSessionState,
  normalizeIdentityId,
  saveEncryptedCredentials,
  saveEncryptedSessionState,
  type IdentityId,
  type LoginFlowStatus,
  type SavedVaultCredentials,
  type SessionStateStorePort,
  type UserIdentity,
  type UserIdentityPatch,
  type UserIdentityRepositoryPort,
  type UserVaultStorageFactoryPort,
  type VaultSecretMaterialPort,
  type VaultStoragePort,
} from "@polisdk/poliauth";

export interface SqliteRunResult {
  changes: number;
  lastInsertRowid: number | bigint;
}

export interface SqliteColumnDefinition {
  name: string;
  column: string | null;
  table: string | null;
  database: string | null;
  type: string | null;
}

export interface SqliteStatementLike<
  BindParameters extends unknown[] = unknown[],
  Result = unknown,
> {
  readonly source: string;
  readonly reader: boolean;
  readonly readonly: boolean;
  readonly busy: boolean;
  run(...params: BindParameters): SqliteRunResult;
  get(...params: BindParameters): Result | undefined;
  all(...params: BindParameters): Result[];
  iterate(...params: BindParameters): IterableIterator<Result>;
  pluck(toggleState?: boolean): this;
  expand(toggleState?: boolean): this;
  raw(toggleState?: boolean): this;
  bind(...params: BindParameters): this;
  columns(): SqliteColumnDefinition[];
  safeIntegers(toggleState?: boolean): this;
}

export type SqliteTransactionArgs<F extends (...args: any[]) => unknown> =
  F extends (...args: infer A) => unknown ? A : never;

export interface SqliteTransactionLike<
  F extends (...args: any[]) => unknown,
> {
  (...params: SqliteTransactionArgs<F>): ReturnType<F>;
  default(...params: SqliteTransactionArgs<F>): ReturnType<F>;
  deferred(...params: SqliteTransactionArgs<F>): ReturnType<F>;
  immediate(...params: SqliteTransactionArgs<F>): ReturnType<F>;
  exclusive(...params: SqliteTransactionArgs<F>): ReturnType<F>;
}

export interface SqliteDatabaseLike {
  readonly memory: boolean;
  readonly readonly: boolean;
  readonly name: string;
  readonly open: boolean;
  readonly inTransaction: boolean;
  prepare<
    BindParameters extends unknown[] | {} = unknown[],
    Result = unknown,
  >(
    source: string,
  ): BindParameters extends unknown[]
    ? SqliteStatementLike<BindParameters, Result>
    : SqliteStatementLike<[BindParameters], Result>;
  transaction<F extends (...args: any[]) => unknown>(
    fn: F,
  ): SqliteTransactionLike<F>;
  exec(source: string): this;
  pragma(source: string, options?: { simple?: boolean }): unknown;
  loadExtension(path: string): this;
  close(): this;
  defaultSafeIntegers(toggleState?: boolean): this;
  unsafeMode(unsafe?: boolean): this;
}

interface SqliteUserRow {
  user_id: string;
  username: string | null;
  display_name: string | null;
  person_code: string;
  polimi_email: string;
  login_status: LoginFlowStatus;
  login_error: string | null;
  roles_json: string;
  metadata_json: string;
  created_at: number;
  updated_at: number;
}

function parseJsonArray(json: string | null): string[] {
  if (!json) return [];
  try {
    const parsed = JSON.parse(json) as unknown;
    return Array.isArray(parsed) ? parsed.map((item) => String(item)) : [];
  } catch {
    return [];
  }
}

function parseJsonObject(json: string | null): Record<string, unknown> {
  if (!json) return {};
  try {
    const parsed = JSON.parse(json) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

function mapUserRow(row: SqliteUserRow): UserIdentity {
  const numericId = Number(row.user_id);
  const userId: IdentityId =
    Number.isSafeInteger(numericId) && String(numericId) === row.user_id
      ? numericId
      : row.user_id;

  return {
    userId,
    username: row.username,
    displayName: row.display_name,
    personCode: row.person_code ?? "",
    polimiEmail: row.polimi_email ?? "",
    loginStatus: row.login_status,
    loginError: row.login_error,
    roles: parseJsonArray(row.roles_json),
    metadata: parseJsonObject(row.metadata_json),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function requireNonEmptyMasterKey(
  masterEncryptionKey: string | undefined,
  caller: string,
): string {
  if (
    typeof masterEncryptionKey !== "string" ||
    masterEncryptionKey.trim().length === 0
  ) {
    throw new Error(
      `${caller} requires a non-empty masterEncryptionKey; refusing to fall back to a default key.`,
    );
  }
  return masterEncryptionKey;
}

function getMasterKeyFingerprint(masterEncryptionKey: string): string {
  return crypto
    .createHash("sha256")
    .update(masterEncryptionKey)
    .digest("hex");
}

/**
 * Derive a deterministic per-user PBKDF2 secret string from the server master key.
 */
export function deriveUserVaultSecret(
  userId: IdentityId,
  masterEncryptionKey: string,
): string {
  const validKey = requireNonEmptyMasterKey(
    masterEncryptionKey,
    "deriveUserVaultSecret",
  );
  const idKey = normalizeIdentityId(userId);
  const fp = getMasterKeyFingerprint(validKey);
  return `poliauth-user-${idKey}-${fp}`;
}

/**
 * Per-user `VaultStoragePort` backed by the `user_vault_kv` table in SQLite.
 */
export class SqliteVaultStorageBackend
  implements VaultStoragePort, VaultSecretMaterialPort
{
  public readonly requiresSecretMaterial = true;
  private readonly db: PoliAuthSqliteDatabase;
  private readonly userId: IdentityId;
  private readonly secretMaterial: string;

  constructor(
    db: PoliAuthSqliteDatabase,
    userId: IdentityId,
    masterEncryptionKey: string,
  ) {
    const validKey = requireNonEmptyMasterKey(
      masterEncryptionKey,
      "SqliteVaultStorageBackend",
    );
    this.db = db;
    this.userId = userId;
    this.secretMaterial = deriveUserVaultSecret(userId, validKey);
  }

  async get(keys: string | string[]): Promise<Record<string, unknown>> {
    const keyList = Array.isArray(keys) ? keys : [keys];
    const result: Record<string, unknown> = {};
    for (const key of keyList) {
      const rawJson = this.db.getVaultRaw(this.userId, key);
      if (rawJson !== null) {
        try {
          result[key] = JSON.parse(rawJson);
        } catch {
          result[key] = rawJson;
        }
      }
    }
    return result;
  }

  async set(items: Record<string, unknown>): Promise<void> {
    const entries = Object.entries(items).map(
      ([key, value]): [string, string] => [key, JSON.stringify(value)],
    );
    this.db.setVaultRawBatch(this.userId, entries);
  }

  async remove(keys: string | string[]): Promise<void> {
    const keyList = Array.isArray(keys) ? keys : [keys];
    this.db.removeVaultRawBatch(this.userId, keyList);
  }

  getSecretMaterial(): string {
    return this.secretMaterial;
  }
}

/**
 * Factory producing per-user `SqliteVaultStorageBackend` instances.
 */
export class SqliteUserVaultStorageFactory
  implements UserVaultStorageFactoryPort
{
  private readonly db: PoliAuthSqliteDatabase;
  private readonly masterEncryptionKey: string;
  private readonly perUserBackends = new Map<string, SqliteVaultStorageBackend>();

  constructor(db: PoliAuthSqliteDatabase, masterEncryptionKey: string) {
    this.db = db;
    this.masterEncryptionKey = requireNonEmptyMasterKey(
      masterEncryptionKey,
      "SqliteUserVaultStorageFactory",
    );
  }

  createForUser(userId: IdentityId): VaultStoragePort {
    const key = normalizeIdentityId(userId);
    let backend = this.perUserBackends.get(key);
    if (!backend) {
      backend = new SqliteVaultStorageBackend(
        this.db,
        userId,
        this.masterEncryptionKey,
      );
      this.perUserBackends.set(key, backend);
    }
    return backend;
  }
}

/**
 * SQLite database adapter for PoliAuth user identity and key-value vault records.
 */
export class PoliAuthSqliteDatabase implements UserIdentityRepositoryPort {
  public readonly sqlite: SqliteDatabaseLike;

  constructor(dbFilePath: string) {
    if (dbFilePath !== ":memory:") {
      const dir = path.dirname(path.resolve(dbFilePath));
      fs.mkdirSync(dir, { recursive: true });
    }
    this.sqlite = new Database(dbFilePath);
    this.sqlite.pragma("journal_mode = WAL");
    this.sqlite.pragma("foreign_keys = ON");
    this.migrate();
  }

  private migrate(): void {
    this.sqlite.exec(`
      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        username TEXT,
        display_name TEXT,
        person_code TEXT NOT NULL DEFAULT '',
        polimi_email TEXT NOT NULL DEFAULT '',
        login_status TEXT NOT NULL DEFAULT 'idle',
        login_error TEXT,
        roles_json TEXT NOT NULL DEFAULT '[]',
        metadata_json TEXT NOT NULL DEFAULT '{}',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS user_vault_kv (
        user_id TEXT NOT NULL,
        vault_key TEXT NOT NULL,
        vault_value_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, vault_key)
      );
    `);
  }

  ensureUser(
    userId: IdentityId,
    defaults?: {
      username?: string | null;
      displayName?: string | null;
      roles?: string[];
      metadata?: Record<string, unknown>;
    },
  ): UserIdentity {
    const now = Date.now();
    const userIdStr = normalizeIdentityId(userId);
    const rolesJson = defaults?.roles ? JSON.stringify(defaults.roles) : null;
    const metadataJson = defaults?.metadata
      ? JSON.stringify(defaults.metadata)
      : null;

    this.sqlite
      .prepare(
        `
      INSERT INTO users (
        user_id, username, display_name, roles_json, metadata_json, created_at, updated_at
      ) VALUES (
        @userId, @username, @displayName, COALESCE(@rolesJson, '[]'), COALESCE(@metadataJson, '{}'), @now, @now
      )
      ON CONFLICT(user_id) DO UPDATE SET
        username = COALESCE(excluded.username, users.username),
        display_name = COALESCE(excluded.display_name, users.display_name),
        roles_json = CASE WHEN @rolesJson IS NOT NULL THEN @rolesJson ELSE users.roles_json END,
        metadata_json = CASE WHEN @metadataJson IS NOT NULL THEN @metadataJson ELSE users.metadata_json END,
        updated_at = excluded.updated_at
    `,
      )
      .run({
        userId: userIdStr,
        username: defaults?.username ?? null,
        displayName: defaults?.displayName ?? null,
        rolesJson,
        metadataJson,
        now,
      });

    return this.getUser(userId)!;
  }

  getUser(userId: IdentityId): UserIdentity | null {
    const row = this.sqlite
      .prepare(`SELECT * FROM users WHERE user_id = ?`)
      .get(normalizeIdentityId(userId)) as SqliteUserRow | undefined;

    return row ? mapUserRow(row) : null;
  }

  updateUser(userId: IdentityId, patch: UserIdentityPatch): UserIdentity {
    const existing = this.getUser(userId) ?? this.ensureUser(userId);
    const updatedUsername =
      patch.username !== undefined ? patch.username : existing.username;
    const updatedDisplayName =
      patch.displayName !== undefined
        ? patch.displayName
        : existing.displayName;
    const updatedPersonCode =
      patch.personCode !== undefined ? patch.personCode : existing.personCode;
    const updatedEmail =
      patch.polimiEmail !== undefined
        ? patch.polimiEmail
        : existing.polimiEmail;
    const updatedStatus =
      patch.loginStatus !== undefined
        ? patch.loginStatus
        : existing.loginStatus;
    const updatedError =
      patch.loginError !== undefined ? patch.loginError : existing.loginError;
    const updatedRoles =
      patch.roles !== undefined ? patch.roles : existing.roles;
    const updatedMetadata =
      patch.metadata !== undefined
        ? { ...existing.metadata, ...patch.metadata }
        : existing.metadata;

    this.sqlite
      .prepare(
        `
      UPDATE users
      SET username = ?,
          display_name = ?,
          person_code = ?,
          polimi_email = ?,
          login_status = ?,
          login_error = ?,
          roles_json = ?,
          metadata_json = ?,
          updated_at = ?
      WHERE user_id = ?
    `,
      )
      .run(
        updatedUsername,
        updatedDisplayName,
        updatedPersonCode,
        updatedEmail,
        updatedStatus,
        updatedError,
        JSON.stringify(updatedRoles),
        JSON.stringify(updatedMetadata),
        Date.now(),
        normalizeIdentityId(userId),
      );

    return this.getUser(userId)!;
  }

  updateLoginStatus(
    userId: IdentityId,
    status: LoginFlowStatus,
    error: string | null = null,
  ): UserIdentity {
    return this.updateUser(userId, {
      loginStatus: status,
      loginError: error,
    });
  }

  listUsers(): UserIdentity[] {
    const rows = this.sqlite
      .prepare(`SELECT * FROM users ORDER BY created_at ASC`)
      .all() as SqliteUserRow[];
    return rows.map(mapUserRow);
  }

  deleteUser(userId: IdentityId): boolean {
    const idStr = normalizeIdentityId(userId);
    const runDelete = this.sqlite.transaction((targetId: string) => {
      this.sqlite
        .prepare(`DELETE FROM user_vault_kv WHERE user_id = ?`)
        .run(targetId);
      const res = this.sqlite
        .prepare(`DELETE FROM users WHERE user_id = ?`)
        .run(targetId);
      return res.changes > 0;
    });
    return runDelete(idStr);
  }

  getVaultRaw(userId: IdentityId, key: string): string | null {
    const row = this.sqlite
      .prepare(
        `SELECT vault_value_json FROM user_vault_kv WHERE user_id = ? AND vault_key = ?`,
      )
      .get(normalizeIdentityId(userId), key) as
      | { vault_value_json: string }
      | undefined;

    return row?.vault_value_json ?? null;
  }

  setVaultRaw(userId: IdentityId, key: string, valueJson: string): void {
    this.setVaultRawBatch(userId, [[key, valueJson]]);
  }

  setVaultRawBatch(
    userId: IdentityId,
    entries: Array<readonly [string, string]>,
  ): void {
    if (entries.length === 0) {
      return;
    }
    const idStr = normalizeIdentityId(userId);
    const now = Date.now();
    const stmt = this.sqlite.prepare(`
      INSERT INTO user_vault_kv (user_id, vault_key, vault_value_json, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id, vault_key) DO UPDATE SET
        vault_value_json = excluded.vault_value_json,
        updated_at = excluded.updated_at
    `);
    const runBatch = this.sqlite.transaction(
      (items: Array<readonly [string, string]>) => {
        for (const [key, valueJson] of items) {
          stmt.run(idStr, key, valueJson, now);
        }
      },
    );
    runBatch(entries);
  }

  removeVaultRaw(userId: IdentityId, key: string): void {
    this.removeVaultRawBatch(userId, [key]);
  }

  removeVaultRawBatch(userId: IdentityId, keys: string[]): void {
    if (keys.length === 0) {
      return;
    }
    const idStr = normalizeIdentityId(userId);
    const stmt = this.sqlite.prepare(
      `DELETE FROM user_vault_kv WHERE user_id = ? AND vault_key = ?`,
    );
    const runBatch = this.sqlite.transaction((targetKeys: string[]) => {
      for (const key of targetKeys) {
        stmt.run(idStr, key);
      }
    });
    runBatch(keys);
  }

  close(): void {
    this.sqlite.close();
  }
}

const sqliteUserMutationQueues = new WeakMap<
  PoliAuthSqliteDatabase,
  Map<string, Promise<void>>
>();

async function withSqliteUserMutationLock<T>(
  db: PoliAuthSqliteDatabase,
  userId: IdentityId,
  task: () => Promise<T>,
): Promise<T> {
  let dbQueues = sqliteUserMutationQueues.get(db);
  if (!dbQueues) {
    dbQueues = new Map<string, Promise<void>>();
    sqliteUserMutationQueues.set(db, dbQueues);
  }
  const lockKey = normalizeIdentityId(userId);
  const previous = dbQueues.get(lockKey) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const chained = previous.then(() => current, () => current);
  dbQueues.set(lockKey, chained);

  await previous;
  try {
    return await task();
  } finally {
    release();
    if (dbQueues.get(lockKey) === chained) {
      dbQueues.delete(lockKey);
    }
  }
}

/**
 * Encrypt and persist a user's PoliMi credentials into SQLite.
 */
export async function saveUserVaultCredentials(
  db: PoliAuthSqliteDatabase,
  masterEncryptionKey: string,
  userId: IdentityId,
  credentials: Partial<SavedVaultCredentials>,
): Promise<SavedVaultCredentials> {
  const validKey = requireNonEmptyMasterKey(
    masterEncryptionKey,
    "saveUserVaultCredentials",
  );
  return withSqliteUserMutationLock(db, userId, async () => {
    const storage = new SqliteVaultStorageBackend(
      db,
      userId,
      validKey,
    );
    const saved = await saveEncryptedCredentials(credentials, storage);
    db.updateUser(userId, {
      personCode: saved.personCode,
      polimiEmail: saved.polimiEmail,
    });
    return saved;
  });
}

/**
 * Load and decrypt a user's PoliMi credentials from SQLite.
 */
export async function loadUserVaultCredentials(
  db: PoliAuthSqliteDatabase,
  masterEncryptionKey: string,
  userId: IdentityId,
): Promise<SavedVaultCredentials | null> {
  const validKey = requireNonEmptyMasterKey(
    masterEncryptionKey,
    "loadUserVaultCredentials",
  );
  const storage = new SqliteVaultStorageBackend(
    db,
    userId,
    validKey,
  );
  return loadEncryptedCredentials(storage);
}

/**
 * Clear a user's encrypted credentials and session state from SQLite.
 */
export async function clearUserVaultCredentials(
  db: PoliAuthSqliteDatabase,
  userId: IdentityId,
): Promise<void> {
  await withSqliteUserMutationLock(db, userId, async () => {
    db.removeVaultRawBatch(userId, [
      VAULT_STORAGE_KEY,
      VAULT_META_KEY,
      SESSION_STATE_STORAGE_KEY,
      SESSION_STATE_META_KEY,
    ]);
    db.updateUser(userId, {
      personCode: "",
      polimiEmail: "",
      loginStatus: "idle",
      loginError: null,
    });
  });
}

/**
 * Encrypt and store a user's browser session state in SQLite using Web Crypto AES-256-GCM.
 */
export async function saveUserSessionState<TState = unknown>(
  db: PoliAuthSqliteDatabase,
  masterEncryptionKey: string,
  userId: IdentityId,
  storageState: TState,
): Promise<void> {
  const validKey = requireNonEmptyMasterKey(
    masterEncryptionKey,
    "saveUserSessionState",
  );
  await withSqliteUserMutationLock(db, userId, async () => {
    const storage = new SqliteVaultStorageBackend(
      db,
      userId,
      validKey,
    );
    await saveEncryptedSessionState(storage, storageState);
  });
}

/**
 * Load and decrypt a user's browser session state from SQLite.
 */
export async function loadUserSessionState<TState = unknown>(
  db: PoliAuthSqliteDatabase,
  masterEncryptionKey: string,
  userId: IdentityId,
): Promise<TState | null> {
  const validKey = requireNonEmptyMasterKey(
    masterEncryptionKey,
    "loadUserSessionState",
  );
  const storage = new SqliteVaultStorageBackend(
    db,
    userId,
    validKey,
  );
  return loadEncryptedSessionState<TState>(storage);
}

/**
 * Remove a user's encrypted browser session state from SQLite.
 */
export async function clearUserSessionState(
  db: PoliAuthSqliteDatabase,
  userId: IdentityId,
): Promise<void> {
  await withSqliteUserMutationLock(db, userId, async () => {
    db.removeVaultRawBatch(userId, [
      SESSION_STATE_STORAGE_KEY,
      SESSION_STATE_META_KEY,
    ]);
  });
}

/**
 * `SessionStateStorePort` adapter backed by `PoliAuthSqliteDatabase`.
 */
export class SqliteSessionStateStore<TState = unknown>
  implements SessionStateStorePort<TState>
{
  private readonly db: PoliAuthSqliteDatabase;
  private readonly masterEncryptionKey: string;

  constructor(db: PoliAuthSqliteDatabase, masterEncryptionKey: string) {
    this.db = db;
    this.masterEncryptionKey = requireNonEmptyMasterKey(
      masterEncryptionKey,
      "SqliteSessionStateStore",
    );
  }

  async loadSessionState<T extends TState = TState>(
    userId: IdentityId,
  ): Promise<T | null> {
    return loadUserSessionState<T>(
      this.db,
      this.masterEncryptionKey,
      userId,
    );
  }

  async saveSessionState(userId: IdentityId, state: TState): Promise<void> {
    await saveUserSessionState<TState>(
      this.db,
      this.masterEncryptionKey,
      userId,
      state,
    );
  }

  async clearSessionState(userId: IdentityId): Promise<void> {
    await clearUserSessionState(this.db, userId);
  }
}
