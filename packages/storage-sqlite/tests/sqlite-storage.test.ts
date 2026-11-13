import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  PoliAuthSqliteDatabase,
  SqliteSessionStateStore,
  SqliteUserVaultStorageFactory,
  SqliteVaultStorageBackend,
  clearUserVaultCredentials,
  deriveUserVaultSecret,
  loadUserSessionState,
  loadUserVaultCredentials,
  resolveMasterEncryptionKey,
  saveUserSessionState,
  saveUserVaultCredentials,
} from "../src/index.js";

describe("@polisdk/storage-sqlite", () => {
  let db: PoliAuthSqliteDatabase;
  const masterKey = "0123456789abcdef0123456789abcdef";

  beforeEach(() => {
    db = new PoliAuthSqliteDatabase(":memory:");
  });

  afterEach(() => {
    db.close();
  });

  it("manages user identity profiles with neutral user_id primary keys", () => {
    const created = db.ensureUser(778899, {
      username: "mrossi",
      displayName: "Mario Rossi",
      roles: ["student", "admin"],
      metadata: { department: "DEIB" },
    });

    expect(created.userId).toBe(778899);
    expect(created.username).toBe("mrossi");
    expect(created.displayName).toBe("Mario Rossi");
    expect(created.loginStatus).toBe("idle");
    expect(created.roles).toEqual(["student", "admin"]);
    expect(created.metadata).toEqual({ department: "DEIB" });

    db.updateLoginStatus(778899, "authenticated", null);
    const updated = db.getUser(778899);
    expect(updated?.loginStatus).toBe("authenticated");

    const allUsers = db.listUsers();
    expect(allUsers).toHaveLength(1);
  });

  it("encrypts and decrypts user credentials and session state in SQLite", async () => {
    db.ensureUser("user-42", { username: "rossi" });

    await saveUserVaultCredentials(db, masterKey, "user-42", {
      personCode: "10654321",
      password: "Password!1",
      totpSecret: "JBSWY3DPEHPK3PXP",
      polimiEmail: "mario.rossi@mail.polimi.it",
    });

    const userRecord = db.getUser("user-42");
    expect(userRecord?.personCode).toBe("10654321");
    expect(userRecord?.polimiEmail).toBe("mario.rossi@mail.polimi.it");

    const loaded = await loadUserVaultCredentials(db, masterKey, "user-42");
    expect(loaded).not.toBeNull();
    expect(loaded?.personCode).toBe("10654321");
    expect(loaded?.password).toBe("Password!1");
    expect(loaded?.totpSecret).toBe("JBSWY3DPEHPK3PXP");

    // Verify SessionStateStore
    const sessionStore = new SqliteSessionStateStore<{ cookies: string[] }>(
      db,
      masterKey,
    );
    await sessionStore.saveSessionState("user-42", {
      cookies: ["JSESSIONID=abc123"],
    });

    const loadedSession = await sessionStore.loadSessionState("user-42");
    expect(loadedSession).toEqual({ cookies: ["JSESSIONID=abc123"] });

    // Verify UserVaultStorageFactory
    const factory = new SqliteUserVaultStorageFactory(db, masterKey);
    const userStorage = factory.createForUser("user-42");
    await userStorage.set({ custom_key: { ok: true } });
    expect(await userStorage.get("custom_key")).toEqual({
      custom_key: { ok: true },
    });

    // Clear user vault
    await clearUserVaultCredentials(db, "user-42");
    expect(await loadUserVaultCredentials(db, masterKey, "user-42")).toBeNull();
    expect(await loadUserSessionState(db, masterKey, "user-42")).toBeNull();
    expect(db.getUser("user-42")?.loginStatus).toBe("idle");
  });

  it("resolves or generates master encryption key files", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "polisdk-key-test-"));
    const keyFile = path.join(tmpDir, "master.key");

    const generated = resolveMasterEncryptionKey({ keyFilePath: keyFile });
    expect(generated.length).toBeGreaterThanOrEqual(16);

    const reloaded = resolveMasterEncryptionKey({ keyFilePath: keyFile });
    expect(reloaded).toBe(generated);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("handles atomic master key creation races and rejects corrupt short key files", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "polisdk-key-race-"));
    try {
      const keyFile = path.join(tmpDir, "atomic.key");
      const results = await Promise.all(
        Array.from({ length: 6 }, async () =>
          resolveMasterEncryptionKey({ keyFilePath: keyFile }),
        ),
      );
      expect(new Set(results).size).toBe(1);
      expect(results[0].length).toBeGreaterThanOrEqual(16);

      const shortKeyFile = path.join(tmpDir, "short.key");
      fs.writeFileSync(shortKeyFile, "too-short\n", "utf8");
      expect(() =>
        resolveMasterEncryptionKey({ keyFilePath: shortKeyFile, minLength: 16 }),
      ).toThrow(/Refusing to overwrite existing key file/i);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("atomically deletes user and vault rows in deleteUser and serializes concurrent credential saves", async () => {
    db.ensureUser("concurrent-user", { username: "concurrent" });

    await Promise.all([
      saveUserVaultCredentials(db, masterKey, "concurrent-user", {
        personCode: "10555666",
      }),
      saveUserVaultCredentials(db, masterKey, "concurrent-user", {
        password: "SqliteConcurrentPassword!",
      }),
      saveUserVaultCredentials(db, masterKey, "concurrent-user", {
        polimiEmail: "concurrent@mail.polimi.it",
      }),
    ]);

    const loaded = await loadUserVaultCredentials(
      db,
      masterKey,
      "concurrent-user",
    );
    expect(loaded?.personCode).toBe("10555666");
    expect(loaded?.password).toBe("SqliteConcurrentPassword!");
    expect(loaded?.polimiEmail).toBe("concurrent@mail.polimi.it");

    expect(db.deleteUser("concurrent-user")).toBe(true);
    expect(db.getUser("concurrent-user")).toBeNull();
    expect(
      await loadUserVaultCredentials(db, masterKey, "concurrent-user"),
    ).toBeNull();
  });

  it("rejects missing or whitespace masterEncryptionKey across all SQLite vault APIs", async () => {
    expect(() => deriveUserVaultSecret("u1", "")).toThrow(
      /requires a non-empty masterEncryptionKey/i,
    );
    expect(() => deriveUserVaultSecret("u1", "   ")).toThrow(
      /requires a non-empty masterEncryptionKey/i,
    );

    expect(
      () =>
        new SqliteVaultStorageBackend(
          db,
          "u1",
          undefined as unknown as string,
        ),
    ).toThrow(/requires a non-empty masterEncryptionKey/i);
    expect(() => new SqliteVaultStorageBackend(db, "u1", "  ")).toThrow(
      /requires a non-empty masterEncryptionKey/i,
    );

    expect(
      () =>
        new SqliteUserVaultStorageFactory(
          db,
          undefined as unknown as string,
        ),
    ).toThrow(/requires a non-empty masterEncryptionKey/i);
    expect(() => new SqliteUserVaultStorageFactory(db, "")).toThrow(
      /requires a non-empty masterEncryptionKey/i,
    );

    expect(() => new SqliteSessionStateStore(db, "   ")).toThrow(
      /requires a non-empty masterEncryptionKey/i,
    );

    await expect(
      saveUserVaultCredentials(db, "", "u1", { personCode: "10123456" }),
    ).rejects.toThrow(/requires a non-empty masterEncryptionKey/i);
    await expect(loadUserVaultCredentials(db, "  ", "u1")).rejects.toThrow(
      /requires a non-empty masterEncryptionKey/i,
    );
    await expect(
      saveUserSessionState(db, "", "u1", { cookies: [] }),
    ).rejects.toThrow(/requires a non-empty masterEncryptionKey/i);
    await expect(loadUserSessionState(db, "  ", "u1")).rejects.toThrow(
      /requires a non-empty masterEncryptionKey/i,
    );
  });
});
