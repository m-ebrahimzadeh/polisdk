import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  PoliAuthSqliteDatabase,
  SqliteSessionStateStore,
  SqliteUserVaultStorageFactory,
  clearUserVaultCredentials,
  loadUserSessionState,
  loadUserVaultCredentials,
  resolveMasterEncryptionKey,
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
});
