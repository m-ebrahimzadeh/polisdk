import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  maskPersonCode,
  maskPolimiEmail,
  maskSecret,
  isValidPersonCode,
  isValidPolimiEmail,
  isValidOtpCode
} from '../domain/credentials.js';
import {
  saveEncryptedCredentials,
  loadEncryptedCredentials,
  clearEncryptedCredentials,
  VAULT_STORAGE_KEY,
  VAULT_META_KEY,
  EncryptedCredentialVault
} from '../storage/vault.js';
import {
  InMemoryVaultStorage,
  InMemoryUserVaultStorageFactory,
  InMemorySessionStateStore,
  InMemoryUserIdentityRepository
} from '../storage/memory-storage.js';
import { ChromeLocalVaultStorage } from '../storage/chrome-storage.js';
import { resolveMasterEncryptionKey } from '../storage/master-key.js';
import {
  PoliAuthSqliteDatabase,
  saveUserVaultCredentials,
  loadUserVaultCredentials,
  clearUserVaultCredentials,
  saveUserBrowserStorageState,
  loadUserBrowserStorageState,
  SqliteSessionStateStore
} from '../storage/sqlite-storage.js';

describe('Credentials Domain & Encrypted Storage Adapters', () => {
  it('masks person codes, emails, and secrets safely for display', () => {
    expect(maskPersonCode('10987654')).toBe('109***54');
    expect(maskPolimiEmail('mario.rossi@mail.polimi.it')).toBe('ma***i@mail.polimi.it');
    expect(maskSecret('supersecret')).toBe('●●●●●●●●');
    expect(maskSecret('')).toBe('Not set');
  });

  it('validates PoliMi person codes, institutional emails, and 6-digit OTPs', () => {
    expect(isValidPersonCode('10987654')).toBe(true);
    expect(isValidPersonCode('123')).toBe(false);
    expect(isValidPolimiEmail('mario.rossi@mail.polimi.it')).toBe(true);
    expect(isValidPolimiEmail('prof@polimi.it')).toBe(true);
    expect(isValidPolimiEmail('user@gmail.com')).toBe(false);
    expect(isValidOtpCode('123456')).toBe(true);
    expect(isValidOtpCode('123 456')).toBe(true);
    expect(isValidOtpCode('12345')).toBe(false);
  });

  it('encrypts, merges, loads, and clears credentials in InMemoryVaultStorage', async () => {
    const storage = new InMemoryVaultStorage();
    await saveEncryptedCredentials(
      {
        personCode: '10987654',
        password: 'MyPoliPassword!'
      },
      storage
    );

    const raw = await storage.get([VAULT_STORAGE_KEY, VAULT_META_KEY]);
    const serialized = JSON.stringify(raw);
    expect(serialized).not.toContain('MyPoliPassword!');
    expect(serialized).not.toContain('10987654');

    // Merge partial update (TOTP + email) without losing password
    await saveEncryptedCredentials(
      {
        totpSecret: 'JBSWY3DPEHPK3PXP',
        polimiEmail: 'mario.rossi@mail.polimi.it'
      },
      storage
    );

    const loaded = await loadEncryptedCredentials(storage);
    expect(loaded).not.toBeNull();
    expect(loaded?.personCode).toBe('10987654');
    expect(loaded?.password).toBe('MyPoliPassword!');
    expect(loaded?.totpSecret).toBe('JBSWY3DPEHPK3PXP');
    expect(loaded?.polimiEmail).toBe('mario.rossi@mail.polimi.it');

    await clearEncryptedCredentials(storage);
    expect(await loadEncryptedCredentials(storage)).toBeNull();
  });

  it('supports ChromeLocalVaultStorage with an injected ChromeStorageAreaLike', async () => {
    const backing = new InMemoryVaultStorage();
    const chromeStorage = new ChromeLocalVaultStorage(backing);
    const vault = new EncryptedCredentialVault({ storage: chromeStorage });

    await vault.saveCredentials({
      personCode: '10112233',
      password: 'ChromePassword!'
    });

    const loaded = await vault.loadCredentials();
    expect(loaded?.personCode).toBe('10112233');
    expect(loaded?.password).toBe('ChromePassword!');
  });

  it('persists per-user encrypted credentials and Playwright storageState in SQLite with strict user and key isolation', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'poliauth-sqlite-test-'));
    const dbPath = path.join(tmpDir, 'auth.sqlite');
    const masterKey = resolveMasterEncryptionKey(undefined, tmpDir);
    expect(masterKey.length).toBeGreaterThanOrEqual(32);

    const db = new PoliAuthSqliteDatabase(dbPath);
    try {
      const user1 = db.ensureUser(1001, { username: 'alice', displayName: 'Alice' });
      const user2 = db.ensureUser(2002, { username: 'bob', displayName: 'Bob' });
      expect(user1.username).toBe('alice');
      expect(user2.username).toBe('bob');

      await saveUserVaultCredentials(db, 1001, masterKey, {
        personCode: '10111111',
        password: 'AliceSecretPassword!',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        polimiEmail: 'alice@mail.polimi.it'
      });

      await saveUserVaultCredentials(db, 2002, masterKey, {
        personCode: '10222222',
        password: 'BobSecretPassword!',
        polimiEmail: 'bob@mail.polimi.it'
      });

      const aliceCreds = await loadUserVaultCredentials(db, 1001, masterKey);
      const bobCreds = await loadUserVaultCredentials(db, 2002, masterKey);

      expect(aliceCreds?.personCode).toBe('10111111');
      expect(aliceCreds?.password).toBe('AliceSecretPassword!');
      expect(bobCreds?.personCode).toBe('10222222');
      expect(bobCreds?.password).toBe('BobSecretPassword!');

      // Wrong master key must return null cleanly without throwing
      const wrongKeyAttempt = await loadUserVaultCredentials(
        db,
        1001,
        'wrong-master-encryption-key-with-32-chars-minimum'
      );
      expect(wrongKeyAttempt).toBeNull();

      // Encrypted Playwright storageState round-trip
      const mockStorageState = {
        cookies: [{ name: 'JSESSIONID', value: 'secret-cookie-123', domain: '.polimi.it' }],
        origins: []
      };
      await saveUserBrowserStorageState(db, 1001, masterKey, mockStorageState);

      const rawStateJson = db.getVaultKey(1001, 'polirecord_playwright_storage_state_v1');
      expect(rawStateJson).toBeDefined();
      expect(rawStateJson).not.toContain('secret-cookie-123');

      const restoredState = await loadUserBrowserStorageState<typeof mockStorageState>(
        db,
        1001,
        masterKey
      );
      expect(restoredState).toEqual(mockStorageState);

      // SqliteSessionStateStore wrapper test
      const sessionStore = new SqliteSessionStateStore(db, masterKey);
      expect(await sessionStore.loadSessionState(1001)).toEqual(mockStorageState);

      await clearUserVaultCredentials(db, 1001);
      expect(await loadUserVaultCredentials(db, 1001, masterKey)).toBeNull();
      expect(await loadUserBrowserStorageState(db, 1001, masterKey)).toBeNull();
    } finally {
      db.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('supports InMemoryUserVaultStorageFactory, InMemorySessionStateStore, and InMemoryUserIdentityRepository', async () => {
    const userRepo = new InMemoryUserIdentityRepository();
    const u = userRepo.ensureUser('user-abc', { username: 'charlie', displayName: 'Charlie' });
    expect(u.loginStatus).toBe('idle');
    userRepo.updateLoginStatus('user-abc', 'authenticated');
    expect(userRepo.getUser('user-abc')?.loginStatus).toBe('authenticated');

    const factory = new InMemoryUserVaultStorageFactory();
    const sessionStore = new InMemorySessionStateStore<{ token: string }>(factory);
    await sessionStore.saveSessionState('user-abc', { token: 'sso-xyz' });
    expect(await sessionStore.loadSessionState('user-abc')).toEqual({ token: 'sso-xyz' });
    expect(await sessionStore.loadSessionState('other-user')).toBeNull();
    await sessionStore.clearSessionState('user-abc');
    expect(await sessionStore.loadSessionState('user-abc')).toBeNull();
  });
});
