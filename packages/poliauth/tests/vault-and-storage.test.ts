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
  saveEncryptedSessionState,
  loadEncryptedSessionState,
  clearEncryptedSessionState,
  VAULT_STORAGE_KEY,
  VAULT_META_KEY,
  SESSION_STATE_STORAGE_KEY,
  SESSION_STATE_META_KEY,
  EncryptedCredentialVault
} from '../storage/vault.js';
import {
  InMemoryVaultStorage,
  InMemoryUserVaultStorageFactory,
  InMemorySessionStateStore,
  InMemoryUserIdentityRepository
} from '../storage/memory-storage.js';

describe('Credentials Domain & Pure Web Crypto Storage Adapters', () => {
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

  it('encrypts, merges, loads, and clears credentials in InMemoryVaultStorage using Web Crypto', async () => {
    const storage = new InMemoryVaultStorage('unit-test-secret');
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

    // Wrong key returns null cleanly
    const wrongKeyResult = await loadEncryptedCredentials(storage, {
      secretMaterial: 'wrong-secret-key'
    });
    expect(wrongKeyResult).toBeNull();

    await clearEncryptedCredentials(storage);
    expect(await loadEncryptedCredentials(storage)).toBeNull();
  });

  it('encrypts, loads, and clears session state using pure Web Crypto PBKDF2 + AES-256-GCM', async () => {
    const storage = new InMemoryVaultStorage('session-secret-key');
    const mockSessionState = {
      cookies: [{ name: 'JSESSIONID', value: 'secret-cookie-value-999', domain: '.polimi.it' }],
      origins: []
    };

    await saveEncryptedSessionState(storage, mockSessionState);
    const raw = await storage.get([SESSION_STATE_STORAGE_KEY, SESSION_STATE_META_KEY]);
    expect(JSON.stringify(raw)).not.toContain('secret-cookie-value-999');

    const loaded = await loadEncryptedSessionState<typeof mockSessionState>(storage);
    expect(loaded).toEqual(mockSessionState);

    // Wrong secret returns null cleanly
    expect(await loadEncryptedSessionState(storage, 'wrong-secret')).toBeNull();

    await clearEncryptedSessionState(storage);
    expect(await loadEncryptedSessionState(storage)).toBeNull();
  });

  it('isolates multi-tenant credentials and session states via EncryptedCredentialVault & InMemoryUserVaultStorageFactory', async () => {
    const factory = new InMemoryUserVaultStorageFactory('tenant-master-secret');
    const vault = new EncryptedCredentialVault({ userFactory: factory });

    await vault.saveCredentials(
      {
        personCode: '10111111',
        password: 'AliceSecretPassword!'
      },
      'alice'
    );
    await vault.saveCredentials(
      {
        personCode: '10222222',
        password: 'BobSecretPassword!'
      },
      'bob'
    );

    expect((await vault.loadCredentials('alice'))?.personCode).toBe('10111111');
    expect((await vault.loadCredentials('bob'))?.personCode).toBe('10222222');

    await vault.saveSessionState({ ssoToken: 'alice-token' }, 'alice');
    expect(await vault.loadSessionState('alice')).toEqual({ ssoToken: 'alice-token' });
    expect(await vault.loadSessionState('bob')).toBeNull();
  });

  it('supports InMemorySessionStateStore and InMemoryUserIdentityRepository', async () => {
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

  it('serializes concurrent partial credential saves without lost read-modify-write updates', async () => {
    const storage = new InMemoryVaultStorage('concurrent-secret');
    await Promise.all([
      saveEncryptedCredentials({ personCode: '10123456' }, storage),
      saveEncryptedCredentials({ password: 'ConcurrentPassword!' }, storage),
      saveEncryptedCredentials({ totpSecret: 'JBSWY3DPEHPK3PXP' }, storage),
      saveEncryptedCredentials({ polimiEmail: 'mario.rossi@mail.polimi.it' }, storage)
    ]);

    const loaded = await loadEncryptedCredentials(storage);
    expect(loaded).not.toBeNull();
    expect(loaded?.personCode).toBe('10123456');
    expect(loaded?.password).toBe('ConcurrentPassword!');
    expect(loaded?.totpSecret).toBe('JBSWY3DPEHPK3PXP');
    expect(loaded?.polimiEmail).toBe('mario.rossi@mail.polimi.it');
  });

  it('refuses to overwrite corrupt or undecryptable vault envelopes and redacts diagnostic warnings', async () => {
    const storage = new InMemoryVaultStorage('right-secret');
    await saveEncryptedCredentials(
      {
        personCode: '10998877',
        password: 'ProtectedPassword!'
      },
      storage
    );

    const warnings: string[] = [];
    const logger = {
      debug: () => {},
      info: () => {},
      warn: (msg: string) => {
        warnings.push(msg);
      },
      error: () => {}
    };

    // Wrong key cannot overwrite existing credentials silently
    await expect(
      saveEncryptedCredentials(
        { personCode: '10000001' },
        storage,
        { secretMaterial: 'wrong-secret', logger }
      )
    ).rejects.toThrow(/Refusing to overwrite existing encrypted vault/i);
    expect(warnings.length).toBeGreaterThan(0);

    // Corrupted payload also refuses silent overwrite
    await storage.set({ [VAULT_STORAGE_KEY]: { version: 1, iv: 'bad' } });
    await expect(saveEncryptedCredentials({ personCode: '10000001' }, storage)).rejects.toThrow(
      /Refusing to overwrite existing encrypted vault/i
    );
  });

  it('aligns InMemorySessionStateStore and EncryptedCredentialVault key derivation on shared factory', async () => {
    const factory = new InMemoryUserVaultStorageFactory('shared-master-secret');
    const vault = new EncryptedCredentialVault({ userFactory: factory });
    const sessionStore = new InMemorySessionStateStore<{ cookie: string }>(factory);

    await vault.saveSessionState({ cookie: 'from-vault' }, 'alice');
    expect(await sessionStore.loadSessionState('alice')).toEqual({ cookie: 'from-vault' });

    await sessionStore.saveSessionState('bob', { cookie: 'from-store' });
    expect(await vault.loadSessionState('bob')).toEqual({ cookie: 'from-store' });
  });

  it('refuses default secret fallback when requireSecretMaterial is enabled', async () => {
    const emptySecretStorage = new InMemoryVaultStorage();
    await expect(
      saveEncryptedCredentials(
        { personCode: '10123456' },
        emptySecretStorage,
        { requireSecretMaterial: true }
      )
    ).rejects.toThrow(/Refusing to fall back to the default local secret/i);

    await expect(
      loadEncryptedCredentials(emptySecretStorage, { requireSecretMaterial: true })
    ).rejects.toThrow(/Refusing to fall back to the default local secret/i);

    const vault = new EncryptedCredentialVault({
      storage: emptySecretStorage,
      cryptoOptions: { requireSecretMaterial: true }
    });
    await expect(vault.saveSessionState({ ok: true })).rejects.toThrow(
      /Refusing to fall back to the default local secret/i
    );
    await expect(vault.loadSessionState()).rejects.toThrow(
      /Refusing to fall back to the default local secret/i
    );

    // Explicit non-empty secret satisfies requireSecretMaterial even with blank override ignored
    const keyHolder = new InMemoryVaultStorage('real-secret');
    await saveEncryptedCredentials(
      { personCode: '10123456' },
      keyHolder,
      { secretMaterial: '   ', requireSecretMaterial: true }
    );
    const loaded = await loadEncryptedCredentials(keyHolder, {
      secretMaterial: '',
      requireSecretMaterial: true
    });
    expect(loaded?.personCode).toBe('10123456');
  });
});
