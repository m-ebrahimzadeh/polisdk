# Phase 5: Migration Guide — Integrating `@polisdk/poliauth` Back into `polirecord`

This guide provides step-by-step instructions and exact module mappings for replacing the internal authentication, 2FA TOTP, vault encryption, session pool, and middleware code in `polirecord` with `@polisdk/poliauth`.

---

## 1. Install `@polisdk/poliauth` in `polirecord`

In `C:\Users\user\Project\polirecord\package.json`, add `@polisdk/poliauth`:

```json
{
  "dependencies": {
    "@polisdk/poliauth": "file:../polisdk/packages/poliauth"
  }
}
```

Then run `npm install`.

---

## 2. Module-by-Module Replacement Matrix

| Original `polirecord` File | Action | Replacement in `@polisdk/poliauth` |
|---|---|---|
| `src/shared/totp.ts` | **Delete & Re-export** | `import { cleanTotpSecret, isValidTotpSecret, decodeBase32, generateTotp, getTotpRemainingSeconds, generateStableTotp } from '@polisdk/poliauth/domain';` |
| `src/shared/vault.ts` | **Delete & Re-export** | `import { saveEncryptedCredentials, loadEncryptedCredentials, clearEncryptedCredentials, getDefaultStorageBackend, VAULT_STORAGE_KEY, VAULT_META_KEY, type StorageBackend } from '@polisdk/poliauth/storage';` |
| `src/shared/login-flow-spec.ts` | **Delete & Re-export** | `import { POLIMI_LOGIN_FLOW_SPEC } from '@polisdk/poliauth/domain';` |
| `src/bot/db/vault-storage.ts` | **Delete & Re-export** | `import { SqliteVaultStorageBackend, saveUserVaultCredentials, loadUserVaultCredentials, clearUserVaultCredentials, saveUserBrowserStorageState, loadUserBrowserStorageState } from '@polisdk/poliauth/storage';` |
| `src/bot/browser/context-pool.ts` | **Replace** | `PlaywrightBrowserSessionPool` (`@polisdk/poliauth/adapters`) + `SqliteSessionStateStore` (`@polisdk/poliauth/storage`) |
| `src/bot/browser/polimi-session.ts` | **Simplify** | Replace the 280-line login state machine (`ensureAuthenticatedArchivePage`) with `PoliAuthOrchestrator.authenticateToService()`; keep only `searchCourseOfferingsInArchive` and `listRecordingsForOfferingInArchive` in `polirecord`. |
| `src/bot/browser/webex-downloader.ts` | **Simplify** | Replace the inline SAML SSO + PoliMi credentials/2FA loop with `PoliAuthOrchestrator.handleFederatedSamlStep()` / `authenticateFederatedSaml()`; keep only MP4 download stream & `ffmpeg` logic in `polirecord`. |
| `src/adapters/polimi-adapter.ts` | **Split** | Import `isPolimiLoginPage`, `isPolimiArchivePage`, `inspectPolimiPageStage`, `recoverPolimiSessionPage`, `submitPolimiCredentials`, `submitPolimiOtp`, `findRecordingArchivesLink`, `clickRecordingArchivesOnPortal` from `@polisdk/poliauth/adapters`; keep only `extractAcademicYears`, `prepareAndSubmitArchiveSearch`, `extractRowsFromCurrentTable`, `collectAllArchivePages`, `resolvePlayUrlFromDom` in `polirecord`. |
| `src/adapters/webex-adapter.ts` | **Split** | Import `isWebexEmailSsoPage`, `inspectWebexSsoPage`, `submitWebexEmailLogin` from `@polisdk/poliauth/adapters`; keep only MP4 player DOM selectors (`#playerDownload_<uuid>`, `#Dlg_download_confirm`, `iframe_MP4`) in `polirecord`. |
| `src/bot/telegram/bot.ts` | **Replace Auth Guard** | Use `createTelegramAuthMiddleware` and `AuthorizationService` from `@polisdk/poliauth`. |
| `src/bot/telegram/handlers/auth-handlers.ts` | **Simplify** | Use `CredentialSetupWizard`, `OtpChallengeCoordinator`, `maskPersonCode`, `maskPolimiEmail`, and `deleteSensitiveTelegramMessage` from `@polisdk/poliauth`. |
| `src/bot/queue/bot-queue-manager.ts` | **Use Redaction Helper** | Import `redactSecrets` from `@polisdk/poliauth/middleware`. |

---

## 3. Before / After Refactoring Examples in `polirecord`

### 3.1 `src/bot/browser/polimi-session.ts`

**Before (280 lines of manual loop over stages):**
```ts
// Manually looped over inspectPolimiPageStage, recoverPolimiSessionPage,
// submitPolimiCredentials, obtainOtpCodeForUser, submitPolimiOtp, and clickRecordingArchivesOnPortal
```

**After (delegating to `PoliAuthOrchestrator`):**
```ts
import {
  PoliAuthOrchestrator,
  PlaywrightAuthPageDriver,
  RECORDINGS_ARCHIVE_SERVICE,
  loadUserVaultCredentials
} from '@polisdk/poliauth';

export async function ensureAuthenticatedArchivePage(
  params: EnsureAuthenticatedArchiveParams
): Promise<EnsureArchiveResult> {
  const creds = await loadUserVaultCredentials(
    params.db,
    params.telegramUserId,
    params.config.masterEncryptionKey
  );
  if (!creds?.personCode || !creds?.password) {
    return { ok: false, error: 'Missing PoliMi credentials. Run /setup first.' };
  }

  const driver = new PlaywrightAuthPageDriver(params.page);
  const orchestrator = new PoliAuthOrchestrator(params.otpCoordinator);

  return orchestrator.authenticateToService({
    userId: params.telegramUserId,
    driver,
    credentials: creds,
    targetService: RECORDINGS_ARCHIVE_SERVICE,
    callbacks: params.callbacks,
    onAuthenticated: () => params.pool.saveUserContextState(params.telegramUserId)
  });
}
```

### 3.2 `src/bot/telegram/bot.ts` (Access Control + Resource Ownership Policy)

```ts
import {
  AuthorizationService,
  createTelegramAuthMiddleware
} from '@polisdk/poliauth';

const authz = new AuthorizationService({
  allowedUserIds: config.allowedTelegramUserIds,
  adminUserIds: config.adminTelegramUserIds,
  enforcePrivateChannel: true,
  resourcePolicy: {
    isResourceAuthorized(userId, resource) {
      if (resource.resourceType === 'transfer') {
        return db.isTransferIdAuthorizedForUser(Number(userId), resource.resourceId);
      }
      return true;
    }
  }
});

bot.use(
  createTelegramAuthMiddleware({
    authorization: authz,
    userRepository: db
  })
);
```

---

## 4. Backward Compatibility Guarantee for Existing Deployments

1. **Chrome Extension (`chrome.storage.local`)**:
   - Uses identical storage keys (`polirecord_secure_vault_v1`, `polirecord_vault_meta_v1`), PBKDF2-HMAC-SHA256 (`100,000` iterations), and `PoliRecord::VaultKey::v1::${runtimeId}::AES-256-GCM` key derivation. Existing extension users do **not** need to re-enter credentials.
2. **Telegram Bot SQLite (`bot.sqlite`)**:
   - Uses identical `users` (`telegram_user_id`) and `user_vault_kv` schema, identical `deriveUserScopedVaultSecret` (`polirecord-telegram-bot-user-${id}-${keyFingerprint}`), and identical `PLAYWRIGHT_STORAGE_STATE_KEY` (`polirecord_playwright_storage_state_v1`) AES-256-GCM format. Existing `bot.sqlite` databases work without any data migration or re-onboarding.
