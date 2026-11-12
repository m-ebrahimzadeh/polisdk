# Phase 5: Public API Documentation & Usage Examples (`@polisdk/poliauth`)

## 1. Package Exports Overview

`@polisdk/poliauth` exposes both a unified root entry point and modular subpath exports:

| Import Path | Contents |
|---|---|
| `@polisdk/poliauth` | Unified `PoliAuth` client + re-exports of all layers |
| `@polisdk/poliauth/domain` | `PoliAuthOrchestrator`, `TotpService`, `OtpChallengeCoordinator`, `CredentialSetupWizard`, `AuthorizationService`, `PolimiServiceRegistry`, `POLIMI_LOGIN_FLOW_SPEC`, credential masking/validation utilities |
| `@polisdk/poliauth/interfaces` | `AuthPageDriverPort`, `SessionContextPoolPort`, `VaultStoragePort`, `UserVaultStorageFactoryPort`, `SessionStateStorePort`, `UserIdentityRepositoryPort`, `OtpChallengeProviderPort`, `AuthorizationServicePort`, `AuthLoggerPort` |
| `@polisdk/poliauth/storage` | `EncryptedCredentialVault`, `saveEncryptedCredentials`, `loadEncryptedCredentials`, `clearEncryptedCredentials`, `PoliAuthSqliteDatabase`, `SqliteVaultStorageBackend`, `SqliteSessionStateStore`, `ChromeLocalVaultStorage`, `InMemoryVaultStorage`, `resolveMasterEncryptionKey` |
| `@polisdk/poliauth/adapters` | `PlaywrightAuthPageDriver`, `PlaywrightBrowserSessionPool`, `ChromeExtensionTabDriver`, `DomAuthPageDriver`, `polimi-dom-adapter`, `webex-sso-dom-adapter`, `ensureAuthAdaptersInjected`, `getInjectedAuthAdapterBundleCode` |
| `@polisdk/poliauth/middleware` | `createAuthMiddleware`, `createTelegramAuthMiddleware`, `deleteSensitiveTelegramMessage`, `redactSecrets`, `createRedactingLogger` |

---

## 2. Usage Example 1: Headless Playwright Bot / Automated CLI

```ts
import {
  PoliAuth,
  PoliAuthSqliteDatabase,
  SqliteUserVaultStorageFactory,
  SqliteSessionStateStore,
  PlaywrightBrowserSessionPool,
  PlaywrightAuthPageDriver,
  RECORDINGS_ARCHIVE_SERVICE,
  resolveMasterEncryptionKey
} from '@polisdk/poliauth';

const dataDir = './data';
const masterKey = resolveMasterEncryptionKey(process.env.MASTER_ENCRYPTION_KEY, dataDir);
const db = new PoliAuthSqliteDatabase(`${dataDir}/poliauth.sqlite`);

const sessionPool = new PlaywrightBrowserSessionPool({
  sessionStateStore: new SqliteSessionStateStore(db, masterKey),
  maxBrowserContexts: 4,
  browserContextIdleTtlMs: 15 * 60_000,
  headless: true
});

const auth = new PoliAuth({
  userStorageFactory: new SqliteUserVaultStorageFactory(db, masterKey),
  userRepository: db,
  sessionPool
});

// 1. Save encrypted credentials for user 1001
await auth.saveCredentials(
  {
    personCode: '10987654',
    password: 'MyPoliPassword!',
    totpSecret: 'JBSWY3DPEHPK3PXP',
    polimiEmail: 'mario.rossi@mail.polimi.it'
  },
  1001
);

// 2. Authenticate to PoliMi Recordings Archive (or any registered service)
await sessionPool.withUserContext(1001, async ({ page }) => {
  const creds = await auth.loadCredentials(1001);
  if (!creds) throw new Error('No credentials stored.');

  const driver = new PlaywrightAuthPageDriver(page);
  const outcome = await auth.authenticatePolimiService({
    userId: 1001,
    driver,
    credentials: creds,
    targetService: RECORDINGS_ARCHIVE_SERVICE
  });

  if (!outcome.ok) {
    throw new Error(`Authentication failed: ${outcome.error}`);
  }
  console.log('Authenticated at:', outcome.url);
});
```

---

## 3. Usage Example 2: Registering a Custom PoliMi Portal Service (e.g., Career / Exams)

Any project in the PoliSDK ecosystem can define its own `PolimiPortalServiceDescriptor` and authenticate into it using the exact same `PoliAuthOrchestrator`:

```ts
import {
  PoliAuth,
  type PolimiPortalServiceDescriptor,
  WEBEEP_SERVICE
} from '@polisdk/poliauth';

const CARRIERA_STUDENTI_SERVICE: PolimiPortalServiceDescriptor = {
  serviceId: '355',
  name: 'Carriera didattica e piano degli studi',
  portalLinkSelectors: ['a[href*="idServizio=355"]'],
  portalTextMatchers: ['carriera', 'piano degli studi', 'academic career'],
  targetUrlSubstrings: ['carriera', 'pianostudi'],
  stageName: 'target_service'
};

const auth = new PoliAuth();
auth.serviceRegistry.register(CARRIERA_STUDENTI_SERVICE);

// Can now pass `targetService: CARRIERA_STUDENTI_SERVICE` or `WEBEEP_SERVICE`
// to `auth.authenticatePolimiService({ ... })`!
```

---

## 4. Usage Example 3: Telegram Bot (`grammY`) with Auth Middleware & 4-Step Wizard

```ts
import {
  PoliAuth,
  createTelegramAuthMiddleware,
  deleteSensitiveTelegramMessage
} from '@polisdk/poliauth';

const auth = new PoliAuth({
  authorizationOptions: {
    allowedUserIds: [123456789],
    adminUserIds: [123456789],
    enforcePrivateChannel: true
  }
});

// 1. Register private-chat + allowlist + auto-provisioning middleware
bot.use(
  createTelegramAuthMiddleware({
    authorization: auth.authorization,
    userRepository: auth.users
  })
);

// 2. Start 4-step credential onboarding wizard on /setup
bot.command('setup', async (ctx) => {
  const userId = ctx.from!.id;
  auth.wizard.startSession(userId);
  await ctx.reply('Step 1/4: Send your PoliMi Person Code (Codice Persona):');
});

// 3. Handle incoming text messages (Manual 2FA OTP waiter or Wizard step)
bot.on('message:text', async (ctx) => {
  const userId = ctx.from!.id;
  const text = ctx.message.text.trim();

  // Check if user is answering a live 2FA manual OTP prompt
  if (auth.otpChallenge.hasPendingOtpWaiter(userId)) {
    await deleteSensitiveTelegramMessage(ctx);
    if (auth.otpChallenge.submitManualOtpForUser(userId, text)) {
      await ctx.reply('✅ 2FA code received, resuming login...');
    } else {
      await ctx.reply('❌ Please send a valid 6-digit numeric OTP code.');
    }
    return;
  }

  // Check if user is in the 4-step credential setup wizard
  if (auth.wizard.hasActiveSession(userId)) {
    await deleteSensitiveTelegramMessage(ctx);
    const transition = auth.wizard.submitStepInput(userId, text);
    if (!transition) return;

    if (transition.status === 'validation_error') {
      await ctx.reply(`⚠️ ${transition.errorMessage}`);
      return;
    }

    if (transition.status === 'next_step') {
      const prompts = {
        person_code: 'Step 1/4: Send your PoliMi Person Code:',
        password: 'Step 2/4: Send your PoliMi Password:',
        email: 'Step 3/4: Send your institutional PoliMi Email (@mail.polimi.it):',
        totp_secret: 'Step 4/4: Send your Base32 TOTP Secret (or type "skip"):'
      };
      await ctx.reply(prompts[transition.step]);
      return;
    }

    if (transition.status === 'completed') {
      await auth.saveCredentials(transition.credentials, userId);
      await ctx.reply(
        `✅ Credentials encrypted & saved for ${transition.maskedPersonCode} (${transition.maskedEmail}).`
      );
    }
  }
});
```

---

## 5. Usage Example 4: Chrome Extension Background Worker & Content Script

```ts
// In Chrome Extension Content Script (polimi-content.ts / webex-content.ts):
import {
  inspectPolimiPageStage,
  recoverPolimiSessionPage,
  submitPolimiCredentials,
  submitPolimiOtp,
  clickPortalService,
  inspectWebexSsoPage,
  submitWebexEmailLogin
} from '@polisdk/poliauth/adapters';

// In Chrome Extension Background Service Worker (background/index.ts):
import {
  PoliAuth,
  ChromeLocalVaultStorage,
  ChromeExtensionTabDriver
} from '@polisdk/poliauth';

const auth = new PoliAuth({
  storage: new ChromeLocalVaultStorage()
});
```
