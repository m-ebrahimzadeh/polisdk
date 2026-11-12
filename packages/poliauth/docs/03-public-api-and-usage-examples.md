# Public API Documentation & Usage Examples (`PoliSDK`)

## 1. Ecosystem Package Overview

| Package | Purpose | Runtime Dependencies |
|---|---|---|
| `@polisdk/poliauth` | Core authentication domain, application use cases, hexagonal ports, pure DOM adapters, and Web Crypto AES-256-GCM vault | Zero (Standard ES2022 + Web Crypto + DOM) |
| `@polisdk/poliauth-playwright` | Playwright `PlaywrightAuthPageDriver`, build-time pre-bundled DOM injector, and `PlaywrightSessionContextPool` | `@polisdk/poliauth`, `playwright` (peer) |
| `@polisdk/poliauth-chrome` | Chrome Extension MV3 `ChromeLocalVaultStorage`, `ChromeExtensionTabDriver`, and `createPoliAuthContentScriptHandler` | `@polisdk/poliauth` |
| `@polisdk/storage-sqlite` | SQLite multi-user `PoliAuthSqliteDatabase`, `SqliteVaultStorageBackend`, `SqliteSessionStateStore`, and `resolveMasterEncryptionKey` | `@polisdk/poliauth`, `better-sqlite3` (peer) |
| `@polisdk/telegram-auth` | Telegram Bot `createTelegramAuthMiddleware`, `deleteSensitiveTelegramMessage`, `TelegramCredentialWizard`, and `TELEGRAM_BOT_TOKEN_REDACTION_RULE` | `@polisdk/poliauth` |

---

## 2. Core `@polisdk/poliauth` Subpath Exports

| Import Path | Contents |
|---|---|
| `@polisdk/poliauth` | Unified `PoliAuth` facade + re-exports of all core layers |
| `@polisdk/poliauth/domain` | Pure domain entities (`IdentityId`, `LoginCredentials`, `SavedVaultCredentials`, `UserIdentity`), `TotpService`, `cleanTotpSecret`, `isValidTotpSecret`, `decodeTotpBase32`, `generateTotp`, `generateStableTotp`, `getTotpRemainingSeconds`, `TotpOptions`, `StableTotpOptions`, `StableTotpResult`, `TotpGeneratorPort`, `POLIMI_LOGIN_FLOW_SPEC`, credential masking/validation utilities (`normalizeCredentials`, `maskSecret`, `maskPersonCode`) |
| `@polisdk/poliauth/application` | `PoliAuthOrchestrator`, `OtpChallengeCoordinator`, `CredentialSetupWizard`, `AuthorizationService` |
| `@polisdk/poliauth/interfaces` | Segregated role ports: `AuthPageDriverPort`, `PageNavigationPort`, `PolimiIdpPagePort`, `FederatedSsoPageDriverPort`, `FederatedAuthPageDriverPort`, `FederatedSsoProviderAdapterPort`, `FederatedSsoProviderResolverPort`, `FederatedSsoProviderSpec`, `VaultStoragePort`, `VaultSecretMaterialPort`, `UserVaultStorageFactoryPort`, `SessionStateStorePort`, `UserIdentityRepositoryPort`, `UserIdentityProvisionerPort`, `UserIdentityReaderPort`, `UserIdentityWriterPort`, `SessionContextPoolPort`, `SessionContextLeasePort`, `SessionContextPersistencePort`, `SessionContextDisposalPort`, `SessionPoolStatsPort`, `OtpChallengeProviderPort`, `OtpCodeProviderPort`, `ManualOtpChallengePort`, `AuthorizationServicePort`, `AccessEvaluatorPort`, `SubjectRoleQueryPort`, `ResourceAuthorizerPort`, `ResourceAuthorizationPolicyPort`, `AuthLoggerPort`, `MaybePromise` |
| `@polisdk/poliauth/storage` | `EncryptedCredentialVault`, `saveEncryptedCredentials`, `loadEncryptedCredentials`, `clearEncryptedCredentials`, `saveEncryptedSessionState`, `loadEncryptedSessionState`, `clearEncryptedSessionState`, `InMemoryVaultStorage`, `InMemoryUserVaultStorageFactory`, `InMemorySessionStateStore`, `InMemoryUserIdentityRepository` |
| `@polisdk/poliauth/adapters` | `DomAuthPageDriver`, `DomFederatedAuthPageDriver`, `polimi-dom-adapter`, `webex-sso-dom-adapter` (`WebexSamlProviderAdapter`, `WEBEX_SAML_FLOW_SPEC`), `federated-sso-dom-adapter` (`SelectorFederatedSsoProviderAdapter`, `inspectFederatedSsoPageBySpec`, `submitFederatedIdentifierBySpec`), `federated-sso-provider-registry` (`FederatedSsoProviderRegistry`, `createDefaultFederatedSsoProviderRegistry`) |
| `@polisdk/poliauth/middleware` | `createAuthMiddleware`, `redactSecrets`, `redactSensitiveErrorText`, `createRedactingLogger` |

---

## 3. Usage Example 1: Server-Side Multi-User Authentication (`@polisdk/poliauth` + `@polisdk/storage-sqlite` + `@polisdk/poliauth-playwright`)

```ts
import { PoliAuth } from '@polisdk/poliauth';
import {
  PoliAuthSqliteDatabase,
  SqliteUserVaultStorageFactory,
  SqliteSessionStateStore,
  resolveMasterEncryptionKey
} from '@polisdk/storage-sqlite';
import {
  PlaywrightAuthPageDriver,
  PlaywrightSessionContextPool
} from '@polisdk/poliauth-playwright';

const masterKey = resolveMasterEncryptionKey({
  keyFilePath: './data/.master_key'
});
const db = new PoliAuthSqliteDatabase('./data/poliauth.sqlite');

const auth = new PoliAuth({
  userVaultFactory: new SqliteUserVaultStorageFactory(db, masterKey),
  sessionStateStore: new SqliteSessionStateStore(db, masterKey),
  userRepository: db
});

const pool = new PlaywrightSessionContextPool({
  sessionStateStore: new SqliteSessionStateStore(db, masterKey)
});

// Authenticate user 1001 in an isolated Playwright context
const managed = await pool.acquireUserContext(1001);
try {
  const page = await pool.getOrCreatePrimaryPage(managed);
  const driver = new PlaywrightAuthPageDriver(page);
  const creds = await auth.loadCredentials(1001);
  if (!creds) throw new Error('User credentials not configured');

  const outcome = await auth.authenticate({
    userId: 1001,
    driver,
    credentials: creds
  });

  if (outcome.ok) {
    await pool.saveUserContextState(1001);
  }
} finally {
  pool.releaseUserContext(1001);
}
```

---

## 4. Usage Example 2: Chrome Extension MV3 (`@polisdk/poliauth` + `@polisdk/poliauth-chrome`)

```ts
import { PoliAuth } from '@polisdk/poliauth';
import {
  ChromeLocalVaultStorage,
  ChromeExtensionTabDriver
} from '@polisdk/poliauth-chrome';

const auth = new PoliAuth({
  storage: new ChromeLocalVaultStorage()
});

const creds = await auth.loadCredentials();
if (creds) {
  const driver = new ChromeExtensionTabDriver(activeTabId);
  await auth.authenticate({
    driver,
    credentials: creds
  });
}
```

---

## 5. Usage Example 3: Telegram Bot Authentication (`@polisdk/poliauth` + `@polisdk/telegram-auth`)

```ts
import {
  createTelegramAuthMiddleware,
  TelegramCredentialWizard,
  deleteSensitiveTelegramMessage
} from '@polisdk/telegram-auth';

const wizard = new TelegramCredentialWizard();
const authMiddleware = createTelegramAuthMiddleware({
  allowedUserIds: [12345678],
  userRepository: db
});
```
