# Public API Documentation & Usage Examples (`PoliSDK`)

## 1. Ecosystem Package Overview

| Package | Purpose | Runtime Dependencies |
|---|---|---|
| `@polisdk/poliauth` | Core authentication domain, application use cases, hexagonal ports, pure DOM adapters, and Web Crypto AES-256-GCM vault | Zero (Standard ES2022 + Web Crypto + DOM) |
| `@polisdk/poliauth-playwright` | Playwright `PlaywrightAuthPageDriver`, build-time pre-bundled DOM injector, and `PlaywrightBrowserSessionPool` | `@polisdk/poliauth`, `playwright` (peer) |
| `@polisdk/poliauth-chrome` | Chrome Extension MV3 `ChromeLocalVaultStorage`, `ChromeExtensionTabDriver`, `createPoliAuthContentScriptHandler`, and `createPoliAuthChromeRuntimeMessageListener` | `@polisdk/poliauth` |
| `@polisdk/storage-sqlite` | SQLite multi-user `PoliAuthSqliteDatabase`, `SqliteVaultStorageBackend`, `SqliteSessionStateStore`, and `resolveMasterEncryptionKey` | `@polisdk/poliauth`, `better-sqlite3` (peer) |
| `@polisdk/telegram-auth` | Telegram Bot `createTelegramAuthMiddleware`, `deleteSensitiveTelegramMessage`, `TelegramCredentialWizard`, and `TELEGRAM_BOT_TOKEN_REDACTION_RULE` | `@polisdk/poliauth` |

---

## 2. Core `@polisdk/poliauth` Subpath Exports

| Import Path | Contents |
|---|---|
| `@polisdk/poliauth` | Unified `PoliAuth` facade + re-exports of all core layers |
| `@polisdk/poliauth/domain` | Pure domain entities (`IdentityId`, `LoginCredentials`, `SavedVaultCredentials`, `UserIdentity`, `PolimiStageInspectionResult`, `FederatedSsoInspectionResult`), `TotpService`, `cleanTotpSecret`, `isValidTotpSecret`, `decodeBase32`, `generateTotp`, `generateStableTotp`, `getTotpRemainingSeconds`, `TotpOptions`, `StableTotpOptions`, `StableTotpResult`, `TotpGeneratorPort`, `POLIMI_LOGIN_FLOW_SPEC`, credential masking/validation/merge utilities (`isValidPersonCode`, `isValidPolimiEmail`, `isValidOtpCode`, `mergeVaultCredentials`, `maskSecret`, `maskPersonCode`, `maskPolimiEmail`), and redaction primitives (`RedactionRule`, `redactSecrets`, `redactSensitiveErrorText`) |
| `@polisdk/poliauth/application` | `PoliAuthOrchestrator`, `OtpChallengeCoordinator`, `CredentialSetupWizard`, `AuthorizationService`, `createRedactingLogger` |
| `@polisdk/poliauth/interfaces` | Segregated role ports: `AuthPageDriverPort`, `PageNavigationPort`, `PolimiIdpPagePort`, `FederatedSsoPageDriverPort`, `FederatedAuthPageDriverPort`, `FederatedSsoProviderAdapterPort`, `FederatedSsoProviderResolverPort`, `FederatedSsoProviderSpec`, `FederatedIdentifierPromptSpec`, `FederatedLoginTriggerSpec`, `VaultStoragePort`, `VaultSecretMaterialPort`, `UserVaultStorageFactoryPort`, `SessionStateStorePort`, `UserIdentityRepositoryPort`, `UserIdentityProvisionerPort`, `UserIdentityReaderPort`, `UserIdentityWriterPort`, `SessionContextPoolPort`, `SessionContextLeasePort`, `SessionContextPersistencePort`, `SessionContextDisposalPort`, `SessionPoolStatsPort`, `OtpChallengeProviderPort`, `OtpCodeProviderPort`, `ManualOtpChallengePort`, `AuthorizationServicePort`, `AccessEvaluatorPort`, `SubjectRoleQueryPort`, `ResourceAuthorizerPort`, `ResourceAuthorizationPolicyPort`, `AuthLoggerPort`, `MaybePromise` |
| `@polisdk/poliauth/storage` | `EncryptedCredentialVault`, `saveEncryptedCredentials`, `loadEncryptedCredentials`, `clearEncryptedCredentials`, `saveEncryptedSessionState`, `loadEncryptedSessionState`, `clearEncryptedSessionState`, `InMemoryVaultStorage`, `InMemoryUserVaultStorageFactory`, `InMemorySessionStateStore`, `InMemoryUserIdentityRepository` |
| `@polisdk/poliauth/adapters` | `DomAuthPageDriver`, `DomFederatedAuthPageDriver`, `polimi-dom-adapter`, `webex-sso-dom-adapter` (`WebexSamlProviderAdapter`, `WEBEX_SAML_FLOW_SPEC`, `createWebexSamlFlowSpec`), `federated-sso-dom-adapter` (`SelectorFederatedSsoProviderAdapter`, `inspectFederatedSsoPageBySpec`, `isFederatedLoginTriggerPage`, `submitFederatedIdentifierBySpec`, `triggerFederatedLoginBySpec`), `federated-sso-provider-registry` (`FederatedSsoProviderRegistry`, `createDefaultFederatedSsoProviderRegistry`) |
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
  PlaywrightBrowserSessionPool
} from '@polisdk/poliauth-playwright';

const masterKey = resolveMasterEncryptionKey({
  keyFilePath: './data/.master_key'
});
const db = new PoliAuthSqliteDatabase('./data/poliauth.sqlite');

const pool = new PlaywrightBrowserSessionPool({
  sessionStateStore: new SqliteSessionStateStore(db, masterKey)
});

const auth = new PoliAuth({
  userStorageFactory: new SqliteUserVaultStorageFactory(db, masterKey),
  userRepository: db,
  sessionPool: pool
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
    userId: 'default-user',
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

---

## 6. Federated SAML 2.0 & Shibboleth SSO (Modes A, B, and C)

Any federated Service Provider can be configured declaratively via `FederatedSsoProviderSpec` and passed directly at runtime to `PlaywrightAuthPageDriver` or `ChromeExtensionTabDriver` (or cloned via `.withFederatedProviderSpec(spec)`):

1. **Mode A (`identifierPrompt`)**: Multi-tenant SaaS SPs (e.g., Webex via `WEBEX_SAML_FLOW_SPEC` or `createWebexSamlFlowSpec()`, Zoom) requiring `federatedIdentifier` (or `credentials.polimiEmail`).
2. **Mode B (`loginTrigger`)**: Click-through Shibboleth/CAS landing pages (e.g., WeBeep `/login/index.php`) where `triggerFederatedLogin()` clicks `loginTrigger.triggerSelector` without entering an email.
3. **Mode C (direct redirect via `entryUrl`)**: Direct Shibboleth endpoints (e.g., `https://webeep.polimi.it/auth/shibboleth/index.php`) that 302-redirect through `transitHostnames` / `transitUrlSubstrings` to PoliMi IdP and return to `authenticatedHostnames` / `authenticatedSelectors`.

### Playwright with Mode B / Mode C `FederatedSsoProviderSpec`

```ts
import {
  PoliAuthOrchestrator,
  OtpChallengeCoordinator,
  TotpService,
  type FederatedSsoProviderSpec
} from '@polisdk/poliauth';
import { PlaywrightAuthPageDriver } from '@polisdk/poliauth-playwright';

const webeepSpec: FederatedSsoProviderSpec = {
  providerId: 'webeep',
  displayName: 'PoliMi WeBeep (Moodle)',
  entryUrl: 'https://webeep.polimi.it/login/index.php',
  loginTrigger: {
    hostnames: ['webeep.polimi.it'],
    pathnameSubstrings: ['/login/index.php'],
    triggerSelector: 'a[href*="/auth/shibboleth/index.php"]'
  },
  transitHostnames: ['shibidp.polimi.it', 'aunicalogin.polimi.it'],
  transitUrlSubstrings: ['/idp/profile/SAML2/', '/Shibboleth.sso/'],
  authenticatedHostnames: ['webeep.polimi.it'],
  authenticatedSelectors: ['#page-my-index', '.usermenu']
};

const orchestrator = new PoliAuthOrchestrator(
  new OtpChallengeCoordinator({ totpGenerator: new TotpService() })
);

const driver = new PlaywrightAuthPageDriver(page, {
  federatedProviderSpec: webeepSpec
});

await orchestrator.authenticateFederatedSaml({
  userId: 1001,
  driver,
  credentials,
  entryUrl: webeepSpec.entryUrl
});
```

### Chrome Extension MV3 with Dynamic `FederatedSsoProviderSpec`

```ts
import { WEBEX_SAML_FLOW_SPEC } from '@polisdk/poliauth/adapters';
import { ChromeExtensionTabDriver } from '@polisdk/poliauth-chrome';

// Mode A (Webex email discovery)
const webexDriver = new ChromeExtensionTabDriver(activeTabId, {
  federatedProviderSpec: WEBEX_SAML_FLOW_SPEC
});

// Switch spec cleanly without rebuilding bundles or changing content scripts
const webeepDriver = webexDriver.withFederatedProviderSpec(webeepSpec);
```

---

## 7. Semantic IdP Error Taxonomy & `reauth_required` Circuit Breaker (Spec Sec 7.1)

`@polisdk/poliauth` exports `PolimiSemanticErrorCode` and `classifyPolimiSemanticError` (`INVALID_CREDENTIALS`, `PASSWORD_EXPIRED`, `ACCOUNT_LOCKED`, `OTP_REJECTED`, `IDP_MAINTENANCE`, `DOM_SELECTOR_DRIFT`) backed by `POLIMI_LOGIN_FLOW_SPEC.semanticErrorIndicators`.

When `PoliAuth` (or `PoliAuthOrchestrator` / `CredentialSetupWizard`) is wired with `identityRepository` (`UserRepository` / `UserIdentityReaderPort & UserIdentityWriterPort`):
1. **Pre-browser fast-fail**: Users in `loginStatus === 'reauth_required'` abort before any browser context is leased or `driver.goto()` is invoked (`reauthRequired: true`, `classification: 'AUTHENTICATION_REJECTED'`).
2. **Stage 1 immediate terminal trip**: `INVALID_CREDENTIALS`, `PASSWORD_EXPIRED`, and `ACCOUNT_LOCKED` (at any stage) immediately set `loginStatus = 'reauth_required'` with zero retries.
3. **Stage 2 `OTP_REJECTED` policy**: On 1st auto-TOTP rejection, status stays unchanged, the orchestrator waits for the next 30-second RFC 6238 TOTP window, and retries `submitOtp` once; a 2nd consecutive failure (or reaching `maxManualOtpAttempts`) trips `'reauth_required'`.
4. **Maintenance & drift preservation**: `IDP_MAINTENANCE` (`PORTAL_OUTAGE_OR_NETWORK_ERROR`) and `DOM_SELECTOR_DRIFT` never mark a user `'reauth_required'`.
5. **Credential reset**: Completing `CredentialSetupWizard` or calling `PoliAuth.saveCredentials(..., identityId)` resets `'reauth_required'` back to `'idle'` and clears `loginError`.
