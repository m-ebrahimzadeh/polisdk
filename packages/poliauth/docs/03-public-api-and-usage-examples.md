# Public API Documentation & Usage Examples (`@polisdk/poliauth`)

## 1. Package Exports Overview

`@polisdk/poliauth` is 100% runtime-agnostic and exposes both a unified root entry point and modular subpath exports:

| Import Path | Contents |
|---|---|
| `@polisdk/poliauth` | Unified `PoliAuth` facade + re-exports of all core layers |
| `@polisdk/poliauth/domain` | Pure domain entities (`IdentityId`, `LoginCredentials`, `SavedVaultCredentials`, `UserIdentity`), `TotpService`, `POLIMI_LOGIN_FLOW_SPEC`, credential masking/validation utilities |
| `@polisdk/poliauth/application` | `PoliAuthOrchestrator`, `OtpChallengeCoordinator`, `CredentialSetupWizard`, `AuthorizationService` |
| `@polisdk/poliauth/interfaces` | `AuthPageDriverPort`, `SessionContextPoolPort`, `VaultStoragePort`, `UserVaultStorageFactoryPort`, `SessionStateStorePort`, `UserIdentityRepositoryPort`, `OtpChallengeProviderPort`, `AuthorizationServicePort`, `AuthLoggerPort` |
| `@polisdk/poliauth/storage` | `EncryptedCredentialVault`, `saveEncryptedCredentials`, `loadEncryptedCredentials`, `clearEncryptedCredentials`, `saveEncryptedSessionState`, `loadEncryptedSessionState`, `clearEncryptedSessionState`, `InMemoryVaultStorage`, `InMemoryUserVaultStorageFactory`, `InMemorySessionStateStore`, `InMemoryUserIdentityRepository` |
| `@polisdk/poliauth/adapters` | `DomAuthPageDriver`, `polimi-dom-adapter`, `webex-sso-dom-adapter` |
| `@polisdk/poliauth/middleware` | `createAuthMiddleware`, `redactSecrets`, `createRedactingLogger` |

---

## 2. Usage Example 1: Authenticating a PoliMi SSO Session

```ts
import {
  PoliAuth,
  DomAuthPageDriver,
  InMemoryVaultStorage
} from '@polisdk/poliauth';

const auth = new PoliAuth({
  storage: new InMemoryVaultStorage('my-encryption-secret')
});

// 1. Encrypt and store PoliMi credentials
await auth.saveCredentials({
  personCode: '10987654',
  password: 'MyPoliPassword!',
  totpSecret: 'JBSWY3DPEHPK3PXP',
  polimiEmail: 'mario.rossi@mail.polimi.it'
});

// 2. Authenticate against any AuthPageDriverPort implementation
const creds = await auth.loadCredentials();
if (!creds) throw new Error('No credentials stored.');

const driver = new DomAuthPageDriver({
  getDocument: () => document,
  getLocation: () => window.location,
  onNavigate: (url) => {
    window.location.href = url;
  }
});

const outcome = await auth.authenticate({
  userId: 'student-1',
  driver,
  credentials: creds
});

if (!outcome.ok) {
  throw new Error(`Authentication failed: ${outcome.error}`);
}
console.log('Authenticated PoliMi session at:', outcome.url);
```

---

## 3. Usage Example 2: Framework-Agnostic Auth Middleware & Interactive Wizard

```ts
import {
  PoliAuth,
  createAuthMiddleware
} from '@polisdk/poliauth';

interface AppRequestContext {
  userId?: string;
  username?: string;
  isPrivateChannel: boolean;
}

const auth = new PoliAuth({
  authorizationOptions: {
    allowedUserIds: ['user-1001'],
    adminUserIds: ['admin-1'],
    enforcePrivateChannel: true
  }
});

const middleware = createAuthMiddleware<AppRequestContext>({
  authorization: auth.authorization,
  userRepository: auth.users,
  extractSubject: (ctx) => ({
    userId: ctx.userId,
    username: ctx.username,
    isPrivateChannel: ctx.isPrivateChannel
  })
});
```
