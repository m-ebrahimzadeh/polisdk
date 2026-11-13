# PoliSDK Monorepo

**PoliSDK** is a modular, Clean Architecture TypeScript platform providing reusable libraries for Politecnico di Milano authentication and student services.

## Packages

| Package | Description | Path |
|---|---|---|
| [`@polisdk/poliauth`](./packages/poliauth) | Standalone, platform-agnostic authentication core: PoliMi SSO & 2FA TOTP/OTP orchestration, Web Crypto AES-256-GCM credential & session vault, federated SAML 2.0 SSO, DOM adapters, and RBAC middleware. | `packages/poliauth` |
| [`@polisdk/poliauth-playwright`](./packages/poliauth-playwright) | Playwright `AuthPageDriverPort`, pre-bundled DOM injection script, and reference-counted `PlaywrightBrowserSessionPool` with LRU eviction and encrypted `storageState` persistence. | `packages/poliauth-playwright` |
| [`@polisdk/poliauth-chrome`](./packages/poliauth-chrome) | Chrome Extension MV3 adapters (`ChromeLocalVaultStorage`, `ChromeExtensionTabDriver`, `createPoliAuthContentScriptHandler`, and `createPoliAuthChromeRuntimeMessageListener`). | `packages/poliauth-chrome` |
| [`@polisdk/storage-sqlite`](./packages/storage-sqlite) | SQLite multi-user identity repository (`PoliAuthSqliteDatabase`), encrypted per-user credential & session vault (`SqliteVaultStorageBackend`, `SqliteSessionStateStore`), and `resolveMasterEncryptionKey`. | `packages/storage-sqlite` |
| [`@polisdk/telegram-auth`](./packages/telegram-auth) | Telegram Bot authentication middleware (`createTelegramAuthMiddleware`), sensitive message deletion (`deleteSensitiveTelegramMessage`), and interactive `TelegramCredentialWizard`. | `packages/telegram-auth` |

## Repository Structure

```text
polisdk/
├── package.json
├── tsconfig.base.json
├── vitest.config.ts
└── packages/
    ├── poliauth/              # Core runtime-agnostic authentication package
    │   ├── src/               # Unified PoliAuth client & package entrypoints
    │   ├── domain/            # Pure domain entities, credential rules, RFC 6238 TOTP & SSO specs
    │   ├── application/       # Stateful use cases (PoliAuthOrchestrator, OtpChallengeCoordinator, Wizard, Authz)
    │   ├── interfaces/        # Hexagonal ports (Driver, Storage, Crypto, OTP, Authz, Logger)
    │   ├── adapters/          # Pure DOM adapters (PoliMi SSO, Federated SAML SSO, DomAuthPageDriver)
    │   ├── middleware/        # Framework-agnostic auth middleware & secret redaction
    │   ├── storage/           # Pure Web Crypto PBKDF2 + AES-256-GCM Vault & In-Memory adapters
    │   ├── tests/             # Unit & integration test suite (Vitest + JSDOM)
    │   └── docs/              # Architecture audit, Clean Architecture design & API docs
    ├── poliauth-playwright/   # Headless/headed Playwright driver & session context pool
    ├── poliauth-chrome/       # Chrome Extension MV3 storage & tab message driver
    ├── storage-sqlite/        # SQLite multi-user identity & encrypted vault persistence
    └── telegram-auth/         # Telegram bot middleware & interactive wizard
```

## Quick Commands

```bash
# Install dependencies and link workspaces
npm install

# Build all packages
npm run build

# Type-check all packages
npm run typecheck

# Run unit and integration test suites across all packages
npm test
```
