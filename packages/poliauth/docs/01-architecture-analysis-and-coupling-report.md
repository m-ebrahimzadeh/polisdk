# Architecture & Boundary Purification Report (`@polisdk/poliauth`)

## 1. Executive Summary

`@polisdk/poliauth` is the standalone authentication core of the **PoliSDK** platform. In Phase 1, all legacy application coupling, runtime-specific infrastructure (`better-sqlite3`, `playwright`, `chrome.*`, `esbuild`, `node:fs`, `node:crypto`), Telegram bot assumptions, and downstream portal service navigation concerns were purged from the core package.

---

## 2. Purified `@polisdk/poliauth` Dependency Graph

```mermaid
flowchart TD
  subgraph Facade["Package Entrypoint (src/)"]
    Index["src/index.ts"]
    Client["src/poliauth-client.ts (PoliAuth)"]
  end

  subgraph Domain["Core Domain & Orchestration (domain/)"]
    Entities["domain/entities.ts"]
    Creds["domain/credentials.ts"]
    FlowSpec["domain/login-flow-spec.ts"]
    Totp["domain/totp.ts"]
    OtpCoord["domain/otp-challenge.ts"]
    Wizard["domain/credential-wizard.ts"]
    Authz["domain/authorization.ts"]
    Orch["domain/login-orchestrator.ts"]
  end

  subgraph Ports["Hexagonal Ports (interfaces/)"]
    StoragePort["interfaces/storage-port.ts"]
    CryptoPort["interfaces/crypto-port.ts"]
    DriverPort["interfaces/browser-driver-port.ts"]
    OtpPort["interfaces/otp-provider-port.ts"]
    AuthzPort["interfaces/authorization-port.ts"]
    LoggerPort["interfaces/logger-port.ts"]
  end

  subgraph Storage["Web-Standard Storage (storage/)"]
    Vault["storage/vault.ts (100% Web Crypto AES-256-GCM)"]
    MemStore["storage/memory-storage.ts"]
  end

  subgraph Adapters["Pure DOM Adapters (adapters/)"]
    PolimiDom["adapters/polimi-dom-adapter.ts"]
    WebexDom["adapters/webex-sso-dom-adapter.ts"]
    DomDriver["adapters/dom-page-driver.ts"]
  end

  subgraph Middleware["Framework-Agnostic Middleware (middleware/)"]
    AuthMw["middleware/auth-middleware.ts"]
    Redaction["middleware/redaction.ts"]
  end

  Index --> Client
  Client --> Domain
  Client --> Storage
  Client --> Middleware
  Domain --> Ports
  Storage --> Ports
  Adapters --> Ports
  Middleware --> Ports
```

---

## 3. Eliminated Coupling Points

| Category | Removed From `@polisdk/poliauth` | Replacement / Architectural Boundary |
| :--- | :--- | :--- |
| **SQLite (`better-sqlite3`)** | `storage/sqlite-storage.ts`, `storage/master-key.ts` | Replaced in core by pure `VaultStoragePort`, `SessionStateStorePort`, and `UserIdentityRepositoryPort` abstractions. |
| **Playwright (`playwright`, `esbuild`)** | `adapters/playwright-page-driver.ts`, `adapters/playwright-session-pool.ts`, `adapters/injected-auth-bundle.ts` | Replaced in core by `AuthPageDriverPort` and `SessionContextPoolPort` interfaces. |
| **Chrome Extensions (`chrome.*`)** | `storage/chrome-storage.ts`, `adapters/chrome-tab-driver.ts`, global `chrome.runtime.id` probes | Replaced by explicit `VaultStoragePort` and `secretMaterial` dependency injection. |
| **Telegram Bot (`grammY` / `Telegraf`)** | `middleware/telegram-middleware.ts`, `TELEGRAM_BOT_TOKEN_REGEX`, `promptMessageId`, `/login` error strings | Replaced by generic `createAuthMiddleware`, `RedactionRule[]`, and UI-neutral `CredentialSetupWizard`. |
| **Legacy Application Naming & Services** | `polirecord_*`, `PoliRecord::*`, `RECORDINGS_ARCHIVE_SERVICE` (`2314`), `'archive'`, `'opening_recording_archives'` | Replaced by `poliauth_*` storage keys, `PoliAuth::*` KDF domain strings, and session-level `'authenticated'` termination. |
| **Node.js Crypto (`node:crypto`, `Buffer`)** | Mixed `createCipheriv` / `Buffer` inside `storage/vault.ts` | Standardized 100% on Web Crypto API (`crypto.subtle` PBKDF2-HMAC-SHA256 + AES-256-GCM) for both credentials and session states. |
