# `@polisdk/poliauth`

Standalone, framework-agnostic authentication, 2FA (RFC 6238 TOTP & manual OTP), session management, federated SAML 2.0 SSO, AES-256-GCM credential vault, and RBAC authorization library for the **PoliSDK** platform.

## Key Capabilities

- **5-Stage Politecnico di Milano Authentication Orchestrator (`PoliAuthOrchestrator`)**:
  - Stage 0: `SessioneTerminata` / security violation recovery (`id_servizio=376`)
  - Stage 1: JAF (`aunicalogin.polimi.it`) credentials submission (skipping hidden `.jaf-visually-hidden` trap buttons)
  - Stage 2: 2FA verification via automatic RFC 6238 TOTP (with 30-second window rollover guard) and seamless fallback to interactive manual 6-digit OTP waiters (`OtpChallengeCoordinator`)
  - Stage 3: `servizionline.polimi.it` Portal discovery and extensible service launch (`PolimiServiceRegistry`: Recordings Archive `2314`, WeBeep `2166`, Portal `376`, or custom services)
  - Stage 4 & 5: Target service verification and multi-hop Federated SAML 2.0 SSO (`idbroker-eu.webex.com/idb/saml2/jsp/doSSO.jsp` ↔ `aunicalogin.polimi.it`)
- **Zero-Trust Encrypted Credential & Session Vault (`storage/`)**:
  - PBKDF2-HMAC-SHA256 (`100,000` iterations) + AES-256-GCM encryption for credentials and Playwright `storageState` cookies/origins
  - Pluggable adapters for SQLite (`PoliAuthSqliteDatabase`, `SqliteVaultStorageBackend`), Chrome Extensions (`ChromeLocalVaultStorage`), and In-Memory (`InMemoryVaultStorage`)
- **Multi-User Browser Session Pool (`PlaywrightBrowserSessionPool`)**:
  - Isolated per-user `BrowserContext` instances, reference-counted active locks, LRU capacity eviction, idle TTL cleanup, and automatic `storageState` encryption/restoration
- **Interactive Onboarding & Security Middleware (`domain/`, `middleware/`)**:
  - 4-step `CredentialSetupWizard` state machine (`person_code` → `password` → `email` → `totp_secret`)
  - `AuthorizationService`, `createAuthMiddleware`, `createTelegramAuthMiddleware`, and `redactSecrets` / `createRedactingLogger`

## Documentation

1. [Phase 1: Architecture Analysis & Coupling Report](./docs/01-architecture-analysis-and-coupling-report.md)
2. [Phase 2 & 3: Clean Architecture & Refactoring Strategy](./docs/02-clean-architecture-and-refactoring-strategy.md)
3. [Phase 5: Public API & Usage Examples](./docs/03-public-api-and-usage-examples.md)
4. [Phase 5: PoliRecord Migration Guide](./docs/04-polirecord-migration-guide.md)
