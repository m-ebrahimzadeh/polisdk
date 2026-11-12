# `@polisdk/poliauth`

Standalone, platform-agnostic authentication, 2FA (RFC 6238 TOTP & manual OTP), session state encryption, federated SAML 2.0 SSO, Web Crypto AES-256-GCM credential vault, and RBAC authorization core library for the **PoliSDK** platform.

## Key Capabilities

- **Politecnico di Milano SSO Authentication Orchestrator (`PoliAuthOrchestrator`)**:
  - Stage 0: `SessioneTerminata` / security violation recovery (`id_servizio=376`)
  - Stage 1: JAF (`aunicalogin.polimi.it`) credentials submission (skipping hidden `.jaf-visually-hidden` trap buttons)
  - Stage 2: 2FA verification via automatic RFC 6238 TOTP (with 30-second window rollover guard) and seamless fallback to interactive manual 6-digit OTP waiters (`OtpChallengeCoordinator`)
  - Stage 3: Authenticated PoliMi SSO session verification (`stage === 'authenticated'`), cleanly decoupled from downstream service navigation
  - Federated SAML 2.0 SSO orchestration across external Service Providers and `aunicalogin.polimi.it`
- **100% Web Standard Encrypted Credential & Session Vault (`storage/`)**:
  - Pure Web Crypto API (`crypto.subtle`) PBKDF2-HMAC-SHA256 (`100,000` iterations) + AES-256-GCM encryption for both credentials and serialized session states
  - Zero Node-specific, SQLite, Playwright, Chrome, or Telegram runtime dependencies
- **Interactive Onboarding & Security Middleware (`domain/`, `middleware/`)**:
  - 4-step `CredentialSetupWizard` state machine (`person_code` → `password` → `email` → `totp_secret`)
  - `AuthorizationService`, `createAuthMiddleware`, and `redactSecrets` / `createRedactingLogger`

## Documentation

1. [Phase 0: Baseline Audit & Ownership Map](./docs/00-baseline-audit-and-ownership-map.md)
2. [Architecture & Boundary Purification](./docs/01-architecture-analysis-and-coupling-report.md)
3. [Clean Architecture & Cryptography Design](./docs/02-clean-architecture-and-refactoring-strategy.md)
4. [Public API & Usage Examples](./docs/03-public-api-and-usage-examples.md)
