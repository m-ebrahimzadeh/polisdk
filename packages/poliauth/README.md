# `@polisdk/poliauth`

Standalone, platform-agnostic authentication, 2FA (RFC 6238 TOTP & manual OTP), session state encryption, federated SAML 2.0 SSO, Web Crypto AES-256-GCM credential vault, and RBAC authorization core library for the **PoliSDK** platform.

## Clean Architecture Layers

- **Enterprise Domain (`domain/`)**:
  - Pure models (`IdentityId`, `LoginCredentials`, `SavedVaultCredentials`, `UserIdentity`), credential validation/masking (`credentials.ts`), RFC 6238 TOTP (`totp.ts`), and PoliMi SSO specification (`POLIMI_LOGIN_FLOW_SPEC`).
- **Application Use Cases (`application/`)**:
  - `PoliAuthOrchestrator` (`authenticate`, `authenticateFederatedSaml`), `OtpChallengeCoordinator`, `CredentialSetupWizard`, and `AuthorizationService`.
- **Hexagonal Ports (`interfaces/`)**:
  - `AuthPageDriverPort`, `SessionContextPoolPort`, `VaultStoragePort`, `SessionStateStorePort`, `UserIdentityRepositoryPort`, `OtpChallengeProviderPort`, `AuthorizationServicePort`, `AuthLoggerPort`.
- **Web-Standard Storage (`storage/`)**:
  - Pure Web Crypto API (`crypto.subtle`) PBKDF2-HMAC-SHA256 (`100,000` iterations) + AES-256-GCM encryption for credentials and session states (`EncryptedCredentialVault`, `InMemoryVaultStorage`).
- **DOM Adapters & Middleware (`adapters/`, `middleware/`)**:
  - `polimi-dom-adapter`, `webex-sso-dom-adapter`, `DomAuthPageDriver`, `createAuthMiddleware`, and `redactSecrets` / `createRedactingLogger`.

## Documentation

1. [Phase 0: Baseline Audit & Ownership Map](./docs/00-baseline-audit-and-ownership-map.md)
2. [Architecture & Boundary Purification](./docs/01-architecture-analysis-and-coupling-report.md)
3. [Clean Architecture & Cryptography Design](./docs/02-clean-architecture-and-refactoring-strategy.md)
4. [Public API & Usage Examples](./docs/03-public-api-and-usage-examples.md)
5. [Interface & Extensibility Review](./docs/04-interface-and-extensibility-review.md)
6. [Final Architecture Validation & Scorecard](./docs/05-final-architecture-validation-and-scorecard.md)
