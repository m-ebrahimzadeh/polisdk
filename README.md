# PoliSDK Monorepo

**PoliSDK** is a modular, Clean Architecture TypeScript platform providing reusable libraries for Politecnico di Milano authentication and student services.

## Packages

| Package | Description | Path |
|---|---|---|
| [`@polisdk/poliauth`](./packages/poliauth) | Standalone, platform-agnostic authentication core: PoliMi SSO & 2FA TOTP/OTP orchestration, Web Crypto AES-256-GCM credential & session vault, federated SAML 2.0 SSO, DOM adapters, and RBAC middleware. | `packages/poliauth` |

## Repository Structure

```text
polisdk/
├── package.json
├── tsconfig.base.json
├── vitest.config.ts
└── packages/
    └── poliauth/
        ├── src/           # Unified PoliAuth client & package entrypoints
        ├── domain/        # Pure domain entities, credential rules, RFC 6238 TOTP & SSO specs
        ├── application/   # Stateful use cases (PoliAuthOrchestrator, OtpChallengeCoordinator, Wizard, Authz)
        ├── interfaces/    # Hexagonal ports (Driver, Storage, Crypto, OTP, Authz, Logger)
        ├── adapters/      # Pure DOM adapters (PoliMi SSO, Federated SAML SSO, DomAuthPageDriver)
        ├── middleware/    # Framework-agnostic auth middleware & secret redaction
        ├── storage/       # Pure Web Crypto PBKDF2 + AES-256-GCM Vault & In-Memory adapters
        ├── tests/         # Unit & integration test suite (Vitest + JSDOM)
        └── docs/          # Architecture audit, Clean Architecture design & API docs
```

## Quick Commands

```bash
# Install dependencies
npm install

# Type-check all packages
npm run typecheck

# Build all packages
npm run build

# Run unit and integration test suites
npm test
```
