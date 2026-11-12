# PoliSDK Monorepo

**PoliSDK** is a modular, Clean Architecture TypeScript platform providing reusable libraries for Politecnico di Milano automation, authentication, and student services.

## Packages

| Package | Description | Path |
|---|---|---|
| [`@polisdk/poliauth`](./packages/poliauth) | Standalone authentication, 2FA TOTP/OTP, AES-256-GCM credential & session vault, multi-user Playwright session pool, federated Webex SAML 2.0 SSO, and RBAC middleware. | `packages/poliauth` |

## Repository Structure

```text
polisdk/
├── package.json
├── tsconfig.base.json
├── vitest.config.ts
└── packages/
    └── poliauth/
        ├── src/           # Unified PoliAuth client & package entrypoints
        ├── domain/        # Pure domain logic (Orchestrator, TOTP, Wizard, Authz, ServiceRegistry)
        ├── interfaces/    # Hexagonal ports (Driver, Storage, Crypto, OTP, Authz, Logger)
        ├── adapters/      # Playwright, Chrome Extension, JSDOM, PoliMi & Webex SSO DOM adapters
        ├── middleware/    # Framework-agnostic & Telegram auth middleware + secret redaction
        ├── storage/       # PBKDF2 + AES-256-GCM Vault, SQLite, Chrome Storage, In-Memory adapters
        ├── tests/         # Unit & integration test suite (Vitest + JSDOM + SQLite)
        └── docs/          # Architecture analysis, Clean Architecture design, API docs & migration guide
```

## Quick Commands

```bash
# Install dependencies
npm install

# Type-check all packages
npm run typecheck

# Build all packages (ESM + TypeScript declarations + IIFE injected browser bundle)
npm run build

# Run unit and integration test suites
npm test
```
