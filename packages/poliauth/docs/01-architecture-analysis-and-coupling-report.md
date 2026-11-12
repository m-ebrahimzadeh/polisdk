# Architecture & Boundary Purification Report (`@polisdk/poliauth`)

## 1. Executive Summary

`@polisdk/poliauth` is the standalone authentication core of the **PoliSDK** platform. In Phases 1 and 2, all legacy application coupling, runtime-specific infrastructure (`better-sqlite3`, `playwright`, `chrome.*`, `esbuild`, `node:fs`, `node:crypto`), Telegram bot assumptions, and downstream portal service navigation concerns were purged, and stateful use cases were cleanly separated into `application/` distinct from `domain/`.

---

## 2. Layered Dependency Graph (`domain/` vs. `application/`)

```mermaid
flowchart TD
  subgraph Facade["Package Entrypoint (src/)"]
    Index["src/index.ts"]
    Client["src/poliauth-client.ts (PoliAuth)"]
  end

  subgraph Application["Application Layer Use Cases (application/)"]
    OtpCoord["application/otp-challenge.ts"]
    Wizard["application/credential-wizard.ts"]
    Authz["application/authorization.ts"]
    Orch["application/login-orchestrator.ts"]
  end

  subgraph Domain["Pure Enterprise Domain (domain/)"]
    Entities["domain/entities.ts"]
    Creds["domain/credentials.ts"]
    FlowSpec["domain/login-flow-spec.ts"]
    Totp["domain/totp.ts"]
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
  Client --> Application
  Client --> Domain
  Client --> Storage
  Client --> Middleware
  Application --> Domain
  Application --> Ports
  Domain --> CryptoPort
  Storage --> Domain
  Storage --> Ports
  Adapters --> Domain
  Adapters --> Ports
  Middleware --> Ports
```

---

## 3. Domain vs. Application Layer Separation

| Layer | Directory | Files | Responsibilities |
| :--- | :--- | :--- | :--- |
| **Enterprise Domain** | `domain/` | `entities.ts`, `credentials.ts`, `totp.ts`, `login-flow-spec.ts` | Stateless models, value objects, credential validation/masking rules, RFC 6238 TOTP computation, and PoliMi SSO protocol specification. |
| **Application Use Cases** | `application/` | `login-orchestrator.ts`, `otp-challenge.ts`, `credential-wizard.ts`, `authorization.ts` | Stateful workflow orchestration (`PoliAuthOrchestrator`), asynchronous 2FA challenge coordination (`OtpChallengeCoordinator`), onboarding wizard state machine (`CredentialSetupWizard`), and RBAC/resource authorization (`AuthorizationService`). |
