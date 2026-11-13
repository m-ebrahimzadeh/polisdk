# `@polisdk/poliauth-playwright`

Playwright browser driver (`PlaywrightAuthPageDriver`), multi-tenant `BrowserContext` session pool (`PlaywrightBrowserSessionPool`), precompiled DOM adapter injection bundle, and live portal verification harnesses (`runPolimiLivePortalProbe`, `runAuthenticatedPolimiLivePortalProbe`) for [`@polisdk/poliauth`](../poliauth).

## Key Features

- **`PlaywrightAuthPageDriver`**: Implements `AuthPageDriverPort` over any Playwright `Page`, automatically injecting `window.__PoliAuthAdapters`, capturing navigation HTTP status codes, distinguishing `PORTAL_OUTAGE_OR_NETWORK_ERROR` from `DOM_SELECTOR_DRIFT` via `PoliAuthDiagnosticError`, and guarding against transient execution-context destruction across SAML/JAF redirects.
- **`PlaywrightBrowserSessionPool`**: Implements `SessionContextPoolPort` with per-user cookie isolation, reference-counted locks, LRU capacity eviction, idle TTL cleanup, and encrypted `storageState` persistence.
- **Zero Runtime Build Dependencies**: The browser-injected IIFE bundle is precompiled at build time into `src/generated/injected-bundle-code.ts`, eliminating runtime dependencies on `esbuild` or `node:fs`.
- **Live Portal Probe & Telemetry Profiler (`runPolimiLivePortalProbe`, `runAuthenticatedPolimiLivePortalProbe`, `loadLiveProbeCredentialsFromEnv`, `formatLivePortalProbeReportMarkdown`, `isLivePortalProbeEnabled`, `isLiveAuthPortalProbeEnabled`)**:
  - Default `runPolimiLivePortalProbe` is a read-only diagnostic harness inspecting Stage 0 (`/aunicalogin/` expired-session trap & `recoverSessionPage()` recovery) and Stage 0 -> 0.5 -> 1 (`getservizio.xml?id_servizio=376` -> `IdentificazioneUnica.do` / `aunicalogin.jsp`), capturing HTTP redirect chains, `Location` and `Content-Security-Policy` headers, adapter injection method (`'evaluate' | 'addScriptTag' | 'pre_injected'`), Stage 2 `form#form_scelta2fa` button inventories, and selector/trap presence derived exclusively from `POLIMI_LOGIN_FLOW_SPEC`.
  - Opt-in `runAuthenticatedPolimiLivePortalProbe` loads `.env` test credentials via `loadLiveProbeCredentialsFromEnv`, enforces a strict **1-attempt circuit breaker** (`generateStableTotp(..., { minRemainingSeconds: 5 })` + immediate halt on error banner), and registers all credential fields + generated OTP into custom `RedactionRule[]` + `extraSecrets` (`[REDACTED]`).
  - Scrubs all URLs, headers, DOM error banners, and exceptions through `redactSecrets` / `redactSensitiveErrorText`, and formats deterministic Markdown tables via `formatLivePortalProbeReportMarkdown(report)` matching `packages/poliauth/docs/06-live-polimi-website-verification-ledger.md`.

## Opt-In Live Portal Verification

```bash
# Run offline unit & mock tests (default hermetic CI)
npm test

# Opt in to run the read-only live Politecnico di Milano portal probe (Stage 0 + Stage 1)
npm run probe:live

# Opt in to run the single-attempt authenticated .env E2E probe (Stages 0 -> 1 -> 2 -> 3)
# Copy .env.example to .env first
npm run probe:live:auth

# Equivalent POSIX shells:
POLIAUTH_LIVE_PROBE=1 npm run probe:live
POLIAUTH_LIVE_PROBE=1 POLIAUTH_LIVE_AUTH_PROBE=1 npm run probe:live:auth
```
