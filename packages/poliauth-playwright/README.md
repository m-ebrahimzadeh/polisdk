# `@polisdk/poliauth-playwright`

Playwright browser driver (`PlaywrightAuthPageDriver`), multi-tenant `BrowserContext` session pool (`PlaywrightBrowserSessionPool`), precompiled DOM adapter injection bundle, and read-only live portal verification probe (`runPolimiLivePortalProbe`) for [`@polisdk/poliauth`](../poliauth).

## Key Features

- **`PlaywrightAuthPageDriver`**: Implements `AuthPageDriverPort` over any Playwright `Page`, automatically injecting `window.__PoliAuthAdapters` and guarding against transient execution-context destruction across SAML/JAF redirects.
- **`PlaywrightBrowserSessionPool`**: Implements `SessionContextPoolPort` with per-user cookie isolation, reference-counted locks, LRU capacity eviction, idle TTL cleanup, and encrypted `storageState` persistence.
- **Zero Runtime Build Dependencies**: The browser-injected IIFE bundle is precompiled at build time into `src/generated/injected-bundle-code.ts`, eliminating runtime dependencies on `esbuild` or `node:fs`.
- **Live Portal Probe & Telemetry Profiler (`runPolimiLivePortalProbe`, `formatLivePortalProbeReportMarkdown`, `isLivePortalProbeEnabled`)**:
  - Read-only diagnostic harness that inspects Politecnico di Milano Stage 0 (`/aunicalogin/` expired-session trap & `recoverSessionPage()` recovery) and Stage 0 -> 0.5 -> 1 (`getservizio.xml?id_servizio=376` -> `IdentificazioneUnica.do` / `aunicalogin.jsp`), captures HTTP redirect chains, `Location` and `Content-Security-Policy` headers, adapter injection method (`'evaluate' | 'addScriptTag' | 'pre_injected'`), and selector/JAF trap presence derived exclusively from `POLIMI_LOGIN_FLOW_SPEC`.
  - Scrubs all URLs, headers, and DOM error banners through `redactSecrets` / `redactSensitiveErrorText`, and never submits credentials or OTP codes.
  - Formats deterministic Markdown tables via `formatLivePortalProbeReportMarkdown(report)` matching `packages/poliauth/docs/06-live-polimi-website-verification-ledger.md`.

## Opt-In Live Portal Verification

```bash
# Run offline unit & mock tests (default hermetic CI)
npm test

# Opt in to run the live Politecnico di Milano portal probe (Stage 0 + Stage 1)
npm run probe:live
# or on POSIX shells:
POLIAUTH_LIVE_PROBE=1 npm run probe:live
```
