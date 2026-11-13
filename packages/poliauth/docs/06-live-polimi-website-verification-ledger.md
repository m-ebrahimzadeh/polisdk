# Phase 6 — Live Politecnico di Milano Website Verification Ledger

## 1. Purpose & Epistemic Classification Rules (Law 3, Law 4 & Principle 3)

This ledger is the **Single Source of Truth** for empirical verification of Politecnico di Milano's Identity Provider (`aunicalogin.polimi.it`, `shibidp.polimi.it`, `idp.polimi.it`) and portal endpoints (`servizionline.polimi.it`) in accordance with **PoliSDK — Living Design Specification (v1.1) Section 4.1 & Section 4.2**.

Every technical assertion and stage verification entry in this ledger strictly separates synthetic JSDOM fixture execution from live HTTPS portal probing using the mandatory epistemic tags:

- **`[FACT:CODE]`**: Confirmed by direct read-only inspection of source files (`POLIMI_LOGIN_FLOW_SPEC`, `PolimiDomAdapter`, `PlaywrightAuthPageDriver`, `live-portal-probe.ts`).
- **`[FACT:EXEC]`**: Confirmed by automated monorepo build, strict `NodeNext` typecheck, or offline synthetic Vitest + JSDOM test execution (`EXIT=0`).
- **`[FACT:LIVE]`**: Confirmed by a timestamped, read-only automated Playwright probe executed against the live Politecnico di Milano portal.
- **`[ASSUMPTION:UNVERIFIED]`**: Historically observed or expected live portal behavior that has not yet been confirmed by an automated `[FACT:LIVE]` probe (for example, post-login Stage 2/3 pages that require real student credentials or an active SSO cookie).

---

## 2. Running the Opt-In Live Portal Probe Safely

The `@polisdk/poliauth-playwright` package provides `runPolimiLivePortalProbe` and `formatLivePortalProbeReportMarkdown` (`packages/poliauth-playwright/src/live-portal-probe.ts`), wired into the monorepo via the opt-in root script `probe:live`.

### Commands

```bash
# Cross-platform opt-in live probe (Windows, macOS, Linux)
npm run probe:live

# Equivalent explicit environment invocation on POSIX shells
POLIAUTH_LIVE_PROBE=1 npm run probe:live

# Optional custom Chromium binary path override
PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/path/to/chrome npm run probe:live
```

### Mandatory Safety & Redaction Invariants

1. **Zero Credential Submission (Hard-Stop Trigger 7):** `runPolimiLivePortalProbe` is **100% read-only** with respect to user credentials. It never invokes `submitCredentials()` or `submitOtp()` and does not accept passwords, person codes, or OTP secrets in `LivePortalProbeOptions`, eliminating any risk of Active Directory / Kerberos account lockouts on real student accounts.
2. **Hermetic Default CI (`npm test`):** When `POLIAUTH_LIVE_PROBE` is unset or not `'1'`, `packages/poliauth-playwright/tests/live-portal-probe.test.ts` runs exclusively offline against deterministic JSDOM/mock browser harnesses with zero network calls and zero skipped tests.
3. **Mandatory Secret Redaction (Law 5):** Every captured URL, redirect `Location` header, `Content-Security-Policy` header, error banner text, and exception message (`__pj1`, `jaf_currentWFID`, `ticket`, `SAMLRequest`, `SAMLResponse`, `password`, `otp`, `totpSecret`, etc.) is scrubbed through Layer 1 `redactSecrets` and `redactSensitiveErrorText` (`packages/poliauth/domain/redaction.ts`) before appearing in `LivePortalProbeReport` or Markdown output.
4. **Centralized Selector Derivation (Law 2):** All DOM presence checks (`#login`, `#password`, visible `evn_conferma`, `.jaf-visually-hidden` trap, `#otp`, `#submit-dissms`, `.cercaServizio`, `SessioneTerminata`) are derived dynamically from `POLIMI_LOGIN_FLOW_SPEC` (`packages/poliauth/domain/login-flow-spec.ts`) without scattering selectors in `@polisdk/poliauth-playwright`.

---

## 3. Politecnico di Milano Stage & Federated SSO Verification Matrix (`Spec v1.1 Sec 4.2`)

| Behavior / Stage Identifier | Synthetic Test Status (`[FACT:EXEC]`) | Live Portal Probe Status | Test Method / Harness | Observed HTTP/DOM Behavior & Known Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **Stage 0: Bare `/aunicalogin/` Expired-Session Trap & Recovery** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | **`VERIFIED_LIVE`** (`[FACT:LIVE]`, `2026-11-13T17:21:13.353Z`) | Synthetic: `dom-adapters.test.ts`, `live-portal-probe.test.ts`; Live: `npm run probe:live` (Chromium) | Requesting `https://aunicalogin.polimi.it/aunicalogin/` returned HTTP `200` directly on `/aunicalogin/` displaying `.poli-messages .alert-danger .jaf-message` (`Violazione della sicurezza`) with `hasExpiredSessionMarker=true`, `hasErrorBanner=true`, CSP `frame-ancestors 'self' https://*.polimi.it`, and zero recovery anchor links (`recoverSessionPage()` returned `ok=false` and fell back to `goto(serviceEntryUrl)`). Recovery via `getservizio.xml?id_servizio=376` immediately returned HTTP `302` -> `aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` (`credentials`). |
| **Stage 0.5: `AunicaLogin.do` / `evn_checkCookieSSO` Priority Detection** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | `HISTORICALLY_OBSERVED — REQUIRES_ACTIVE_SSO_COOKIE` (`[ASSUMPTION:UNVERIFIED]`) | Synthetic: `dom-adapters.test.ts`, `login-orchestrator.test.ts`; Live: Incognito unauthenticated probe | Clean incognito contexts without an active `aunicalogin` cookie transition directly from `getservizio.xml?id_servizio=376` (`302`) to `aunicalogin.jsp` (`credentials`). Live observation of `AunicaLogin.do` auto-submit requires an existing active SSO cookie context. |
| **Stage 1: `aunicalogin.jsp` / `IdentificazioneUnica.do` & `.jaf-visually-hidden` Trap** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | **`VERIFIED_LIVE`** (`[FACT:LIVE]`, `2026-11-13T17:21:13.353Z`) | Synthetic: `dom-adapters.test.ts`, `live-portal-probe.test.ts`; Live: `npm run probe:live` (Chromium) | `getservizio.xml?id_servizio=376` returned HTTP `302` -> `aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` (`200 OK`, CSP `frame-ancestors 'self' https://*.polimi.it`). `ensureAuthAdaptersInjected` succeeded via `'evaluate'`. DOM probe verified `hasLoginInput=true`, `hasPasswordInput=true`, `hasVisibleSubmitButton=true`, and `hasJafVisuallyHiddenTrap=true`. |
| **Stage 2: `IdentificazioneDFA.do` / 2FA OTP & `#submit-dissms`** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | `HISTORICALLY_OBSERVED — REQUIRES_AUTHENTICATED_CREDENTIALS` (`[ASSUMPTION:UNVERIFIED]`) | Synthetic: `dom-adapters.test.ts`, `totp.test.ts`, `live-portal-probe.test.ts` (`customUrlsToInspect`) | Live probe intentionally halts prior to credential submission (Hard-Stop Trigger 7). Note (`[FACT:CODE]`): `POLIMI_LOGIN_FLOW_SPEC.otpPage.submitButtonSelector` currently defines `'button#submit-dissms[name="evn_continua"], button[name="evn_continua"]:not(.jaf-visually-hidden)'` (targeting `#submit-dissms`), whereas Spec v1.1 Sec 4.1 notes `#submit-dissms` as an exclusion; confirm on live Stage 2 only during an explicit interactive operator session. |
| **Stage 3: `servizionline.polimi.it` / `.cercaServizio` Authenticated Landing** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | `HISTORICALLY_OBSERVED — REQUIRES_AUTHENTICATED_SESSION` (`[ASSUMPTION:UNVERIFIED]`) | Synthetic: `dom-adapters.test.ts`, `login-orchestrator.test.ts`, `live-portal-probe.test.ts` (`customUrlsToInspect`) | Requires completing Stage 1 + Stage 2 authentication to obtain a live `servizionline.polimi.it` session. |
| **Federated SSO (Modes A `identifierPrompt`, B `loginTrigger`, C Direct Redirect)** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | `HISTORICALLY_OBSERVED — PENDING_LIVE_SP_PROBE` (`[ASSUMPTION:UNVERIFIED]`) | Synthetic: `dom-adapters.test.ts`, `login-orchestrator.test.ts`, `playwright-driver-and-pool.test.ts`, `chrome-adapters.test.ts` | Unauthenticated Service Provider discovery/trigger pages (e.g., Webex `doSSO.jsp`, WeBeep `/login/index.php`) are verified via JSDOM fixtures; full end-to-end assertion completion requires Stage 1 + Stage 2 credentials. |

---

## 4. Timestamped Live Portal Probe Telemetry Log

### Run 1 — `2026-11-13T17:21:13.353Z` (`npm run probe:live`, Playwright Chromium Channel, Read-Only)

### Automated Portal Probe Telemetry (2026-11-13T17:21:13.353Z)

- **Environment:** `live_network`
- **Overall Success:** `true`
- **Stages Probed:** `3`

#### Stage Telemetry & Redirect Matrix

| Probe | Target URL | Final URL | Inspected Stage | Adapter Injection | Redirect Hops | CSP Headers | Duration (ms) | Epistemic Status |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- | :---: | :--- |
| `stage_0_bare_aunicalogin` | `https://aunicalogin.polimi.it/aunicalogin/` | `https://aunicalogin.polimi.it/aunicalogin/` | `session_expired` | `evaluate` | 1 | frame-ancestors 'self' https://*.polimi.it | 681 | `[FACT:LIVE]` |
| `stage_0_session_recovery` | `https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376` | `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` | `credentials` | `evaluate` | 2 | frame-ancestors 'self' https://*.polimi.it | 554 | `[FACT:LIVE]` |
| `stage_1_service_entry_credentials` | `https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376` | `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` | `credentials` | `evaluate` | 2 | frame-ancestors 'self' https://*.polimi.it | 330 | `[FACT:LIVE]` |

#### DOM Selector & Trap Audit Matrix

| Probe | `#login` | `#password` | Visible Submit | JAF Trap | `#otp` | `#submit-dissms` | SSO Handoff | Expired Marker | Auth Marker | Error Banner | Sanitized Error |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `stage_0_bare_aunicalogin` | false | false | false | false | false | false | false | true | false | true | `Violazione della sicurezza` |
| `stage_0_session_recovery` | true | true | true | true | false | false | false | false | false | false | — |
| `stage_1_service_entry_credentials` | true | true | true | true | false | false | false | false | false | false | — |

#### Redirect Hops & Probe Notes

- **`stage_0_bare_aunicalogin`** (`[FACT:LIVE]`):
  - Hop 0: HTTP 200 `https://aunicalogin.polimi.it/aunicalogin/` (2026-11-13T17:21:13.463Z)
- **`stage_0_session_recovery`** (`[FACT:LIVE]`):
  - Hop 0: HTTP 302 `https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376` -> Location: `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` (2026-11-13T17:21:14.086Z)
  - Hop 1: HTTP 200 `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` (2026-11-13T17:21:14.231Z)
  - Note: recoverSessionPage() ok=false navigatedTo=https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376
- **`stage_1_service_entry_credentials`** (`[FACT:LIVE]`):
  - Hop 0: HTTP 302 `https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376` -> Location: `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` (2026-11-13T17:21:14.640Z)
  - Hop 1: HTTP 200 `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` (2026-11-13T17:21:14.738Z)
