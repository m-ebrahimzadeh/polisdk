# Phase 6 — Live Politecnico di Milano Website Verification Ledger

## 1. Purpose & Epistemic Classification Rules (Law 3, Law 4 & Principle 3)

This ledger is the **Single Source of Truth** for empirical verification of Politecnico di Milano's Identity Provider (`aunicalogin.polimi.it`, `shibidp.polimi.it`, `idp.polimi.it`) and portal endpoints (`servizionline.polimi.it`) in accordance with **PoliSDK — Living Design Specification (v1.1) Section 4.1 & Section 4.2**.

Every technical assertion and stage verification entry in this ledger strictly separates synthetic JSDOM fixture execution from live HTTPS portal probing using the mandatory epistemic tags:

- **`[FACT:CODE]`**: Confirmed by direct read-only inspection of source files (`POLIMI_LOGIN_FLOW_SPEC`, `PolimiDomAdapter`, `PlaywrightAuthPageDriver`, `live-portal-probe.ts`, `entities.ts`, `login-orchestrator.ts`).
- **`[FACT:EXEC]`**: Confirmed by automated monorepo build, strict `NodeNext` typecheck, or offline synthetic Vitest + JSDOM test execution (`EXIT=0`).
- **`[FACT:LIVE]`**: Confirmed by a timestamped automated Playwright probe executed against the live Politecnico di Milano portal (`npm run probe:live` read-only or `npm run probe:live:auth` opt-in single-attempt authenticated E2E).
- **`[ASSUMPTION:UNVERIFIED]`**: Historically observed or expected live portal behavior that has not yet been confirmed by an automated `[FACT:LIVE]` probe in the current suite (for example, live federated SAML SP endpoints such as Webex or WeBeep).

---

## 2. Running the Opt-In Live Portal Probes Safely

The `@polisdk/poliauth-playwright` package provides `runPolimiLivePortalProbe`, `runAuthenticatedPolimiLivePortalProbe`, `loadLiveProbeCredentialsFromEnv`, and `formatLivePortalProbeReportMarkdown` (`packages/poliauth-playwright/src/live-portal-probe.ts`), wired into the monorepo via `probe:live` and `probe:live:auth`.

### Commands

```bash
# 1. Read-only live probe (Stages 0 -> Recovery -> Stage 1, zero credentials)
npm run probe:live

# 2. Opt-in authenticated .env live E2E probe (Stages 0 -> 1 -> 2 -> 3, strict 1-attempt cap)
# First copy .env.example to .env and populate real test credentials
npm run probe:live:auth

# Equivalent explicit environment invocations on POSIX shells
POLIAUTH_LIVE_PROBE=1 npm run probe:live
POLIAUTH_LIVE_PROBE=1 POLIAUTH_LIVE_AUTH_PROBE=1 npm run probe:live:auth

# Optional custom Chromium binary path override
PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/path/to/chrome npm run probe:live
```

### Mandatory Safety, Anti-Lockout & Redaction Invariants

1. **Zero Credential Submission by Default (`probe:live`):** `runPolimiLivePortalProbe` with default options (`probeAuthenticatedFlow` unset/false) is **100% read-only** with respect to user credentials and never invokes `submitCredentials()` or `submitOtp()`.
2. **Single-Attempt Anti-Lockout Circuit Breaker (`probe:live:auth`, Hard-Stop Trigger 7):** When `POLIAUTH_LIVE_AUTH_PROBE=1` (`runAuthenticatedPolimiLivePortalProbe`), `.env` credentials (`POLIAUTH_PERSON_CODE`, `POLIAUTH_PASSWORD`, `POLIAUTH_TOTP_SECRET`, optional `POLIAUTH_EMAIL`) are loaded strictly in Node runtime via `loadLiveProbeCredentialsFromEnv()`. Both Stage 1 (`submitCredentials`) and Stage 2 (`submitOtp`) enforce a **hard 1-attempt cap** (`maxAttempts = 1`), compute TOTP via `generateStableTotp(secret, { minRemainingSeconds: 5 })` to prevent 30s window boundary rollovers, and **halt immediately with zero retries** if any error banner or submission failure occurs.
3. **Hermetic Default CI (`npm test`):** When `POLIAUTH_LIVE_PROBE` and `POLIAUTH_LIVE_AUTH_PROBE` are unset or not `'1'`, `packages/poliauth-playwright/tests/live-portal-probe.test.ts` runs exclusively offline against deterministic JSDOM/mock browser harnesses with zero network calls and zero skipped tests.
4. **Mandatory Secret Redaction (Law 5):** All loaded credential values (`personCode`, `password`, `totpSecret`, `polimiEmail`) and any generated 6-digit TOTP code are dynamically registered into custom `RedactionRule[]` + `extraSecrets` alongside built-in token scrubbers (`__pj1`, `jaf_currentWFID`, `ticket`, `SAMLRequest`, `SAMLResponse`, `password`, `otp`, `totpSecret`) via Layer 1 `redactSecrets` and `redactSensitiveErrorText` (`packages/poliauth/domain/redaction.ts`). No raw secret can appear in telemetry records, logs, exceptions, or Markdown tables.
5. **Centralized Selector Derivation & Drift Disambiguation (`TASK-6.2`):** All DOM presence checks and `POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators` outage signatures come exclusively from `POLIMI_LOGIN_FLOW_SPEC` (`packages/poliauth/domain/login-flow-spec.ts`), and ambiguous/failing states are deterministically classified via `classifyPolimiFailure` (`PORTAL_OUTAGE_OR_NETWORK_ERROR` vs. `DOM_SELECTOR_DRIFT` vs. `AUTHENTICATION_REJECTED` / `OTP_CHALLENGE_FAILED` / `TARGET_CLOSED`) wrapped in `PoliAuthDiagnosticError`.

---

## 3. Politecnico di Milano Stage & Federated SSO Verification Matrix (`Spec v1.1 Sec 4.2`)

| Behavior / Stage Identifier | Synthetic Test Status (`[FACT:EXEC]`) | Live Portal Probe Status | Test Method / Harness | Observed HTTP/DOM Behavior & Known Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **Stage 0: Bare `/aunicalogin/` Expired-Session Trap & Recovery** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | **`VERIFIED_LIVE`** (`[FACT:LIVE]`, Run 1 & Run 2 `2026-11-13T18:26:38Z`) | Synthetic: `dom-adapters.test.ts`, `live-portal-probe.test.ts`; Live: `npm run probe:live` / `probe:live:auth` (Chrome) | Bare `https://aunicalogin.polimi.it/aunicalogin/` returned HTTP `200` displaying `.poli-messages .alert-danger .jaf-message` (`Violazione della sicurezza`) with `hasExpiredSessionMarker=true`, CSP `frame-ancestors 'self' https://*.polimi.it`, and zero inline continue anchors. Following `PlaywrightAuthPageDriver.recoverSessionPage()` fallback fix (`ok: true` when `goto(serviceEntryUrl)` succeeds), `stage_0_session_recovery` reported `ok=true` and redirected `getservizio.xml?id_servizio=376` (`302`) -> `aunicalogin.jsp?...&__pj1=[REDACTED]` (`credentials`). |
| **Stage 0.5: `AunicaLogin.do` / `LoginExtensionPoint.do` Intermediate Handoff** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | **`VERIFIED_LIVE` HTTP 302 Chain** (`[FACT:LIVE]`, Run 2 `2026-11-13T18:26:40Z`); HTML auto-submit form `HISTORICALLY_OBSERVED` (`[ASSUMPTION:UNVERIFIED]`) | Synthetic: `dom-adapters.test.ts`, `live-portal-probe.test.ts`; Live: `npm run probe:live:auth` | In fresh authenticated Run 2, submitting OTP on `IdentificazioneDFA.do` bypassed an intermediate HTML form and performed a direct HTTP `302` chain via `controller/passi/IdentificazioneDFA.do` -> `controller/passi/LoginExtensionPoint.do` -> `servizionline.polimi.it/portaleservizi/?ticket=[REDACTED]`. Intermediate HTML `sso_handoff` form (`AunicaLogin.do`) remains verified synthetically. |
| **Stage 1: `aunicalogin.jsp` / `IdentificazioneUnica.do` & `.jaf-visually-hidden` Trap** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | **`VERIFIED_LIVE`** (`[FACT:LIVE]`, Run 1 & Run 2 `2026-11-13T18:26:39Z`) | Synthetic: `dom-adapters.test.ts`, `live-portal-probe.test.ts`; Live: `npm run probe:live:auth` (Chrome) | `getservizio.xml?id_servizio=376` returned HTTP `302` -> `aunicalogin.jsp` (`200 OK`, CSP `frame-ancestors 'self' https://*.polimi.it`). DOM verified `#login`, `#password`, visible submit, and `.jaf-visually-hidden` trap. Submitting credentials once (`attempt 1/1`) transitioned via `IdentificazioneUnica.do` (`200 OK`) directly into Stage 2 (`otp`). |
| **Stage 2: `IdentificazioneDFA.do` / `form#form_scelta2fa` & `#submit-dissms` Empirical Audit** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | **`VERIFIED_LIVE`** (`[FACT:LIVE]`, Run 2 `2026-11-13T18:26:40Z`) | Synthetic: `dom-adapters.test.ts`, `totp.test.ts`, `live-portal-probe.test.ts`; Live: `npm run probe:live:auth` | **Empirical DOM Button Inventory (`form#form_scelta2fa`):** Only 2 submit controls existed on live App-TOTP Stage 2: Index `0` `button[name="evn_continua"].jaf-visually-hidden` (hidden JAF trap) and Index `1` `button#submit-dissms[name="evn_continua"].btn.btn-primary.jaf-btn.jaf-btn-big` (`"Continua"`), with **no other visible `evn_continua` button**. `POLIMI_LOGIN_FLOW_SPEC.otpPage.submitButtonSelector` prioritizes `button[name="evn_continua"]:not(#submit-dissms):not(.jaf-visually-hidden)` and `findPreferredButton()` safely falls back to visible `#submit-dissms` (`fallbackSubmitButtonSelector`). Single TOTP submission (`minRemainingSeconds=5`) succeeded (`302`). |
| **Stage 3: `servizionline.polimi.it` / `.cercaServizio` Authenticated Landing** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | **`VERIFIED_LIVE`** (`[FACT:LIVE]`, Run 2 `2026-11-13T18:26:41Z`) | Synthetic: `dom-adapters.test.ts`, `login-orchestrator.test.ts`, `live-portal-probe.test.ts`; Live: `npm run probe:live:auth` | Completed full redirect chain into `https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do?jaf_currentWFID=[REDACTED]&EVN_SHOW_PORTALE=evento` (`HTTP 200`, CSP `frame-ancestors 'self' https://*.polimi.it`, adapter injection `'pre_injected'`), confirming `inspectedStage='authenticated'` and `hasAuthenticatedMarker=true` (`.cercaServizio` / `Logout.do` / `.jaf-user-info`). |
| **Outage vs. Selector Drift Disambiguation (`TASK-6.2`)** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | `SYNTHETIC_FAILURE_INJECTION_VERIFIED` (`[FACT:EXEC]`) | Synthetic: `dom-adapters.test.ts`, `login-orchestrator.test.ts`, `live-portal-probe.test.ts` | `classifyPolimiFailure()` and `PoliAuthDiagnosticError` deterministically separate `PORTAL_OUTAGE_OR_NETWORK_ERROR` (HTTP `500/502/503/504`, `ETIMEDOUT`/`ERR_*`, maintenance banners, empty bodies) from `DOM_SELECTOR_DRIFT` (populated HTTP `200` known IdP host with unrecognized/missing selectors), short-circuiting `PoliAuthOrchestrator` without spurious retries and scrubbing secrets. |
| **Federated SSO (Modes A `identifierPrompt`, B `loginTrigger`, C Direct Redirect)** | `VERIFIED_JSDOM_FIXTURE` (`[FACT:EXEC]`) | `HISTORICALLY_OBSERVED — PENDING_LIVE_SP_PROBE` (`[ASSUMPTION:UNVERIFIED]`) | Synthetic: `dom-adapters.test.ts`, `login-orchestrator.test.ts`, `playwright-driver-and-pool.test.ts`, `chrome-adapters.test.ts` | Unauthenticated Service Provider discovery/trigger pages (e.g., Webex `doSSO.jsp`, WeBeep `/login/index.php`) are verified via JSDOM fixtures; live external SP assertion flows were not executed in Run 2 (`id_servizio=376`). |

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

---

### Run 2 — `2026-11-13T18:26:38.078Z` (`npm run probe:live:auth`, Playwright Chrome Channel, Authenticated E2E `.env` Single-Attempt Probe)

### Automated Portal Probe Telemetry (2026-11-13T18:26:38.078Z)

- **Environment:** `live_network`
- **Overall Success:** `true`
- **Stages Probed:** `5` (`Stage 0 -> Recovery -> Stage 1 -> Stage 2 (2FA OTP) -> Stage 3 Authenticated`)
- **Credentials Redaction:** Person code, password, TOTP secret, email, and live generated 6-digit OTP registered dynamically into `RedactionRule[]` + `extraSecrets` (`[REDACTED]`); zero secret strings leaked in logs or telemetry.

#### Stage Telemetry & Redirect Matrix

| Probe | Target URL | Final URL | Inspected Stage | Adapter Injection | Redirect Hops | CSP Headers | Duration (ms) | Epistemic Status |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- | :---: | :--- |
| `stage_0_bare_aunicalogin` | `https://aunicalogin.polimi.it/aunicalogin/` | `https://aunicalogin.polimi.it/aunicalogin/` | `session_expired` | `evaluate` | 1 | frame-ancestors 'self' https://*.polimi.it | 728 | `[FACT:LIVE]` |
| `stage_0_session_recovery` | `https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376` | `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` | `credentials` | `evaluate` | 2 | frame-ancestors 'self' https://*.polimi.it | 614 | `[FACT:LIVE]` |
| `stage_1_service_entry_credentials` | `https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376` | `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` | `credentials` | `evaluate` | 2 | frame-ancestors 'self' https://*.polimi.it | 527 | `[FACT:LIVE]` |
| `stage_1_credentials_submit_to_otp` | `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` | `https://aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/IdentificazioneUnica.do?&jaf_currentWFID=[REDACTED]&polij_step=0&__pj0=0&__pj1=[REDACTED]` | `otp` | `pre_injected` | 1 | frame-ancestors 'self' https://*.polimi.it | 481 | `[FACT:LIVE]` |
| `stage_2_otp_submit_to_authenticated` | `https://aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/IdentificazioneUnica.do?&jaf_currentWFID=[REDACTED]&polij_step=0&__pj0=0&__pj1=[REDACTED]` | `https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do?jaf_currentWFID=[REDACTED]&EVN_SHOW_PORTALE=evento` | `authenticated` | `pre_injected` | 4 | frame-ancestors 'self' https://*.polimi.it | 1434 | `[FACT:LIVE]` |

#### DOM Selector & Trap Audit Matrix

| Probe | `#login` | `#password` | Visible Submit | JAF Trap | `#otp` | `#submit-dissms` | SSO Handoff | Expired Marker | Auth Marker | Error Banner | Sanitized Error |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `stage_0_bare_aunicalogin` | false | false | false | false | false | false | false | true | false | true | `Violazione della sicurezza` |
| `stage_0_session_recovery` | true | true | true | true | false | false | false | false | false | false | — |
| `stage_1_service_entry_credentials` | true | true | true | true | false | false | false | false | false | false | — |
| `stage_1_credentials_submit_to_otp` | false | false | false | true | true | true | false | false | false | false | — |
| `stage_2_otp_submit_to_authenticated` | false | false | false | false | false | false | false | false | true | false | — |

#### Stage 2 Button Inventory (`form#form_scelta2fa`)

| Probe | Index | Tag | `id` | `name` | `type` | Visible | Text | Matches Primary OTP | `#submit-dissms` Trap | JAF Hidden Trap | Classes |
| :--- | :---: | :--- | :--- | :--- | :--- | :---: | :--- | :---: | :---: | :---: | :--- |
| `stage_1_credentials_submit_to_otp` | 0 | `button` | — | `evn_continua` | `submit` | true | `—` | false | false | true | `jaf-visually-hidden` |
| `stage_1_credentials_submit_to_otp` | 1 | `button` | `submit-dissms` | `evn_continua` | `submit` | true | `Continua` | false | true | false | `btn btn-primary jaf-btn jaf-btn-big` |

> `[FACT:LIVE]` Empirical finding: Live `form#form_scelta2fa` renders only the `.jaf-visually-hidden` default button at index `0` and `button#submit-dissms` (`"Continua"`) at index `1` on the standard App-TOTP flow. Keeping `#submit-dissms` in `fallbackSubmitButtonSelector` via `findPreferredButton()` allowed `submitPolimiOtp()` to bypass the `.jaf-visually-hidden` trap and submit Stage 2 cleanly without requiring an unrendered third button.

#### Redirect Hops & Probe Notes

- **`stage_0_bare_aunicalogin`** (`[FACT:LIVE]` HTTP 200):
  - Hop 0: HTTP 200 `https://aunicalogin.polimi.it/aunicalogin/` (2026-11-13T18:26:38.272Z)
- **`stage_0_session_recovery`** (`[FACT:LIVE]` HTTP 200):
  - Hop 0: HTTP 302 `https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376` -> Location: `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` (2026-11-13T18:26:38.866Z)
  - Hop 1: HTTP 200 `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` (2026-11-13T18:26:39.024Z)
  - Note: `recoverSessionPage() ok=true navigatedTo=https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376`
- **`stage_1_service_entry_credentials`** (`[FACT:LIVE]` HTTP 200):
  - Hop 0: HTTP 302 `https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376` -> Location: `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` (2026-11-13T18:26:39.480Z)
  - Hop 1: HTTP 200 `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=[REDACTED]` (2026-11-13T18:26:39.624Z)
- **`stage_1_credentials_submit_to_otp`** (`[FACT:LIVE]` HTTP 200):
  - Hop 0: HTTP 200 `https://aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/IdentificazioneUnica.do?&jaf_currentWFID=[REDACTED]&polij_step=0&__pj0=0&__pj1=[REDACTED]` (2026-11-13T18:26:40.242Z)
  - Note: Submitted Stage 1 credentials (attempt 1/1).
- **`stage_2_otp_submit_to_authenticated`** (`[FACT:LIVE]` HTTP 200):
  - Hop 0: HTTP 302 `https://aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/passi/IdentificazioneDFA.do?jaf_currentWFID=[REDACTED]&polij_step=0&__pj0=0&__pj1=[REDACTED]` -> Location: `https://aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/passi/LoginExtensionPoint.do?jaf_currentWFID=[REDACTED]&EVN_DEFAULT=evento` (2026-11-13T18:26:40.663Z)
  - Hop 1: HTTP 302 `https://aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/passi/LoginExtensionPoint.do?jaf_currentWFID=[REDACTED]&EVN_DEFAULT=evento` -> Location: `https://servizionline.polimi.it/portaleservizi/?ticket=[REDACTED]&profile=0&al_id_srv=376&returnURL=...&lang=IT&__pj0=0&__pj1=[REDACTED]` (2026-11-13T18:26:40.711Z)
  - Hop 2: HTTP 302 `https://servizionline.polimi.it/portaleservizi/?ticket=[REDACTED]&profile=0&al_id_srv=376&returnURL=...&lang=IT&__pj0=0&__pj1=[REDACTED]` -> Location: `https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do?jaf_currentWFID=[REDACTED]&EVN_SHOW_PORTALE=evento` (2026-11-13T18:26:41.211Z)
  - Hop 3: HTTP 200 `https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do?jaf_currentWFID=[REDACTED]&EVN_SHOW_PORTALE=evento` (2026-11-13T18:26:41.580Z)
  - Note: Submitted Stage 2 TOTP (attempt 1/1; `minRemainingSeconds=5`; `remainingSeconds=20`; `waitedMs=0`).
