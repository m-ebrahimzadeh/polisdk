# Clean Architecture & Cryptographic Design (`@polisdk/poliauth`)

## 1. Strict Separation of Authentication vs. Downstream Services

`@polisdk/poliauth` enforces a strict boundary between **authentication** and **application service navigation**:
- Authentication begins at `POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl` (`id_servizio=376`), recovers expired sessions (`SessioneTerminata`), submits credentials (`IdentificazioneUnica.do`), completes 2FA (`IdentificazioneDFA.do`), and terminates immediately upon establishing an **authenticated PoliMi session** (`stage === 'authenticated'`).
- `@polisdk/poliauth` never automatically navigates to downstream student services (such as Recordings Archive, WeBeep, or Career portals).

---

## 2. Unified Web Standard Cryptography (`storage/vault.ts`)

Both user credentials (`SavedVaultCredentials`) and serialized session states (`SessionStateStorePort`) use a single, coherent, platform-independent cryptographic pipeline built exclusively on the standard **Web Crypto API (`globalThis.crypto.subtle`)**:

1. **Key Derivation**:
   - Algorithm: `PBKDF2-HMAC-SHA256`
   - Iterations: `100,000`
   - Salt: `16` cryptographically random bytes (`crypto.getRandomValues`), persisted alongside the ciphertext in `VaultMetadata` (`version: 1`)
   - Domain Separation:
     - Credentials: `PoliAuth::VaultKey::v1::${secretMaterial}::AES-256-GCM` (`poliauth_credentials_vault_v1` / `poliauth_vault_meta_v1`)
     - Session State: `PoliAuth::SessionStateKey::v1::${secretMaterial}::AES-256-GCM` (`poliauth_session_state_v1` / `poliauth_session_state_meta_v1`)
2. **Authenticated Encryption**:
   - Cipher: `AES-256-GCM` (`256-bit` derived key, `12-byte` random IV per encryption operation, `128-bit` authentication tag)
   - Zero Node `Buffer` or `node:crypto` dependencies, allowing identical execution in Node.js 20+, Deno, Bun, Cloudflare Workers, and modern browsers.

---

## 3. Preserved PoliMi SSO & 2FA Domain Invariants

All production invariants for Politecnico di Milano's JAF Identity Provider are preserved and verified by automated tests:
- **Stage 0 Security Violation Recovery**: Bare `/aunicalogin/` (`SessioneTerminataLogoutSSO.do` / `SessioneTerminata.do`) automatically recovers via `id_servizio=376`.
- **`sso_handoff` Priority over `credentials`**: `inspectPolimiPageStage` checks `form[action*="AunicaLogin.do"]` and `input[name="evn_checkCookieSSO"]` **before** `#login && #password` so auto-submitting SSO handoff pages are never mistaken for unauthenticated login forms.
- **Skipping Hidden JAF Submit Buttons**: Both Stage 1 (`button[name="evn_conferma"]:not(.jaf-visually-hidden)`) and Stage 2 (`button#submit-dissms[name="evn_continua"]`) skip `.jaf-visually-hidden` trap buttons.
- **TOTP Window Rollover Guard**: `generateStableTotp` waits for the next 30-second window when `<= 2s` remain so codes never expire mid-POST.
