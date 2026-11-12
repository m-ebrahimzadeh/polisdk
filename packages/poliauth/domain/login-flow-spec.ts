/**
 * @module @polisdk/poliauth/domain/login-flow-spec
 * Specification of the Politecnico di Milano Identity Provider login flow
 * (`aunicalogin.polimi.it` -> authenticated `servizionline.polimi.it` session).
 *
 * This specification is strictly limited to PoliMi's own IdP. Federated SAML
 * Service Provider specifications are owned by their provider adapters
 * (see `adapters/webex-sso-dom-adapter.ts` -> `WEBEX_SAML_FLOW_SPEC`).
 */

export const POLIMI_LOGIN_FLOW_SPEC = {
  /**
   * Step 1: Initial entry URLs and session-expired recovery behavior.
   *
   * - Opening bare `https://aunicalogin.polimi.it/aunicalogin/` without a target `id_servizio`
   *   or with a stale session cookie renders `SessioneTerminataLogoutSSO.do` displaying
   *   `.alert-danger` ("Violazione della sicurezza") and `.alert-success` ("Logout effettuato")
   *   with 0 forms.
   * - Opening a session with an expired cookie redirects (302) to
   *   `https://aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/logout/SessioneTerminata.do?jaf_currentWFID=main&EVN_DEFAULT=evento`
   *   displaying `.alert-warning` ("Sessione di lavoro scaduta") and a primary button
   *   `a.btn-primary[href*="id_servizio=376"]` ("Continua").
   * - Requesting `https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376`
   *   performs a 302 redirect to
   *   `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=<HMAC>`
   *   which renders the Politecnico di Milano SSO login form.
   */
  entry: {
    requestedUrl: 'https://aunicalogin.polimi.it/aunicalogin/',
    serviceEntryUrl:
      'https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376',
    onlineServicesShortcutUrl: 'https://www.polimi.it/servizi-online',
    ssoPortalServiceId: '376',
    sessionExpiredSelectors: {
      continueToPortalLink:
        'a.btn-primary[href*="id_servizio=376"], a[role="button"][href*="id_servizio=376"]',
      logoutLink: 'a[href*="mode=logout"]',
      dangerAlert: '.poli-messages .alert-danger .jaf-message',
      warningAlert: '.poli-messages .alert-warning .jaf-message'
    }
  },

  /**
   * Step 2: PoliMi Credentials Page ("Polimi - Autenticazione").
   *
   * Note: The form contains a hidden submit button `button.jaf-visually-hidden[name="evn_conferma"]`
   * as its first element and a visible submit button `.aunicalogin-button-accedi button[name="evn_conferma"]` ("Accedi").
   */
  credentialsPage: {
    titleSubstring: 'Autenticazione',
    urlSubstrings: [
      'aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp',
      'aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/IdentificazioneUnica.do'
    ],
    formSelector:
      'form.jaf-form[action*="IdentificazioneUnica.do"], form.jaf-mobile-form[action*="IdentificazioneUnica.do"]',
    cardSelector: '#table-credenziali',
    personCodeInputSelector: 'input#login[name="login"], input[name="login"]',
    passwordInputSelector: 'input#password[name="password"], input[name="password"]',
    stayConnectedCheckboxSelector: 'input#RESTA_CONNESSO[name="RESTA_CONNESSO"]',
    submitButtonSelector:
      '.aunicalogin-button-accedi button[name="evn_conferma"], button[name="evn_conferma"]:not(.jaf-visually-hidden)',
    fallbackSubmitButtonSelector: 'button[name="evn_conferma"]',
    errorAlertSelector: '.poli-messages .alert-danger .jaf-message'
  },

  /**
   * Step 3: PoliMi 2FA / OTP Page ("Polimi - Autenticazione 2FA").
   */
  otpPage: {
    titleSubstring: 'Autenticazione 2FA',
    urlSubstrings: ['IdentificazioneUnica.do', 'IdentificazioneDFA.do'],
    formSelector: 'form#form_scelta2fa, form[action*="IdentificazioneDFA.do"]',
    otpInputSelector: 'input#otp[name="otp"], input[name="otp"]',
    submitButtonSelector:
      'button#submit-dissms[name="evn_continua"], button[name="evn_continua"]:not(.jaf-visually-hidden)',
    fallbackSubmitButtonSelector: 'button[name="evn_continua"]',
    errorAlertSelector: '.poli-messages .alert-danger .jaf-message'
  },

  /**
   * Step 4: Authenticated PoliMi SSO Session ("Portale servizi" on `servizionline.polimi.it`
   * or any authenticated `polimi.it` session).
   */
  authenticatedSession: {
    portalHostname: 'servizionline.polimi.it',
    portalPathnameSubstring: '/portaleservizi/',
    portalTitleSubstring: 'Portale servizi',
    authenticatedDomSelectors: [
      'input.cercaServizio[name="search"]',
      'a[href*="Logout.do"]',
      'a[href*="evn_logout"]',
      '.jaf-user-info'
    ]
  },

  /**
   * Step 5: PoliMi acting as a SAML 2.0 Identity Provider (IdP).
   *
   * When a federated Service Provider (SP) delegates authentication to Politecnico
   * di Milano, the browser transits through these IdP hostnames. Every federated SP
   * adapter treats them as "SAML in transit" from the SP's point of view, while the
   * orchestrator drives the actual IdP pages through `PolimiIdpPagePort`.
   *
   * Service-Provider-specific specifications (Webex, Zoom, GitLab, ...) deliberately
   * do NOT live here: they are owned by their federated SSO provider adapters.
   */
  samlIdentityProvider: {
    transitHostnames: ['aunicalogin.polimi.it', 'shibidp.polimi.it', 'idp.polimi.it']
  }
} as const;
