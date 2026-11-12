/**
 * @module @polisdk/poliauth/domain/login-flow-spec
 * Specification of the Politecnico di Milano (aunicalogin -> Authenticated Session)
 * and Federated SAML 2.0 SSO login flows.
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
   * Federated SAML SSO Email Discovery ("Sign In - Webex" on `idbroker-eu.webex.com`).
   */
  webexSsoPage: {
    hostnames: ['idbroker-eu.webex.com', 'idbroker.webex.com'],
    pathnameSubstring: '/idb/saml2/jsp/doSSO.jsp',
    visibleFormSelector: 'form#md-form',
    hiddenLookupFormSelector: 'form#GlobalEmailLookupForm',
    emailInputSelector: 'input#IDToken1[name="IDToken1"], input#IDToken1',
    submitButtonSelector: 'button#IDButton2[name="btnOK"], button#IDButton2',
    contextualErrorSelector: '#nameContextualError1',
    samlTransitHostnames: [
      'idbroker-eu.webex.com',
      'idbroker.webex.com',
      'shibidp.polimi.it',
      'idp.polimi.it',
      'aunicalogin.polimi.it'
    ]
  }
} as const;
