/**
 * @module @polisdk/poliauth/domain/login-flow-spec
 * Persistent specification of the Politecnico di Milano (aunicalogin -> Portale Servizi ->
 * Target Service -> Federated Webex SAML SSO) automated login flow captured from live debugging.
 *
 * 100% compatible with `POLIMI_LOGIN_FLOW_SPEC` in PoliRecord (`src/shared/login-flow-spec.ts`).
 */

export const POLIMI_LOGIN_FLOW_SPEC = {
  /**
   * Step 1: Initial entry URLs and session-expired recovery behavior.
   *
   * Live observation:
   * - Opening bare `https://aunicalogin.polimi.it/aunicalogin/` without a target `id_servizio`
   *   or with a stale session cookie renders `SessioneTerminataLogoutSSO.do` displaying
   *   `.alert-danger` ("Violazione della sicurezza") and `.alert-success` ("Logout effettuato")
   *   with 0 forms.
   * - Opening a service with an expired session redirects (302) to
   *   `https://aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/logout/SessioneTerminata.do?jaf_currentWFID=main&EVN_DEFAULT=evento`
   *   displaying `.alert-warning` ("Sessione di lavoro scaduta") and a primary button
   *   `a.btn-primary[href*="id_servizio=376"]` ("Continua").
   * - Requesting `https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376`
   *   (or `https://www.polimi.it/servizi-online`) performs a 302 redirect to
   *   `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=<HMAC>`
   *   which renders the "Servizi online" (`id_servizio=376`) login form.
   */
  entry: {
    requestedUrl: 'https://aunicalogin.polimi.it/aunicalogin/',
    serviceEntryUrl:
      'https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376',
    onlineServicesShortcutUrl: 'https://www.polimi.it/servizi-online',
    serviziOnlineServiceId: '376',
    recordingsArchiveServiceId: '2314',
    webexServiceId: '2070',
    webexIdpServiceId: '436',
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
   * URL: `https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376&profile=0&__pj0=0&__pj1=<HMAC>`
   * Form POST action: `/aunicalogin/aunicalogin/controller/IdentificazioneUnica.do?&jaf_currentWFID=main&polij_step=0&__pj0=0&__pj1=<HMAC>`
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
   * Step 4: Online Services Portal ("Portale servizi" on `servizionline.polimi.it`).
   */
  portalPage: {
    hostname: 'servizionline.polimi.it',
    pathnameSubstring: '/portaleservizi/',
    titleSubstring: 'Portale servizi',
    searchServiceInputSelector: 'input.cercaServizio[name="search"]',
    recordingArchivesLinkSelectors: [
      'a#srv_vm_530',
      'a#fav_vm_530',
      'a.srv_link[href*="idServizio=2314"]',
      'a[href*="idServizio=2314"]'
    ],
    recordingArchivesTextMatchers: [
      'recordings archive',
      'recording archives',
      'archivio registrazioni didattica',
      'archivio registrazioni'
    ]
  },

  /**
   * Step 5: Webex SAML SSO Email Entry ("Sign In - Webex" on `idbroker-eu.webex.com`).
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
