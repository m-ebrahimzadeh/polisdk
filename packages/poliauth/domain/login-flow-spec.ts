/**
 * @module @polisdk/poliauth/domain/login-flow-spec
 * Specification of the Politecnico di Milano Identity Provider login flow
 * (`aunicalogin.polimi.it` -> authenticated `servizionline.polimi.it` session).
 *
 * This specification is strictly limited to PoliMi's own IdP. Federated SAML
 * Service Provider specifications are owned by their provider adapters
 * (see `adapters/webex-sso-dom-adapter.ts` -> `WEBEX_SAML_FLOW_SPEC`).
 */

/**
 * Canonical structural contract for the Politecnico di Milano Identity Provider
 * login flow and outage/maintenance detection indicators.
 */
export interface PolimiLoginFlowSpec {
  readonly entry: {
    readonly requestedUrl: string;
    readonly serviceEntryUrl: string;
    readonly onlineServicesShortcutUrl: string;
    readonly ssoPortalServiceId: string;
    readonly idpHostname: string;
    readonly idpPathnameSubstring: string;
    readonly sessionTerminatedMarker: string;
    readonly sessionExpiredTextMarkers: readonly string[];
    readonly sessionExpiredSelectors: {
      readonly continueToPortalLink: string;
      readonly fallbackContinueToPortalLink: string;
      readonly logoutLink: string;
      readonly dangerAlert: string;
      readonly warningAlert: string;
    };
  };
  readonly ssoHandoffPage: {
    readonly formSelector: string;
    readonly checkCookieInputSelector: string;
  };
  readonly credentialsPage: {
    readonly titleSubstring: string;
    readonly urlSubstrings: readonly string[];
    readonly formSelector: string;
    readonly cardSelector: string;
    readonly personCodeInputSelector: string;
    readonly passwordInputSelector: string;
    readonly stayConnectedCheckboxSelector: string;
    readonly submitButtonSelector: string;
    readonly fallbackSubmitButtonSelector: string;
    readonly errorAlertSelector: string;
  };
  readonly otpPage: {
    readonly titleSubstring: string;
    readonly urlSubstrings: readonly string[];
    readonly formSelector: string;
    readonly otpInputSelector: string;
    readonly fallbackOtpInputSelector: string;
    readonly submitButtonSelector: string;
    readonly fallbackSubmitButtonSelector: string;
    readonly errorAlertSelector: string;
  };
  readonly authenticatedSession: {
    readonly portalHostname: string;
    readonly portalPathnameSubstring: string;
    readonly portalTitleSubstring: string;
    readonly authenticatedDomSelectors: readonly string[];
  };
  readonly samlIdentityProvider: {
    readonly transitHostnames: readonly string[];
  };
  readonly maintenanceIndicators: {
    readonly httpStatusCodes: readonly number[];
    readonly textPatterns: readonly string[];
    readonly networkErrorPatterns: readonly string[];
    readonly bannerSelectors: readonly string[];
  };
  readonly semanticErrorIndicators: {
    readonly passwordExpiredPatterns: readonly string[];
    readonly accountLockedPatterns: readonly string[];
    readonly invalidCredentialsPatterns: readonly string[];
    readonly otpRejectedPatterns: readonly string[];
  };
}

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
    idpHostname: 'aunicalogin.polimi.it',
    idpPathnameSubstring: '/aunicalogin',
    sessionTerminatedMarker: 'SessioneTerminata',
    sessionExpiredTextMarkers: ['violazione della sicurezza', 'sessione di lavoro'],
    sessionExpiredSelectors: {
      continueToPortalLink:
        'a.btn-primary[href*="id_servizio=376"], a[role="button"][href*="id_servizio=376"]',
      fallbackContinueToPortalLink: 'a[href*="id_servizio=376"]',
      logoutLink: 'a[href*="mode=logout"]',
      dangerAlert: '.poli-messages .alert-danger .jaf-message',
      warningAlert: '.poli-messages .alert-warning .jaf-message'
    }
  },

  /**
   * Intermediate SSO cookie auto-submit handoff (`AunicaLogin.do?evn_checkCookieSSO=evento`).
   */
  ssoHandoffPage: {
    formSelector:
      'form[action*="AunicaLogin.do"], form[action*="doSSO.jsp"], form[name="form1"][action*="Aunica"]',
    checkCookieInputSelector: 'input[name="evn_checkCookieSSO"]'
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
    errorAlertSelector: '.poli-messages .alert-danger .jaf-message, .poli-messages .alert-danger, .alert-danger'
  },

  /**
   * Step 3: PoliMi 2FA / OTP Page ("Polimi - Autenticazione 2FA").
   */
  otpPage: {
    titleSubstring: 'Autenticazione 2FA',
    urlSubstrings: ['IdentificazioneUnica.do', 'IdentificazioneDFA.do'],
    formSelector: 'form#form_scelta2fa, form[action*="IdentificazioneDFA.do"]',
    otpInputSelector: 'input#otp[name="otp"], input[name="otp"]',
    fallbackOtpInputSelector: 'input#codice_otp[name="codice_otp"], input#codice_otp',
    submitButtonSelector:
      'button[name="evn_continua"]:not(#submit-dissms):not(.jaf-visually-hidden)',
    fallbackSubmitButtonSelector:
      'button#submit-dissms[name="evn_continua"]:not(.jaf-visually-hidden), button[name="evn_continua"]:not(.jaf-visually-hidden), button[name="evn_continua"]',
    errorAlertSelector: '.poli-messages .alert-danger .jaf-message, .poli-messages .alert-danger, .alert-danger'
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
  },

  /**
   * Step 6: Outage, Gateway & Scheduled Maintenance Signatures for Drift Disambiguation.
   */
  maintenanceIndicators: {
    httpStatusCodes: [500, 502, 503, 504],
    textPatterns: [
      'manutenzione',
      'maintenance',
      'servizio temporaneamente non disponibile',
      'bad gateway',
      'service unavailable',
      'gateway time-out',
      'gateway timeout'
    ],
    networkErrorPatterns: [
      'ETIMEDOUT',
      'ECONNRESET',
      'ECONNREFUSED',
      'ENOTFOUND',
      'EAI_AGAIN',
      'ERR_NAME_NOT_RESOLVED',
      'ERR_CONNECTION_TIMED_OUT',
      'ERR_CONNECTION_REFUSED',
      'ERR_INTERNET_DISCONNECTED',
      'ERR_TUNNEL_CONNECTION_FAILED',
      'ERR_NETWORK_CHANGED',
      'net::ERR_'
    ],
    bannerSelectors: [
      '.poli-messages .alert-warning .jaf-message',
      '.poli-messages .alert-danger .jaf-message',
      '.alert-warning',
      '.maintenance-banner'
    ]
  },
  semanticErrorIndicators: {
    passwordExpiredPatterns: [
      'password scaduta',
      'password expired',
      'cambio password obbligatorio',
      'aggiornare la password',
      'modify your password',
      'rinnovo password',
      'expired password',
      'password must be changed'
    ],
    accountLockedPatterns: [
      'account bloccato',
      'utenza bloccata',
      'account locked',
      'troppi tentativi',
      'too many attempts',
      'temporaneamente bloccato',
      'abilitazione sospesa',
      'utente bloccato',
      'account suspended'
    ],
    invalidCredentialsPatterns: [
      'credenziali non valide',
      'codice persona o password errati',
      'autenticazione fallita',
      'login fallito',
      'invalid credentials',
      'wrong username or password',
      'utente o password non corretti',
      'credenziali errate',
      'login rejected'
    ],
    otpRejectedPatterns: [
      'codice otp non valido',
      'codice di sicurezza errato',
      'otp errato',
      'codice scaduto',
      'invalid otp',
      'invalid verification code',
      'codice errato',
      'codice otp errato',
      'otp non valido'
    ]
  }
} as const satisfies PolimiLoginFlowSpec;
