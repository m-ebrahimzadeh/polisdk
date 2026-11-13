import { POLIMI_LOGIN_FLOW_SPEC } from '../domain/login-flow-spec.js';
import type {
  PolimiPageStage,
  PolimiStageInspectionResult
} from '../domain/entities.js';
import type { PageLocationSnapshot } from '../interfaces/browser-driver-port.js';

function dispatchInputEvents(el: Element): void {
  const EventCtor = el.ownerDocument?.defaultView?.Event ?? Event;
  el.dispatchEvent(new EventCtor('input', { bubbles: true }));
  el.dispatchEvent(new EventCtor('change', { bubbles: true }));
}

function getPageUrl(loc: PageLocationSnapshot): string {
  return loc.href || `${loc.pathname}${loc.search ?? ''}`;
}

function isPolimiHostname(hostname: string): boolean {
  const lower = (hostname || '').toLowerCase();
  return lower === 'polimi.it' || lower.endsWith('.polimi.it');
}

function isPolimiIdpLocation(loc: PageLocationSnapshot): boolean {
  const lowerHost = (loc.hostname || '').toLowerCase();
  const idpHost = POLIMI_LOGIN_FLOW_SPEC.entry.idpHostname.toLowerCase();
  if (lowerHost === idpHost || lowerHost.endsWith(`.${idpHost}`)) {
    return true;
  }
  return (
    isPolimiHostname(lowerHost) &&
    (loc.pathname || '').includes(POLIMI_LOGIN_FLOW_SPEC.entry.idpPathnameSubstring)
  );
}

/**
 * Checks whether the current DOM and location correspond to a PoliMi login, 2FA, or session error page.
 */
export function isPolimiLoginPage(doc: Document, loc: PageLocationSnapshot): boolean {
  const loginInput = doc.querySelector(POLIMI_LOGIN_FLOW_SPEC.credentialsPage.personCodeInputSelector);
  const passwordInput = doc.querySelector(POLIMI_LOGIN_FLOW_SPEC.credentialsPage.passwordInputSelector);
  if (loginInput && passwordInput) {
    return true;
  }

  const otpInput = doc.querySelector(POLIMI_LOGIN_FLOW_SPEC.otpPage.otpInputSelector);
  if (otpInput) {
    return true;
  }

  if (
    isPolimiIdpLocation(loc) ||
    (isPolimiHostname(loc.hostname) &&
      loc.pathname.includes(POLIMI_LOGIN_FLOW_SPEC.entry.sessionTerminatedMarker))
  ) {
    return true;
  }

  return false;
}

/**
 * Checks whether the current DOM and location correspond to an authenticated Politecnico di Milano session.
 */
export function isPolimiAuthenticatedSessionPage(
  doc: Document,
  loc: PageLocationSnapshot
): boolean {
  if (isPolimiLoginPage(doc, loc)) {
    return false;
  }

  if (!isPolimiHostname(loc.hostname)) {
    return false;
  }

  for (const selector of POLIMI_LOGIN_FLOW_SPEC.authenticatedSession.authenticatedDomSelectors) {
    if (doc.querySelector(selector)) {
      return true;
    }
  }

  const lowerHost = (loc.hostname || '').toLowerCase();
  const portalHost = POLIMI_LOGIN_FLOW_SPEC.authenticatedSession.portalHostname.toLowerCase();
  if (
    lowerHost === portalHost ||
    lowerHost.endsWith(`.${portalHost}`) ||
    loc.pathname.includes(POLIMI_LOGIN_FLOW_SPEC.authenticatedSession.portalPathnameSubstring)
  ) {
    return true;
  }

  return false;
}

/**
 * Inspects the current PoliMi DOM and URL to determine which stage of the
 * authentication pipeline the browser is currently on:
 * - `'authenticated'`: Reached an authenticated PoliMi session
 * - `'session_expired'`: Session expired or security violation page (`SessioneTerminata`)
 * - `'otp'`: 2FA OTP input page (`IdentificazioneUnica.do` / `IdentificazioneDFA.do`)
 * - `'sso_handoff'`: Intermediate SSO cookie handoff (`AunicaLogin.do?evn_checkCookieSSO=evento`)
 * - `'credentials'`: Person Code + Password login form (`aunicalogin.jsp`)
 * - `'unknown'`: Unrecognized or intermediate page
 */
export function inspectPolimiPageStage(
  doc: Document,
  loc: PageLocationSnapshot
): PolimiStageInspectionResult {
  const url = getPageUrl(loc);
  const title = doc.title || '';
  const dangerError =
    doc
      .querySelector(POLIMI_LOGIN_FLOW_SPEC.credentialsPage.errorAlertSelector)
      ?.textContent?.trim() || undefined;

  // 1. Session Expired / Terminated Security Violation page (scoped to PoliMi IdP)
  const onPolimiIdp = isPolimiIdpLocation(loc);
  const bodyText = (doc.body?.textContent ?? '').toLowerCase();
  const continueLink = onPolimiIdp
    ? doc.querySelector<HTMLAnchorElement>(
        POLIMI_LOGIN_FLOW_SPEC.entry.sessionExpiredSelectors.continueToPortalLink
      )
    : null;
  if (
    onPolimiIdp &&
    (loc.pathname.includes(POLIMI_LOGIN_FLOW_SPEC.entry.sessionTerminatedMarker) ||
      POLIMI_LOGIN_FLOW_SPEC.entry.sessionExpiredTextMarkers.some((marker) =>
        bodyText.includes(marker)
      ) ||
      Boolean(continueLink))
  ) {
    return {
      stage: 'session_expired',
      url,
      title,
      errorMessage: dangerError
    };
  }

  // 2. Stage 2: 2FA OTP Input Page
  const otpInput =
    doc.querySelector<HTMLInputElement>(POLIMI_LOGIN_FLOW_SPEC.otpPage.otpInputSelector) ??
    doc.querySelector<HTMLInputElement>(POLIMI_LOGIN_FLOW_SPEC.otpPage.fallbackOtpInputSelector);
  if (otpInput) {
    return {
      stage: 'otp',
      url,
      title,
      errorMessage: dangerError
    };
  }

  // 3. Intermediate SSO Auto-Submit Handoff (e.g. AunicaLogin.do or doSSO.jsp)
  // Must be checked BEFORE Stage 1 credentials because aunicalogin.jsp renders both
  // the SSO auto-submit form (`AunicaLogin.do`) and a hidden `#login`/`#password`
  // form while an SSO cookie is already active.
  const ssoForm = doc.querySelector<HTMLFormElement>(
    POLIMI_LOGIN_FLOW_SPEC.ssoHandoffPage.formSelector
  );
  const checkCookieBtn = doc.querySelector<HTMLElement>(
    POLIMI_LOGIN_FLOW_SPEC.ssoHandoffPage.checkCookieInputSelector
  );
  if (ssoForm || checkCookieBtn) {
    return {
      stage: 'sso_handoff',
      url,
      title
    };
  }

  // 4. Stage 1: Username & Password Credentials Page
  const loginInput = doc.querySelector<HTMLInputElement>(
    POLIMI_LOGIN_FLOW_SPEC.credentialsPage.personCodeInputSelector
  );
  const passwordInput = doc.querySelector<HTMLInputElement>(
    POLIMI_LOGIN_FLOW_SPEC.credentialsPage.passwordInputSelector
  );
  if (loginInput && passwordInput) {
    return {
      stage: 'credentials',
      url,
      title,
      errorMessage: dangerError
    };
  }

  // 5. Authenticated PoliMi Session
  if (isPolimiAuthenticatedSessionPage(doc, loc)) {
    return {
      stage: 'authenticated',
      url,
      title
    };
  }

  return {
    stage: 'unknown',
    url,
    title
  };
}

/**
 * Recovers from a PoliMi `SessioneTerminata` / security violation page by clicking
 * the "Continua..." anchor or returning `serviceEntryUrl` (`id_servizio=376`).
 */
export function recoverPolimiSessionPage(doc: Document): {
  ok: boolean;
  navigatedTo: string;
} {
  const continueLink =
    doc.querySelector<HTMLAnchorElement>(
      POLIMI_LOGIN_FLOW_SPEC.entry.sessionExpiredSelectors.continueToPortalLink
    ) ??
    doc.querySelector<HTMLAnchorElement>(
      POLIMI_LOGIN_FLOW_SPEC.entry.sessionExpiredSelectors.fallbackContinueToPortalLink
    );

  if (continueLink) {
    const navigatedTo = continueLink.href || POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl;
    continueLink.click();
    return {
      ok: true,
      navigatedTo
    };
  }

  return {
    ok: false,
    navigatedTo: POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl
  };
}

/**
 * Populates `#login` and `#password` on the PoliMi JAF login form and clicks the visible
 * `button[name="evn_conferma"]:not(.jaf-visually-hidden)` submit button.
 */
export function submitPolimiCredentials(
  doc: Document,
  credentials: { personCode: string; password: string; stayConnected?: boolean }
): { ok: boolean; error?: string } {
  const loginInput = doc.querySelector<HTMLInputElement>(
    POLIMI_LOGIN_FLOW_SPEC.credentialsPage.personCodeInputSelector
  );
  const passwordInput = doc.querySelector<HTMLInputElement>(
    POLIMI_LOGIN_FLOW_SPEC.credentialsPage.passwordInputSelector
  );

  if (!loginInput || !passwordInput) {
    return {
      ok: false,
      error: 'PoliMi #login or #password input fields not found on page.'
    };
  }

  loginInput.focus();
  loginInput.value = credentials.personCode.trim();
  dispatchInputEvents(loginInput);

  passwordInput.focus();
  passwordInput.value = credentials.password;
  dispatchInputEvents(passwordInput);

  if (credentials.stayConnected) {
    const stayCheckbox = doc.querySelector<HTMLInputElement>(
      POLIMI_LOGIN_FLOW_SPEC.credentialsPage.stayConnectedCheckboxSelector
    );
    if (stayCheckbox && !stayCheckbox.checked) {
      stayCheckbox.checked = true;
      dispatchInputEvents(stayCheckbox);
    }
  }

  const visibleSubmitBtn =
    doc.querySelector<HTMLElement>(POLIMI_LOGIN_FLOW_SPEC.credentialsPage.submitButtonSelector) ??
    doc.querySelector<HTMLElement>(
      POLIMI_LOGIN_FLOW_SPEC.credentialsPage.fallbackSubmitButtonSelector
    );

  if (visibleSubmitBtn) {
    visibleSubmitBtn.click();
    return { ok: true };
  }

  const form = loginInput.closest('form');
  if (form) {
    form.submit();
    return { ok: true };
  }

  return {
    ok: false,
    error: 'Could not locate visible submit button or parent form for credentials.'
  };
}

/**
 * Populates the 2FA OTP input on the PoliMi 2FA page and clicks `#submit-dissms[name="evn_continua"]`
 * (strictly avoiding the hidden `.jaf-visually-hidden` duplicate button).
 */
export function submitPolimiOtp(
  doc: Document,
  otpInputOrParams: string | { otp: string }
): { ok: boolean; error?: string } {
  const rawOtp = typeof otpInputOrParams === 'string' ? otpInputOrParams : otpInputOrParams.otp;
  const otpField =
    doc.querySelector<HTMLInputElement>(POLIMI_LOGIN_FLOW_SPEC.otpPage.otpInputSelector) ??
    doc.querySelector<HTMLInputElement>(POLIMI_LOGIN_FLOW_SPEC.otpPage.fallbackOtpInputSelector);

  if (!otpField) {
    return {
      ok: false,
      error: 'OTP input field not found on page.'
    };
  }

  const cleanOtp = rawOtp.replace(/\s+/g, '').trim();
  otpField.focus();
  otpField.value = cleanOtp;
  dispatchInputEvents(otpField);

  const submitBtn =
    doc.querySelector<HTMLElement>(POLIMI_LOGIN_FLOW_SPEC.otpPage.submitButtonSelector) ??
    doc.querySelector<HTMLElement>(POLIMI_LOGIN_FLOW_SPEC.otpPage.fallbackSubmitButtonSelector);

  if (submitBtn) {
    submitBtn.click();
    return { ok: true };
  }

  const form = otpField.closest('form');
  if (form) {
    form.submit();
    return { ok: true };
  }

  return {
    ok: false,
    error: 'Could not locate 2FA OTP submit button.'
  };
}

export type { PolimiPageStage };
