import { POLIMI_LOGIN_FLOW_SPEC } from '../domain/login-flow-spec.js';
import type {
  PolimiPageStage,
  PolimiStageInspectionResult
} from '../domain/entities.js';
import {
  type PolimiPortalServiceDescriptor,
  RECORDINGS_ARCHIVE_SERVICE
} from '../domain/service-registry.js';
import type { PageLocationSnapshot } from '../interfaces/browser-driver-port.js';

function dispatchInputEvents(el: Element): void {
  const EventCtor = el.ownerDocument?.defaultView?.Event ?? Event;
  el.dispatchEvent(new EventCtor('input', { bubbles: true }));
  el.dispatchEvent(new EventCtor('change', { bubbles: true }));
}

function getPageUrl(loc: PageLocationSnapshot): string {
  return loc.href || `${loc.pathname}${loc.search ?? ''}`;
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
    loc.hostname.includes('aunicalogin.polimi.it') ||
    loc.pathname.includes('/aunicalogin') ||
    loc.pathname.includes('SessioneTerminata')
  ) {
    return true;
  }

  return false;
}

/**
 * Checks whether the current DOM and location match a specific target PoliMi service descriptor.
 */
export function isPolimiTargetServicePage(
  doc: Document,
  loc: PageLocationSnapshot,
  service: PolimiPortalServiceDescriptor = RECORDINGS_ARCHIVE_SERVICE
): boolean {
  if (isPolimiLoginPage(doc, loc)) {
    return false;
  }

  if (service.requiredDomSelector && doc.querySelector(service.requiredDomSelector)) {
    return true;
  }

  const fullUrl = getPageUrl(loc);
  const matchesUrl = service.targetUrlSubstrings.some(
    (sub) => fullUrl.includes(sub) || loc.pathname.includes(sub) || loc.hostname.includes(sub)
  );
  if (matchesUrl) {
    if (!service.requiredDomSelector) {
      return true;
    }
    if (doc.querySelector(service.requiredDomSelector)) {
      return true;
    }
  }

  const headings = Array.from(doc.querySelectorAll('h1, h2, h3, .jaf-title, title'));
  return headings.some((h) => {
    const text = (h.textContent ?? '').toLowerCase();
    return service.portalTextMatchers.some((kw) => text.includes(kw.toLowerCase()));
  });
}

/**
 * Checks whether the current DOM and location correspond to the authenticated
 * PoliMi Recordings Archive service (`idServizio=2314`).
 */
export function isPolimiArchivePage(doc: Document, loc: PageLocationSnapshot): boolean {
  return isPolimiTargetServicePage(doc, loc, RECORDINGS_ARCHIVE_SERVICE);
}

/**
 * Locates a link on the PoliMi Servizi Online portal matching the given `PolimiPortalServiceDescriptor`.
 */
export function findPortalServiceLink(
  doc: Document,
  service: PolimiPortalServiceDescriptor = RECORDINGS_ARCHIVE_SERVICE
): HTMLAnchorElement | null {
  for (const selector of service.portalLinkSelectors) {
    const el = doc.querySelector<HTMLAnchorElement>(selector);
    if (el) return el;
  }

  const allLinks = Array.from(doc.querySelectorAll<HTMLAnchorElement>('a[href]'));
  for (const a of allLinks) {
    const text = (a.textContent ?? '').trim().toLowerCase();
    const href = a.getAttribute('href') ?? '';
    if (
      href.includes(`idServizio=${service.serviceId}`) ||
      href.includes(`id_servizio=${service.serviceId}`) ||
      service.portalTextMatchers.some((kw) => text.includes(kw.toLowerCase()))
    ) {
      return a;
    }
  }

  return null;
}

/**
 * Locates the "Consultazione archivio registrazioni / Recording archives" link (`idServizio=2314`)
 * on the PoliMi Servizi Online portal.
 */
export function findRecordingArchivesLink(doc: Document): HTMLAnchorElement | null {
  return findPortalServiceLink(doc, RECORDINGS_ARCHIVE_SERVICE);
}

/**
 * Inspects the current PoliMi DOM and URL to determine which stage of the 5-stage
 * authentication and service navigation pipeline the browser is currently on.
 */
export function inspectPolimiPageStage(
  doc: Document,
  loc: PageLocationSnapshot,
  targetService: PolimiPortalServiceDescriptor = RECORDINGS_ARCHIVE_SERVICE
): PolimiStageInspectionResult {
  const url = getPageUrl(loc);
  const title = doc.title || '';
  const dangerError =
    doc
      .querySelector(POLIMI_LOGIN_FLOW_SPEC.credentialsPage.errorAlertSelector)
      ?.textContent?.trim() || undefined;

  // 1. Target service already loaded
  if (isPolimiTargetServicePage(doc, loc, targetService)) {
    const reportedStage: PolimiPageStage = targetService.stageName ?? 'archive';
    return {
      stage: reportedStage,
      url,
      title,
      detectedServiceId: targetService.serviceId
    };
  }

  // 2. Session Expired / Terminated Security Violation page
  const bodyText = (doc.body?.textContent ?? '').toLowerCase();
  const continueLink = doc.querySelector<HTMLAnchorElement>(
    POLIMI_LOGIN_FLOW_SPEC.entry.sessionExpiredSelectors.continueToPortalLink
  );
  if (
    loc.pathname.includes('SessioneTerminata') ||
    bodyText.includes('violazione della sicurezza') ||
    bodyText.includes('sessione di lavoro') ||
    (continueLink && loc.hostname.includes('aunicalogin.polimi.it'))
  ) {
    return {
      stage: 'session_expired',
      url,
      title,
      errorMessage: dangerError
    };
  }

  // 3. Stage 2: 2FA OTP Input Page
  const otpInput = doc.querySelector<HTMLInputElement>(
    POLIMI_LOGIN_FLOW_SPEC.otpPage.otpInputSelector
  );
  if (otpInput) {
    return {
      stage: 'otp',
      url,
      title,
      errorMessage: dangerError
    };
  }

  // 4. Intermediate SSO Auto-Submit Handoff (e.g. AunicaLogin.do or doSSO.jsp)
  // Must be checked BEFORE Stage 1 credentials because aunicalogin.jsp?id_servizio=2070/2314
  // renders both the SSO auto-submit form (`AunicaLogin.do`) and a hidden `#login`/`#password`
  // form while an SSO cookie is already active.
  const ssoForm = doc.querySelector<HTMLFormElement>(
    'form[action*="AunicaLogin.do"], form[action*="doSSO.jsp"], form[name="form1"][action*="Aunica"]'
  );
  const checkCookieBtn = doc.querySelector<HTMLElement>('input[name="evn_checkCookieSSO"]');
  if (ssoForm || checkCookieBtn) {
    return {
      stage: 'sso_handoff',
      url,
      title
    };
  }

  // 5. Stage 1: Username & Password Credentials Page
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

  // 6. Stage 3: Servizi Online Portal Home
  const portalLink = findPortalServiceLink(doc, targetService);
  const archiveLink = findRecordingArchivesLink(doc);
  if (
    portalLink ||
    archiveLink ||
    loc.hostname.includes(POLIMI_LOGIN_FLOW_SPEC.portalPage.hostname) ||
    loc.pathname.includes(POLIMI_LOGIN_FLOW_SPEC.portalPage.pathnameSubstring)
  ) {
    return {
      stage: 'portal',
      url,
      title,
      hasRecordingArchivesLink: Boolean(archiveLink),
      hasTargetServiceLink: Boolean(portalLink)
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
    ) ?? doc.querySelector<HTMLAnchorElement>('a[href*="id_servizio=376"]');

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
    doc.querySelector<HTMLInputElement>('input#codice_otp[name="codice_otp"], input#codice_otp');

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

/**
 * Clicks a service link on the PoliMi Servizi Online portal matching `service`.
 */
export function clickPortalService(
  doc: Document,
  service: PolimiPortalServiceDescriptor = RECORDINGS_ARCHIVE_SERVICE
): { ok: boolean; href?: string; error?: string } {
  const link = findPortalServiceLink(doc, service);
  const fallbackHref = `https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/servizi/Servizi.do?evn_srv=evento&idServizio=${service.serviceId}`;
  if (link) {
    const href = link.href || link.getAttribute('href') || fallbackHref;
    link.click();
    return {
      ok: true,
      href
    };
  }

  return {
    ok: false,
    href: fallbackHref,
    error: `${service.name} link not found in DOM.`
  };
}

/**
 * Clicks the "Consultazione archivio registrazioni / Recording archives" (`idServizio=2314`)
 * link on the PoliMi Servizi Online portal.
 */
export function clickRecordingArchivesOnPortal(doc: Document): {
  ok: boolean;
  href?: string;
  error?: string;
} {
  return clickPortalService(doc, RECORDINGS_ARCHIVE_SERVICE);
}

export type { PolimiPageStage };
