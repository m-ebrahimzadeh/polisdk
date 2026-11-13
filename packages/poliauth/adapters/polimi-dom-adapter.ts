import { POLIMI_LOGIN_FLOW_SPEC } from '../domain/login-flow-spec.js';
import {
  classifyPolimiFailure,
  classifyPolimiSemanticError,
  isExpectedPolimiIdpHostname,
  type PoliAuthDiagnosticErrorPayload,
  type PoliAuthDomDiagnosticSnapshot,
  type PolimiPageStage,
  type PolimiSemanticErrorCode,
  type PolimiStageInspectionResult
} from '../domain/entities.js';
import { redactSecrets } from '../domain/redaction.js';
import type {
  PageActionResult,
  PageLocationSnapshot
} from '../interfaces/browser-driver-port.js';

export interface PolimiPageActionResult extends PageActionResult {
  diagnostic?: PoliAuthDiagnosticErrorPayload;
}

export interface PolimiStageInspectionOptions {
  httpStatus?: number;
}

function dispatchInputEvents(el: Element): void {
  const EventCtor = el.ownerDocument?.defaultView?.Event ?? Event;
  el.dispatchEvent(new EventCtor('input', { bubbles: true }));
  el.dispatchEvent(new EventCtor('change', { bubbles: true }));
}

function getPageUrl(loc: PageLocationSnapshot): string {
  return loc.href || `${loc.pathname}${loc.search ?? ''}`;
}

function getFallbackLocation(doc: Document): PageLocationSnapshot {
  const docLoc = (doc as { location?: Location | null }).location;
  if (docLoc) {
    return {
      hostname: docLoc.hostname || '',
      pathname: docLoc.pathname || '',
      search: docLoc.search || '',
      href: docLoc.href || ''
    };
  }
  return {
    hostname: '',
    pathname: '',
    search: '',
    href: ''
  };
}

function isPolimiHostname(hostname: string): boolean {
  const lower = (hostname || '').toLowerCase();
  return lower === 'polimi.it' || lower.endsWith('.polimi.it');
}

function isPolimiIdpLocation(loc: PageLocationSnapshot): boolean {
  const lowerHost = (loc.hostname || '').toLowerCase();
  if (isExpectedPolimiIdpHostname(lowerHost)) {
    return true;
  }
  const idpHost = POLIMI_LOGIN_FLOW_SPEC.entry.idpHostname.toLowerCase();
  if (lowerHost.endsWith(`.${idpHost}`)) {
    return true;
  }
  return (
    isPolimiHostname(lowerHost) &&
    (loc.pathname || '').includes(POLIMI_LOGIN_FLOW_SPEC.entry.idpPathnameSubstring)
  );
}

function isDomElementVisible(el: Element): boolean {
  if (el.classList?.contains('jaf-visually-hidden')) {
    return false;
  }
  let current: Element | null = el;
  while (current) {
    if (current.hasAttribute('hidden')) {
      return false;
    }
    const htmlCurrent = current as HTMLElement;
    if (
      htmlCurrent.style &&
      (htmlCurrent.style.display === 'none' || htmlCurrent.style.visibility === 'hidden')
    ) {
      return false;
    }
    const view = el.ownerDocument?.defaultView;
    if (view && typeof view.getComputedStyle === 'function') {
      const computed = view.getComputedStyle(current);
      if (computed.display === 'none' || computed.visibility === 'hidden') {
        return false;
      }
      if (
        computed.clip === 'rect(0px, 0px, 0px, 0px)' ||
        (computed.position === 'absolute' &&
          computed.width === '1px' &&
          computed.height === '1px' &&
          computed.overflow === 'hidden')
      ) {
        return false;
      }
    }
    current = current.parentElement;
  }
  return true;
}

function findPreferredButton(
  doc: Document,
  primarySelectorList: string,
  fallbackSelectorList?: string
): HTMLElement | null {
  const pickOrdered = (selectorList: string, requireVisible: boolean): HTMLElement | null => {
    if (!selectorList) return null;
    const parts = selectorList
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    for (const part of parts) {
      let matches: HTMLElement[] = [];
      try {
        matches = Array.from(doc.querySelectorAll<HTMLElement>(part));
      } catch {
        matches = [];
      }
      for (const candidate of matches) {
        const disabled =
          (candidate as HTMLButtonElement).disabled || candidate.hasAttribute('disabled');
        if (disabled) continue;
        if (!requireVisible || isDomElementVisible(candidate)) {
          return candidate;
        }
      }
    }
    return null;
  };

  return (
    pickOrdered(primarySelectorList, true) ??
    pickOrdered(fallbackSelectorList ?? '', true) ??
    pickOrdered(primarySelectorList, false) ??
    pickOrdered(fallbackSelectorList ?? '', false)
  );
}

function hasMaintenanceBannerInDoc(doc: Document): boolean {
  const titleText = (doc.title || '').toLowerCase();
  const bodyText = (doc.body?.textContent ?? '').toLowerCase();
  if (
    POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators.textPatterns.some(
      (pattern) =>
        bodyText.includes(pattern.toLowerCase()) ||
        titleText.includes(pattern.toLowerCase())
    )
  ) {
    return true;
  }

  for (const bannerSel of POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators.bannerSelectors) {
    if (bannerSel === '.maintenance-banner' && doc.querySelector(bannerSel)) {
      return true;
    }
  }
  return false;
}

function extractErrorAlertText(doc: Document): string | undefined {
  const dangerCandidates = [
    POLIMI_LOGIN_FLOW_SPEC.credentialsPage.errorAlertSelector,
    POLIMI_LOGIN_FLOW_SPEC.otpPage.errorAlertSelector,
    POLIMI_LOGIN_FLOW_SPEC.entry.sessionExpiredSelectors.dangerAlert
  ];
  for (const sel of dangerCandidates) {
    const text = doc.querySelector(sel)?.textContent?.trim();
    if (text) {
      return text;
    }
  }

  const warningCandidates = [
    POLIMI_LOGIN_FLOW_SPEC.entry.sessionExpiredSelectors.warningAlert,
    ...POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators.bannerSelectors
  ];
  const criticalWarningPatterns = [
    ...POLIMI_LOGIN_FLOW_SPEC.semanticErrorIndicators.passwordExpiredPatterns,
    ...POLIMI_LOGIN_FLOW_SPEC.semanticErrorIndicators.accountLockedPatterns,
    ...POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators.textPatterns
  ];
  for (const sel of warningCandidates) {
    const text = doc.querySelector(sel)?.textContent?.trim();
    if (text) {
      const lower = text.toLowerCase();
      if (criticalWarningPatterns.some((pattern) => lower.includes(pattern.toLowerCase()))) {
        return text;
      }
    }
  }
  return undefined;
}

function hasSessionExpiredMarkers(doc: Document, loc: PageLocationSnapshot): boolean {
  const onPolimiIdp = isPolimiIdpLocation(loc);
  if (!onPolimiIdp) {
    return false;
  }
  const bodyText = (doc.body?.textContent ?? '').toLowerCase();
  const continueLink = doc.querySelector<HTMLAnchorElement>(
    POLIMI_LOGIN_FLOW_SPEC.entry.sessionExpiredSelectors.continueToPortalLink
  );
  return (
    loc.pathname.includes(POLIMI_LOGIN_FLOW_SPEC.entry.sessionTerminatedMarker) ||
    POLIMI_LOGIN_FLOW_SPEC.entry.sessionExpiredTextMarkers.some((marker) =>
      bodyText.includes(marker)
    ) ||
    Boolean(continueLink)
  );
}

/**
 * Captures a sanitized structural DOM snapshot suitable for deterministic failure
 * classification (`PORTAL_OUTAGE_OR_NETWORK_ERROR` vs. `DOM_SELECTOR_DRIFT`).
 */
export function capturePolimiDomDiagnosticSnapshot(
  doc: Document,
  loc: PageLocationSnapshot,
  httpStatus?: number
): PoliAuthDomDiagnosticSnapshot {
  const url = redactSecrets(getPageUrl(loc));
  const pathname = redactSecrets(loc.pathname || '');
  const rawError = extractErrorAlertText(doc);
  const sanitizedError = rawError ? redactSecrets(rawError) : undefined;
  const hasMaintenanceBanner = hasMaintenanceBannerInDoc(doc);
  const bodyChildren = doc.body?.children?.length ?? 0;
  const trimmedBodyText = (doc.body?.textContent ?? '').trim();
  const hasEmptyBody = !doc.body || (bodyChildren === 0 && trimmedBodyText.length === 0);

  const hasLoginInput = Boolean(
    doc.querySelector(POLIMI_LOGIN_FLOW_SPEC.credentialsPage.personCodeInputSelector)
  );
  const hasPasswordInput = Boolean(
    doc.querySelector(POLIMI_LOGIN_FLOW_SPEC.credentialsPage.passwordInputSelector)
  );
  const hasOtpInput = Boolean(
    doc.querySelector(POLIMI_LOGIN_FLOW_SPEC.otpPage.otpInputSelector) ??
      doc.querySelector(POLIMI_LOGIN_FLOW_SPEC.otpPage.fallbackOtpInputSelector)
  );
  const hasSsoHandoffForm = Boolean(
    doc.querySelector(POLIMI_LOGIN_FLOW_SPEC.ssoHandoffPage.formSelector) ??
      doc.querySelector(POLIMI_LOGIN_FLOW_SPEC.ssoHandoffPage.checkCookieInputSelector)
  );
  const hasExpiredSessionMarker = hasSessionExpiredMarkers(doc, loc);

  const hasAuthenticatedMarker =
    isPolimiHostname(loc.hostname) &&
    !hasMaintenanceBanner &&
    !hasEmptyBody &&
    !hasLoginInput &&
    !hasPasswordInput &&
    !hasOtpInput &&
    POLIMI_LOGIN_FLOW_SPEC.authenticatedSession.authenticatedDomSelectors.some((selector) =>
      Boolean(doc.querySelector(selector))
    );

  return {
    url,
    pathname,
    ...(httpStatus !== undefined ? { httpStatus } : {}),
    hasEmptyBody,
    hasLoginInput,
    hasPasswordInput,
    hasOtpInput,
    hasSsoHandoffForm,
    hasExpiredSessionMarker,
    hasAuthenticatedMarker,
    hasErrorBanner: Boolean(sanitizedError),
    hasMaintenanceBanner,
    ...(sanitizedError ? { errorMessage: sanitizedError } : {})
  };
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

  const otpInput =
    doc.querySelector(POLIMI_LOGIN_FLOW_SPEC.otpPage.otpInputSelector) ??
    doc.querySelector(POLIMI_LOGIN_FLOW_SPEC.otpPage.fallbackOtpInputSelector);
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

  if (hasMaintenanceBannerInDoc(doc)) {
    return false;
  }

  for (const selector of POLIMI_LOGIN_FLOW_SPEC.authenticatedSession.authenticatedDomSelectors) {
    if (doc.querySelector(selector)) {
      return true;
    }
  }

  const bodyChildren = doc.body?.children?.length ?? 0;
  const trimmedBodyText = (doc.body?.textContent ?? '').trim();
  if (!doc.body || (bodyChildren === 0 && trimmedBodyText.length === 0)) {
    return false;
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
 * - `'unknown'`: Unrecognized, maintenance, or intermediate page
 */
export function inspectPolimiPageStage(
  doc: Document,
  loc: PageLocationSnapshot,
  options?: PolimiStageInspectionOptions
): PolimiStageInspectionResult {
  const url = getPageUrl(loc);
  const title = doc.title || '';
  const httpStatus = options?.httpStatus;
  const dangerError = extractErrorAlertText(doc);

  const buildMatchedStageResult = (
    stage: Exclude<PolimiPageStage, 'unknown'>
  ): PolimiStageInspectionResult => {
    const maintenanceBanner = hasMaintenanceBannerInDoc(doc);
    const shouldCheckSemantic =
      Boolean(dangerError) ||
      maintenanceBanner ||
      (httpStatus !== undefined && httpStatus >= 500);
    const snapshotForSemantic = shouldCheckSemantic
      ? capturePolimiDomDiagnosticSnapshot(doc, loc, httpStatus)
      : undefined;
    const semanticErrorCode = shouldCheckSemantic
      ? classifyPolimiSemanticError({
          operation: 'inspectPolimiPageStage',
          stage,
          url,
          title,
          pathname: loc.pathname,
          httpStatus,
          errorMessage: dangerError,
          diagnosticSnapshot: snapshotForSemantic
        })
      : undefined;
    return {
      stage,
      url,
      title,
      errorMessage: dangerError,
      ...(httpStatus !== undefined ? { httpStatus } : {}),
      ...(semanticErrorCode ? { semanticErrorCode } : {})
    };
  };

  const buildUnknownResult = (selectorOrEndpoint: string): PolimiStageInspectionResult => {
    const sanitizedUrl = redactSecrets(url);
    const diagnosticSnapshot = capturePolimiDomDiagnosticSnapshot(doc, loc, httpStatus);
    const diagnosticError = classifyPolimiFailure({
      component: '@polisdk/poliauth/adapters/polimi-dom-adapter',
      operation: 'inspectPolimiPageStage',
      stage: 'unknown',
      url: sanitizedUrl,
      title,
      pathname: loc.pathname,
      httpStatus,
      selectorOrEndpoint,
      diagnosticSnapshot
    });
    return {
      stage: 'unknown',
      url: sanitizedUrl,
      title,
      ...(dangerError ? { errorMessage: redactSecrets(dangerError) } : {}),
      ...(httpStatus !== undefined ? { httpStatus } : {}),
      ...(diagnosticError.semanticErrorCode
        ? { semanticErrorCode: diagnosticError.semanticErrorCode }
        : {}),
      diagnosticSnapshot,
      diagnosticError
    };
  };

  // 0. Explicit HTTP 5xx server outage -> classify immediately instead of misreading page state
  if (
    httpStatus !== undefined &&
    ((
      POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators.httpStatusCodes as readonly number[]
    ).includes(httpStatus) ||
      httpStatus >= 500)
  ) {
    return buildUnknownResult(
      `HTTP ${String(httpStatus)} (${POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl})`
    );
  }

  // 1. Session Expired / Terminated Security Violation page (scoped to PoliMi IdP)
  if (hasSessionExpiredMarkers(doc, loc)) {
    return buildMatchedStageResult('session_expired');
  }

  // 2. Stage 2: 2FA OTP Input Page
  const otpInput =
    doc.querySelector<HTMLInputElement>(POLIMI_LOGIN_FLOW_SPEC.otpPage.otpInputSelector) ??
    doc.querySelector<HTMLInputElement>(POLIMI_LOGIN_FLOW_SPEC.otpPage.fallbackOtpInputSelector);
  if (otpInput) {
    return buildMatchedStageResult('otp');
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
    return buildMatchedStageResult('credentials');
  }

  // 5. Authenticated PoliMi Session (guard against empty/maintenance pages on servizionline.polimi.it)
  if (isPolimiAuthenticatedSessionPage(doc, loc)) {
    return {
      stage: 'authenticated',
      url,
      title
    };
  }

  return buildUnknownResult(
    `${POLIMI_LOGIN_FLOW_SPEC.credentialsPage.personCodeInputSelector} | ${POLIMI_LOGIN_FLOW_SPEC.otpPage.otpInputSelector}`
  );
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
  credentials: { personCode: string; password: string; stayConnected?: boolean },
  loc?: PageLocationSnapshot
): PolimiPageActionResult {
  const resolvedLoc = loc ?? getFallbackLocation(doc);
  const loginInput = doc.querySelector<HTMLInputElement>(
    POLIMI_LOGIN_FLOW_SPEC.credentialsPage.personCodeInputSelector
  );
  const passwordInput = doc.querySelector<HTMLInputElement>(
    POLIMI_LOGIN_FLOW_SPEC.credentialsPage.passwordInputSelector
  );

  if (!loginInput || !passwordInput) {
    const diagnosticSnapshot = capturePolimiDomDiagnosticSnapshot(doc, resolvedLoc);
    const diagnostic = classifyPolimiFailure({
      component: '@polisdk/poliauth/adapters/polimi-dom-adapter',
      operation: 'submitCredentials',
      stage: 'credentials',
      url: getPageUrl(resolvedLoc),
      pathname: resolvedLoc.pathname,
      selectorOrEndpoint: `${POLIMI_LOGIN_FLOW_SPEC.credentialsPage.personCodeInputSelector} | ${POLIMI_LOGIN_FLOW_SPEC.credentialsPage.passwordInputSelector}`,
      error: 'PoliMi #login or #password input fields not found on page.',
      diagnosticSnapshot
    });
    return {
      ok: false,
      error: diagnostic.message,
      diagnostic
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

  const visibleSubmitBtn = findPreferredButton(
    doc,
    POLIMI_LOGIN_FLOW_SPEC.credentialsPage.submitButtonSelector,
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

  const diagnosticSnapshot = capturePolimiDomDiagnosticSnapshot(doc, resolvedLoc);
  const diagnostic = classifyPolimiFailure({
    component: '@polisdk/poliauth/adapters/polimi-dom-adapter',
    operation: 'submitCredentials',
    stage: 'credentials',
    url: getPageUrl(resolvedLoc),
    pathname: resolvedLoc.pathname,
    selectorOrEndpoint: POLIMI_LOGIN_FLOW_SPEC.credentialsPage.submitButtonSelector,
    error: 'Could not locate visible submit button or parent form for credentials.',
    diagnosticSnapshot
  });

  return {
    ok: false,
    error: diagnostic.message,
    diagnostic
  };
}

/**
 * Populates the 2FA OTP input on the PoliMi 2FA page and prioritizes the primary
 * `button[name="evn_continua"]:not(#submit-dissms):not(.jaf-visually-hidden)` control,
 * falling back cleanly to `#submit-dissms` when it is the sole visible submit button.
 */
export function submitPolimiOtp(
  doc: Document,
  otpInputOrParams: string | { otp: string },
  loc?: PageLocationSnapshot
): PolimiPageActionResult {
  const resolvedLoc = loc ?? getFallbackLocation(doc);
  const rawOtp = typeof otpInputOrParams === 'string' ? otpInputOrParams : otpInputOrParams.otp;
  const otpField =
    doc.querySelector<HTMLInputElement>(POLIMI_LOGIN_FLOW_SPEC.otpPage.otpInputSelector) ??
    doc.querySelector<HTMLInputElement>(POLIMI_LOGIN_FLOW_SPEC.otpPage.fallbackOtpInputSelector);

  if (!otpField) {
    const diagnosticSnapshot = capturePolimiDomDiagnosticSnapshot(doc, resolvedLoc);
    const diagnostic = classifyPolimiFailure({
      component: '@polisdk/poliauth/adapters/polimi-dom-adapter',
      operation: 'submitOtp',
      stage: 'otp',
      url: getPageUrl(resolvedLoc),
      pathname: resolvedLoc.pathname,
      selectorOrEndpoint: POLIMI_LOGIN_FLOW_SPEC.otpPage.otpInputSelector,
      error: 'OTP input field not found on page.',
      diagnosticSnapshot
    });
    return {
      ok: false,
      error: diagnostic.message,
      diagnostic
    };
  }

  const cleanOtp = rawOtp.replace(/\s+/g, '').trim();
  otpField.focus();
  otpField.value = cleanOtp;
  dispatchInputEvents(otpField);

  const submitBtn = findPreferredButton(
    doc,
    POLIMI_LOGIN_FLOW_SPEC.otpPage.submitButtonSelector,
    POLIMI_LOGIN_FLOW_SPEC.otpPage.fallbackSubmitButtonSelector
  );

  if (submitBtn) {
    submitBtn.click();
    return { ok: true };
  }

  const form = otpField.closest('form');
  if (form) {
    form.submit();
    return { ok: true };
  }

  const diagnosticSnapshot = capturePolimiDomDiagnosticSnapshot(doc, resolvedLoc);
  const diagnostic = classifyPolimiFailure({
    component: '@polisdk/poliauth/adapters/polimi-dom-adapter',
    operation: 'submitOtp',
    stage: 'otp',
    url: getPageUrl(resolvedLoc),
    pathname: resolvedLoc.pathname,
    selectorOrEndpoint: POLIMI_LOGIN_FLOW_SPEC.otpPage.submitButtonSelector,
    error: 'Could not locate 2FA OTP submit button.',
    diagnosticSnapshot
  });

  return {
    ok: false,
    error: diagnostic.message,
    diagnostic
  };
}

export { classifyPolimiFailure, classifyPolimiSemanticError } from '../domain/entities.js';
export type {
  PolimiPageStage,
  PolimiFailureClassificationInput,
  PolimiSemanticErrorCode
} from '../domain/entities.js';
