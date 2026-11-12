import { POLIMI_LOGIN_FLOW_SPEC } from '../domain/login-flow-spec.js';
import type { FederatedSsoInspectionResult } from '../domain/entities.js';
import type { PageLocationSnapshot } from '../interfaces/browser-driver-port.js';
import { isPolimiLoginPage } from './polimi-dom-adapter.js';

export interface WebexSsoInspectionOptions {
  /**
   * Optional custom CSS selector on the target Webex page that indicates
   * the user has completed SSO and reached the authenticated resource.
   */
  authenticatedSelector?: string;
}

/**
 * Checks whether a URL/hostname is currently in a Webex or PoliMi SAML SSO transit endpoint.
 */
export function isWebexOrPolimiSsoTransitUrl(url: string, hostname = ''): boolean {
  const lowerUrl = url.toLowerCase();
  const lowerHost = hostname.toLowerCase();
  return (
    POLIMI_LOGIN_FLOW_SPEC.webexSsoPage.samlTransitHostnames.some((h) =>
      lowerHost.includes(h.toLowerCase())
    ) ||
    lowerHost.includes('signin.webex.com') ||
    lowerUrl.includes('/idb/saml2/') ||
    lowerUrl.includes('/aunicalogin/') ||
    lowerUrl.includes('dosso.jsp')
  );
}

/**
 * Checks whether the current DOM and URL correspond to the Webex SAML SSO email prompt
 * (`idbroker-eu.webex.com/idb/saml2/jsp/doSSO.jsp` or `signin.webex.com`).
 */
export function isWebexEmailSsoPage(doc: Document, loc: PageLocationSnapshot): boolean {
  const emailInput = doc.querySelector<HTMLInputElement>(
    POLIMI_LOGIN_FLOW_SPEC.webexSsoPage.emailInputSelector
  );
  if (emailInput) {
    return true;
  }

  if (
    POLIMI_LOGIN_FLOW_SPEC.webexSsoPage.hostnames.some((h) => loc.hostname.includes(h)) ||
    loc.hostname.includes('signin.webex.com') ||
    loc.pathname.includes(POLIMI_LOGIN_FLOW_SPEC.webexSsoPage.pathnameSubstring)
  ) {
    return true;
  }

  return false;
}

/**
 * Inspects a Webex or PoliMi SAML SSO page and classifies its federated SSO state:
 * - `'login_required'`: Webex `#IDToken1` email prompt or `aunicalogin.polimi.it` login required
 * - `'sso_in_transit'`: Mid-SAML redirect or auto-submit form in transit
 * - `'authenticated'`: Reached the authenticated Webex destination
 * - `'error'`: Contextual error displayed on page
 */
export function inspectWebexSsoPage(
  doc: Document,
  loc: PageLocationSnapshot,
  options?: WebexSsoInspectionOptions
): FederatedSsoInspectionResult {
  const url = loc.href || `${loc.pathname}${loc.search ?? ''}`;
  const isEmailPage = isWebexEmailSsoPage(doc, loc);
  const isTransit = isWebexOrPolimiSsoTransitUrl(url, loc.hostname);

  const contextualError = doc
    .querySelector(POLIMI_LOGIN_FLOW_SPEC.webexSsoPage.contextualErrorSelector)
    ?.textContent?.trim();
  if (contextualError) {
    return {
      status: 'error',
      isEmailSsoPage: isEmailPage,
      isSamlTransitPage: isTransit,
      url,
      reason: contextualError
    };
  }

  if (isEmailPage) {
    return {
      status: 'login_required',
      isEmailSsoPage: true,
      isSamlTransitPage: true,
      url,
      reason: 'Webex SAML SSO institutional email prompt detected'
    };
  }

  if (isPolimiLoginPage(doc, loc)) {
    return {
      status: 'login_required',
      isEmailSsoPage: false,
      isSamlTransitPage: true,
      url,
      reason: 'PoliMi SAML IdP login or 2FA required'
    };
  }

  const ssoForm = doc.querySelector<HTMLFormElement>(
    'form[action*="SAML2"], form[action*="AunicaLogin.do"], form[action*="doSSO.jsp"], input[name="SAMLResponse"], input[name="SAMLRequest"]'
  );
  if (ssoForm) {
    return {
      status: 'sso_in_transit',
      isEmailSsoPage: false,
      isSamlTransitPage: true,
      url,
      reason: 'SAML assertion or redirect form in progress'
    };
  }

  if (options?.authenticatedSelector && doc.querySelector(options.authenticatedSelector)) {
    return {
      status: 'authenticated',
      isEmailSsoPage: false,
      isSamlTransitPage: false,
      url
    };
  }

  if (loc.hostname.includes('webex.com') && !isTransit) {
    return {
      status: 'authenticated',
      isEmailSsoPage: false,
      isSamlTransitPage: false,
      url
    };
  }

  return {
    status: 'sso_in_transit',
    isEmailSsoPage: false,
    isSamlTransitPage: isTransit,
    url,
    reason: 'Waiting for federated SSO state resolution'
  };
}

/**
 * Submits the user's institutional `@mail.polimi.it` / `@polimi.it` email on the Webex
 * SAML SSO identity broker (`idbroker-eu.webex.com/idb/saml2/jsp/doSSO.jsp`).
 *
 * Preserves the critical `#IDToken1` / `#IDButton2` invariant:
 * `#IDButton2` starts `disabled` and only enables after `input`, `change`, and `blur`
 * events are dispatched on `#IDToken1`.
 */
export function submitWebexEmailLogin(
  doc: Document,
  email: string
): { ok: boolean; error?: string } {
  const emailInput = doc.querySelector<HTMLInputElement>(
    POLIMI_LOGIN_FLOW_SPEC.webexSsoPage.emailInputSelector
  );
  if (!emailInput) {
    return {
      ok: false,
      error: 'Webex SSO email input (#IDToken1) not found on page.'
    };
  }

  const cleanEmail = email.trim();
  const EventCtor = doc.defaultView?.Event ?? Event;
  emailInput.focus();
  emailInput.value = cleanEmail;
  emailInput.dispatchEvent(new EventCtor('input', { bubbles: true }));
  emailInput.dispatchEvent(new EventCtor('change', { bubbles: true }));
  emailInput.dispatchEvent(new EventCtor('blur', { bubbles: true }));

  const nextButton =
    doc.querySelector<HTMLButtonElement | HTMLInputElement>(
      POLIMI_LOGIN_FLOW_SPEC.webexSsoPage.submitButtonSelector
    ) ?? doc.querySelector<HTMLButtonElement | HTMLInputElement>('#IDButton2');

  if (nextButton) {
    nextButton.disabled = false;
    nextButton.removeAttribute('disabled');
    nextButton.click();
    return { ok: true };
  }

  const form =
    emailInput.closest('form') ??
    doc.querySelector<HTMLFormElement>(POLIMI_LOGIN_FLOW_SPEC.webexSsoPage.visibleFormSelector) ??
    doc.querySelector<HTMLFormElement>('#vimutest');
  if (form) {
    form.submit();
    return { ok: true };
  }

  return {
    ok: false,
    error: 'Could not locate Webex SSO Next button (#IDButton2) or parent form.'
  };
}
