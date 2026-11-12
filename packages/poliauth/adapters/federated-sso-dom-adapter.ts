/**
 * @module @polisdk/poliauth/adapters/federated-sso-dom-adapter
 * Generic, spec-driven DOM adapter for federated SAML 2.0 Service Providers.
 *
 * Every function in this module is a pure function of `(spec, document, location)`
 * and is safe to bundle into injected browser scripts: a `FederatedSsoProviderSpec`
 * is plain JSON, so it can be sent into a page (Playwright `page.evaluate`) and
 * interpreted there without rebuilding the bundle for each new provider.
 */

import { POLIMI_LOGIN_FLOW_SPEC } from '../domain/login-flow-spec.js';
import type { FederatedSsoInspectionResult } from '../domain/entities.js';
import type {
  PageActionResult,
  PageLocationSnapshot
} from '../interfaces/browser-driver-port.js';
import type {
  FederatedSsoProviderAdapterPort,
  FederatedSsoProviderSpec
} from '../interfaces/federated-sso-provider-port.js';

/**
 * Protocol-level (provider-neutral) SAML 2.0 HTTP-POST binding markers.
 */
export const SAML_PROTOCOL_FORM_SELECTOR =
  'form[action*="SAML2"], form[action*="saml2"], input[name="SAMLResponse"], input[name="SAMLRequest"]';

function getPageUrl(loc: PageLocationSnapshot): string {
  return loc.href || `${loc.pathname}${loc.search ?? ''}`;
}

function hostnameMatches(hostname: string, candidates: readonly string[]): boolean {
  const lowerHost = hostname.toLowerCase();
  return candidates.some((candidate) => {
    const lowerCandidate = candidate.toLowerCase();
    return lowerHost === lowerCandidate || lowerHost.endsWith(`.${lowerCandidate}`);
  });
}

function querySelectorSafe<T extends Element = Element>(doc: Document, selector?: string): T | null {
  if (!selector) {
    return null;
  }
  try {
    return doc.querySelector<T>(selector) as T | null;
  } catch {
    return null;
  }
}

/**
 * Checks whether a URL/hostname belongs to the provider's SAML transit endpoints
 * or to the PoliMi SAML Identity Provider (`POLIMI_LOGIN_FLOW_SPEC.samlIdentityProvider`).
 */
export function isFederatedSsoTransitLocation(
  spec: FederatedSsoProviderSpec,
  url: string,
  hostname = ''
): boolean {
  const lowerUrl = url.toLowerCase();
  return (
    hostnameMatches(hostname, spec.transitHostnames) ||
    hostnameMatches(hostname, POLIMI_LOGIN_FLOW_SPEC.samlIdentityProvider.transitHostnames) ||
    spec.transitUrlSubstrings.some((fragment) => lowerUrl.includes(fragment.toLowerCase()))
  );
}

/**
 * Checks whether the current DOM/location corresponds to the provider's
 * identifier-discovery prompt (input rendered, or prompt hostname/pathname reached).
 */
export function isFederatedIdentifierPromptPage(
  spec: FederatedSsoProviderSpec,
  doc: Document,
  loc: PageLocationSnapshot
): boolean {
  if (querySelectorSafe(doc, spec.identifierPrompt.identifierInputSelector)) {
    return true;
  }
  return (
    hostnameMatches(loc.hostname, spec.identifierPrompt.hostnames) ||
    spec.identifierPrompt.pathnameSubstrings.some((fragment) => loc.pathname.includes(fragment))
  );
}

/**
 * Classifies the current page from a federated Service Provider's perspective:
 * - `'error'`: inline validation error rendered on the identifier prompt
 * - `'login_required'`: identifier prompt input rendered (`isIdentifierPrompt: true`)
 * - `'sso_in_transit'`: SAML POST binding form, SP transit endpoint, or PoliMi IdP page
 * - `'authenticated'`: authenticated SP application reached
 */
export function inspectFederatedSsoPageBySpec(
  spec: FederatedSsoProviderSpec,
  doc: Document,
  loc: PageLocationSnapshot
): FederatedSsoInspectionResult {
  const url = getPageUrl(loc);
  const providerId = spec.providerId;
  const isTransit = isFederatedSsoTransitLocation(spec, url, loc.hostname);

  const contextualError = querySelectorSafe(
    doc,
    spec.identifierPrompt.contextualErrorSelector
  )?.textContent?.trim();
  if (contextualError) {
    const hasIdentifierInput = Boolean(
      querySelectorSafe(doc, spec.identifierPrompt.identifierInputSelector)
    );
    return {
      providerId,
      status: 'error',
      isIdentifierPrompt: hasIdentifierInput,
      isEmailSsoPage: hasIdentifierInput,
      isSamlTransitPage: isTransit,
      url,
      reason: contextualError
    };
  }

  if (querySelectorSafe(doc, spec.identifierPrompt.identifierInputSelector)) {
    return {
      providerId,
      status: 'login_required',
      isIdentifierPrompt: true,
      isEmailSsoPage: true,
      isSamlTransitPage: true,
      url,
      reason: `${spec.displayName} SAML SSO identifier prompt detected`
    };
  }

  if (querySelectorSafe(doc, SAML_PROTOCOL_FORM_SELECTOR)) {
    return {
      providerId,
      status: 'sso_in_transit',
      isIdentifierPrompt: false,
      isEmailSsoPage: false,
      isSamlTransitPage: true,
      url,
      reason: 'SAML assertion or redirect form in progress'
    };
  }

  if (spec.authenticatedSelectors?.some((selector) => querySelectorSafe(doc, selector))) {
    return {
      providerId,
      status: 'authenticated',
      isIdentifierPrompt: false,
      isEmailSsoPage: false,
      isSamlTransitPage: false,
      url
    };
  }

  if (isFederatedIdentifierPromptPage(spec, doc, loc)) {
    return {
      providerId,
      status: 'sso_in_transit',
      isIdentifierPrompt: false,
      isEmailSsoPage: false,
      isSamlTransitPage: true,
      url,
      reason: `Waiting for ${spec.displayName} identifier prompt to render`
    };
  }

  if (isTransit) {
    return {
      providerId,
      status: 'sso_in_transit',
      isIdentifierPrompt: false,
      isEmailSsoPage: false,
      isSamlTransitPage: true,
      url,
      reason: 'Browser is on a SAML SP/IdP transit endpoint'
    };
  }

  if (hostnameMatches(loc.hostname, spec.authenticatedHostnames)) {
    return {
      providerId,
      status: 'authenticated',
      isIdentifierPrompt: false,
      isEmailSsoPage: false,
      isSamlTransitPage: false,
      url
    };
  }

  return {
    providerId,
    status: 'sso_in_transit',
    isIdentifierPrompt: false,
    isEmailSsoPage: false,
    isSamlTransitPage: false,
    url,
    reason: 'Waiting for federated SSO state resolution'
  };
}

/**
 * Fills the provider's identifier input, dispatches `input`/`change`/`blur` so
 * reactive SP forms enable their submit button, and submits the prompt.
 */
export function submitFederatedIdentifierBySpec(
  spec: FederatedSsoProviderSpec,
  doc: Document,
  identifier: string
): PageActionResult {
  const prompt = spec.identifierPrompt;
  const input = querySelectorSafe<HTMLInputElement>(doc, prompt.identifierInputSelector);
  if (!input) {
    return {
      ok: false,
      error: `${spec.displayName} SSO identifier input (${prompt.identifierInputSelector}) not found on page.`
    };
  }

  const EventCtor = doc.defaultView?.Event ?? Event;
  input.focus();
  input.value = identifier.trim();
  input.dispatchEvent(new EventCtor('input', { bubbles: true }));
  input.dispatchEvent(new EventCtor('change', { bubbles: true }));
  input.dispatchEvent(new EventCtor('blur', { bubbles: true }));

  const submitButton = querySelectorSafe<HTMLButtonElement | HTMLInputElement>(
    doc,
    prompt.submitButtonSelector
  );
  if (submitButton) {
    if (prompt.forceEnableSubmitButton) {
      submitButton.disabled = false;
      submitButton.removeAttribute('disabled');
    }
    submitButton.click();
    return { ok: true };
  }

  const form =
    input.closest('form') ?? querySelectorSafe<HTMLFormElement>(doc, prompt.formSelector);
  if (form) {
    form.submit();
    return { ok: true };
  }

  return {
    ok: false,
    error: `Could not locate ${spec.displayName} SSO submit button or parent form.`
  };
}

/**
 * Generic `FederatedSsoProviderAdapterPort` driven entirely by a declarative
 * `FederatedSsoProviderSpec`. Most SAML SPs (Zoom, Piazza, GitLab, Microsoft 365, ...)
 * can be supported by writing a spec alone, without subclassing.
 */
export class SelectorFederatedSsoProviderAdapter implements FederatedSsoProviderAdapterPort {
  public readonly spec: FederatedSsoProviderSpec;

  constructor(spec: FederatedSsoProviderSpec) {
    this.spec = spec;
  }

  get providerId(): string {
    return this.spec.providerId;
  }

  get displayName(): string {
    return this.spec.displayName;
  }

  inspectPage(doc: Document, loc: PageLocationSnapshot): FederatedSsoInspectionResult {
    return inspectFederatedSsoPageBySpec(this.spec, doc, loc);
  }

  submitIdentifier(doc: Document, identifier: string): PageActionResult {
    return submitFederatedIdentifierBySpec(this.spec, doc, identifier);
  }
}
