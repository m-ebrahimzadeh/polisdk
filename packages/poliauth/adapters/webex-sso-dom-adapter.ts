/**
 * @module @polisdk/poliauth/adapters/webex-sso-dom-adapter
 * Cisco Webex federated SAML 2.0 Service Provider adapter.
 *
 * Webex is one concrete, pluggable `FederatedSsoProviderAdapterPort` implementation.
 * Nothing in the core domain, ports, or orchestrator references Webex.
 */

import type { FederatedSsoProviderSpec } from '../interfaces/federated-sso-provider-port.js';
import { SelectorFederatedSsoProviderAdapter } from './federated-sso-dom-adapter.js';

/**
 * Specification of the Webex SAML SSO email discovery flow
 * ("Sign In - Webex" on `idbroker-eu.webex.com/idb/saml2/jsp/doSSO.jsp`).
 *
 * Critical invariant: `#IDButton2` starts `disabled` and only enables after `input`,
 * `change`, and `blur` events are dispatched on `#IDToken1`
 * (`forceEnableSubmitButton: true`). The page also renders a hidden
 * `form#GlobalEmailLookupForm`, which must never be submitted directly.
 */
export const WEBEX_SAML_FLOW_SPEC = {
  providerId: 'webex',
  displayName: 'Webex',
  identifierPrompt: {
    hostnames: ['idbroker-eu.webex.com', 'idbroker.webex.com', 'signin.webex.com'],
    pathnameSubstrings: ['/idb/saml2/jsp/doSSO.jsp'],
    identifierInputSelector: 'input#IDToken1[name="IDToken1"], input#IDToken1',
    submitButtonSelector: 'button#IDButton2[name="btnOK"], button#IDButton2',
    formSelector: 'form#md-form, form#vimutest',
    contextualErrorSelector: '#nameContextualError1',
    forceEnableSubmitButton: true
  },
  transitHostnames: ['idbroker-eu.webex.com', 'idbroker.webex.com', 'signin.webex.com'],
  transitUrlSubstrings: ['/idb/saml2/', 'dosso.jsp'],
  authenticatedHostnames: ['webex.com']
} as const satisfies FederatedSsoProviderSpec;

export interface WebexSamlProviderOptions {
  /**
   * Optional CSS selector on the target Webex page proving that SSO completed
   * and the authenticated Webex application rendered.
   */
  authenticatedSelector?: string;
  /**
   * Optional CSS selectors on the target Webex page proving that SSO completed
   * and the authenticated Webex application rendered.
   */
  authenticatedSelectors?: readonly string[];
}

/**
 * Builds a (JSON-serialisable) Webex spec, optionally extended with custom
 * authenticated-page selectors. Pass the result to remote drivers such as
 * `PlaywrightAuthPageDriver` or `ChromeExtensionTabDriver`.
 */
export function createWebexSamlFlowSpec(
  options: WebexSamlProviderOptions = {}
): FederatedSsoProviderSpec {
  const customSelectors: string[] = [];
  if (options.authenticatedSelector) {
    customSelectors.push(options.authenticatedSelector);
  }
  if (options.authenticatedSelectors) {
    customSelectors.push(...options.authenticatedSelectors);
  }
  if (customSelectors.length === 0) {
    return WEBEX_SAML_FLOW_SPEC;
  }
  return {
    ...WEBEX_SAML_FLOW_SPEC,
    authenticatedSelectors: customSelectors
  };
}

/**
 * `FederatedSsoProviderAdapterPort` implementation for Cisco Webex.
 */
export class WebexSamlProviderAdapter extends SelectorFederatedSsoProviderAdapter {
  constructor(options: WebexSamlProviderOptions = {}) {
    super(createWebexSamlFlowSpec(options));
  }
}
