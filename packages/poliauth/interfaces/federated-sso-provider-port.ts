/**
 * @module @polisdk/poliauth/interfaces/federated-sso-provider-port
 * Pluggable Federated SAML 2.0 Service Provider Ports (Open/Closed Principle).
 *
 * A federated Service Provider (SP) — Webex, Zoom, Piazza, GitLab, Microsoft 365, ... —
 * redirects the user to the PoliMi IdP after an optional identifier-discovery prompt.
 * Each SP is plugged in through `FederatedSsoProviderAdapterPort`; drivers and the
 * orchestrator never need to change when a new SP is added.
 */

import type { FederatedSsoInspectionResult } from '../domain/entities.js';
import type { PageActionResult, PageLocationSnapshot } from './browser-driver-port.js';

/**
 * Service Provider Interface implemented by every federated SAML SP adapter.
 *
 * `TDocument` defaults to the DOM `Document`, but can be any document abstraction
 * understood by the adapter (e.g. a server-side HTML parser).
 */
export interface FederatedSsoProviderAdapterPort<TDocument = Document> {
  /** Stable, lowercase provider identifier (e.g. `'webex'`, `'zoom'`). */
  readonly providerId: string;
  /** Human-readable provider name used in diagnostics. */
  readonly displayName: string;

  /**
   * Classifies the current page from this Service Provider's perspective.
   */
  inspectPage(doc: TDocument, loc: PageLocationSnapshot): FederatedSsoInspectionResult;

  /**
   * Fills and submits the SP's identifier-discovery prompt (institutional email / username).
   */
  submitIdentifier(doc: TDocument, identifier: string): PageActionResult;
}

/**
 * Lookup port used by delivery adapters (e.g. Chrome content scripts) that receive
 * only a `providerId` across a process/message boundary.
 */
export interface FederatedSsoProviderResolverPort<TDocument = Document> {
  resolve(providerId: string): FederatedSsoProviderAdapterPort<TDocument> | undefined;
}

/**
 * Declarative, JSON-serialisable description of a federated SP's SAML login pages.
 *
 * Because it is plain data, a spec can cross process boundaries (Playwright
 * `page.evaluate`, Chrome messaging) and be interpreted in-page by the generic
 * `SelectorFederatedSsoProviderAdapter`, with no rebuild of injected bundles.
 */
export interface FederatedSsoProviderSpec {
  /** Stable, lowercase provider identifier (e.g. `'webex'`). */
  providerId: string;
  /** Human-readable provider name used in diagnostics. */
  displayName: string;

  /** The SP's identifier-discovery (email / username) prompt. */
  identifierPrompt: {
    /** Hostnames serving the identifier prompt. */
    hostnames: readonly string[];
    /** Pathname substrings identifying the identifier prompt. */
    pathnameSubstrings: readonly string[];
    /** CSS selector of the identifier input. */
    identifierInputSelector: string;
    /** CSS selector of the button that submits the identifier. */
    submitButtonSelector: string;
    /** Optional CSS selector of the form submitted when no button is found. */
    formSelector?: string;
    /** Optional CSS selector of an inline validation error. */
    contextualErrorSelector?: string;
    /**
     * Whether the submit button starts `disabled` and must be force-enabled after
     * dispatching `input`/`change`/`blur` events on the identifier input.
     */
    forceEnableSubmitButton?: boolean;
  };

  /** SP-owned hostnames traversed during SAML redirects (never "authenticated"). */
  transitHostnames: readonly string[];
  /** URL substrings (lowercase) identifying SP SAML redirect/assertion endpoints. */
  transitUrlSubstrings: readonly string[];

  /** Hostname suffixes of the authenticated SP application. */
  authenticatedHostnames: readonly string[];
  /** Optional CSS selectors proving the authenticated SP application has rendered. */
  authenticatedSelectors?: readonly string[];
}
