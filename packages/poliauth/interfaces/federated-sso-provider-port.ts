/**
 * @module @polisdk/poliauth/interfaces/federated-sso-provider-port
 * Pluggable Federated SAML/Shibboleth Service Provider Ports (Open/Closed Principle).
 *
 * A federated Service Provider (SP) — Webex, Zoom, WeBeep, Career Services, Microsoft 365, ... —
 * delegates authentication to the PoliMi IdP using one of three initiation modes:
 * - Mode A (`identifierPrompt`): multi-tenant SaaS email/identifier prompt
 * - Mode B (`loginTrigger`): click-through SSO button/link on an SP landing page
 * - Mode C (direct redirect): entry URL that immediately redirects through SAML/Shibboleth transit
 *
 * Each SP is plugged in through `FederatedSsoProviderAdapterPort` or a JSON-serializable
 * `FederatedSsoProviderSpec`; drivers and the orchestrator never need to change when a new SP is added.
 */

import type { FederatedSsoInspectionResult } from '../domain/entities.js';
import type { PageActionResult, PageLocationSnapshot } from './browser-driver-port.js';

/**
 * Service Provider Interface implemented by every federated SAML/Shibboleth SP adapter.
 *
 * `TDocument` defaults to the DOM `Document`, but can be any document abstraction
 * understood by the adapter (e.g. a server-side HTML parser).
 */
export interface FederatedSsoProviderAdapterPort<TDocument = Document> {
  /** Stable, lowercase provider identifier (e.g. `'webex'`, `'webeep'`). */
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

  /**
   * Clicks/triggers the SP's SSO login button or link without entering an identifier.
   */
  triggerLogin(doc: TDocument): PageActionResult;
}

/**
 * Lookup port used by delivery adapters (e.g. Chrome content scripts) that receive
 * only a `providerId` across a process/message boundary.
 */
export interface FederatedSsoProviderResolverPort<TDocument = Document> {
  resolve(providerId: string): FederatedSsoProviderAdapterPort<TDocument> | undefined;
}

/**
 * Mode A: Identifier-discovery (email / username) prompt specification for multi-tenant SaaS SPs.
 */
export interface FederatedIdentifierPromptSpec {
  /** Hostnames serving the identifier prompt. */
  hostnames: readonly string[];
  /** Pathname substrings identifying the identifier prompt. */
  pathnameSubstrings?: readonly string[];
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
}

/**
 * Mode B: Click-through SSO login trigger specification for Shibboleth/CAS SP landing pages.
 */
export interface FederatedLoginTriggerSpec {
  /** Hostnames serving the SP login landing page. */
  hostnames: readonly string[];
  /** Optional pathname substrings identifying the SP login page. */
  pathnameSubstrings?: readonly string[];
  /** CSS selector of the SSO login trigger button or anchor link. */
  triggerSelector: string;
  /** Optional CSS selector of an inline error banner on the SP login page. */
  contextualErrorSelector?: string;
  /**
   * Whether a disabled trigger element must be force-enabled before clicking.
   */
  forceEnableTrigger?: boolean;
}

/**
 * Declarative, JSON-serialisable description of a federated SP's SAML/Shibboleth login pages.
 *
 * Supports Mode A (`identifierPrompt`), Mode B (`loginTrigger`), and Mode C (direct redirect
 * where neither prompt nor trigger is configured and `entryUrl` redirects directly via `transitHostnames` /
 * `transitUrlSubstrings`). Because it is plain data, a spec can cross process boundaries (Playwright
 * `page.evaluate`, Chrome messaging) and be interpreted in-page by the generic
 * `SelectorFederatedSsoProviderAdapter`, with no rebuild of injected bundles.
 */
export interface FederatedSsoProviderSpec {
  /** Stable, lowercase provider identifier (e.g. `'webex'`, `'webeep'`). */
  providerId: string;
  /** Human-readable provider name used in diagnostics. */
  displayName: string;
  /** Optional SP entry URL (e.g., direct Shibboleth initiator or landing page URL). */
  entryUrl?: string;

  /** Mode A: Optional identifier-discovery (email / username) prompt. */
  identifierPrompt?: FederatedIdentifierPromptSpec;

  /** Mode B: Optional click-through SSO login trigger button/link. */
  loginTrigger?: FederatedLoginTriggerSpec;

  /** SP-owned hostnames traversed during SAML redirects (never "authenticated"). */
  transitHostnames: readonly string[];
  /** URL substrings (lowercase) identifying SP SAML redirect/assertion endpoints. */
  transitUrlSubstrings: readonly string[];

  /** Hostname suffixes of the authenticated SP application. */
  authenticatedHostnames: readonly string[];
  /** Optional CSS selectors proving the authenticated SP application has rendered. */
  authenticatedSelectors?: readonly string[];
}
