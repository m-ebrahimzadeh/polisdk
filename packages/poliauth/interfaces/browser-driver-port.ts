/**
 * @module @polisdk/poliauth/interfaces/browser-driver-port
 * Segregated Browser Page Driver Ports (Interface Segregation Principle).
 *
 * Role interfaces:
 * - `PageNavigationPort`          — navigation primitives shared by every driver.
 * - `PolimiIdpPagePort`           — Politecnico di Milano IdP page capabilities (credentials, 2FA, recovery).
 * - `AuthPageDriverPort`          — core driver = navigation + PoliMi IdP (required by `authenticate`).
 * - `FederatedSsoPageDriverPort`  — optional federated SAML Service Provider capabilities.
 * - `FederatedAuthPageDriverPort` — core driver + federated SP (required by `authenticateFederatedSaml`).
 *
 * No port in this module references any concrete Service Provider (Webex, Zoom, ...).
 */

import type {
  FederatedSsoInspectionResult,
  PolimiStageInspectionResult
} from '../domain/entities.js';

/**
 * Minimal URL/Location snapshot independent of browser globals.
 */
export interface PageLocationSnapshot {
  hostname: string;
  pathname: string;
  search?: string;
  href: string;
}

/**
 * Result of a single page interaction (form fill + submit).
 */
export interface PageActionResult {
  ok: boolean;
  error?: string;
}

/**
 * Result of recovering from a PoliMi `SessioneTerminata` / security-violation page.
 */
export interface SessionRecoveryResult {
  ok: boolean;
  navigatedTo: string;
}

/**
 * Credentials submitted on the PoliMi IdP credentials form.
 */
export interface PolimiCredentialSubmission {
  personCode: string;
  password: string;
  stayConnected?: boolean;
}

/**
 * 6-digit OTP submitted on the PoliMi IdP 2FA form.
 */
export interface PolimiOtpSubmission {
  otp: string;
}

/**
 * Navigation primitives shared by every page driver.
 */
export interface PageNavigationPort {
  /**
   * Navigates the underlying page/tab to the given URL.
   */
  goto(url: string, timeoutMs?: number): Promise<void>;

  /**
   * Waits for an in-flight navigation or page load to settle.
   */
  waitForNavigation(timeoutMs?: number): Promise<void>;
}

/**
 * Politecnico di Milano Identity Provider page capabilities.
 */
export interface PolimiIdpPagePort {
  /**
   * Inspects the current PoliMi authentication stage (`authenticated`, `otp`,
   * `credentials`, `sso_handoff`, `session_expired`, or `unknown`).
   */
  inspectPolimiStage(): Promise<PolimiStageInspectionResult>;

  /**
   * Recovers from bare `/aunicalogin/` security violation or expired session pages.
   */
  recoverSessionPage(): Promise<SessionRecoveryResult>;

  /**
   * Populates Person Code and Password and submits the PoliMi login form.
   */
  submitCredentials(params: PolimiCredentialSubmission): Promise<PageActionResult>;

  /**
   * Populates the 6-digit 2FA OTP and submits `#form_scelta2fa`.
   */
  submitOtp(params: PolimiOtpSubmission): Promise<PageActionResult>;
}

/**
 * Core authentication page driver: navigation + PoliMi IdP capabilities.
 * This is the only driver contract required by `PoliAuthOrchestrator.authenticate`.
 */
export interface AuthPageDriverPort extends PageNavigationPort, PolimiIdpPagePort {}

/**
 * Federated SAML 2.0 Service Provider page capabilities.
 *
 * Implementations delegate SP-specific DOM knowledge to a pluggable
 * `FederatedSsoProviderAdapterPort` (or its serialisable `FederatedSsoProviderSpec`),
 * so new providers can be added without modifying this port or the orchestrator.
 */
export interface FederatedSsoPageDriverPort {
  /**
   * Identifier of the federated SSO provider this driver is bound to (e.g. `'webex'`).
   */
  readonly federatedProviderId: string;

  /**
   * Classifies the current page from the federated Service Provider's perspective.
   */
  inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult>;

  /**
   * Submits the user's identifier (institutional email / username) on the SP's
   * identifier-discovery prompt.
   */
  submitFederatedIdentifier(identifier: string): Promise<PageActionResult>;

  /**
   * Clicks/triggers the SP's SSO login button or link without entering an identifier.
   */
  triggerFederatedLogin(): Promise<PageActionResult>;
}

/**
 * Driver contract required by `PoliAuthOrchestrator.authenticateFederatedSaml`:
 * the core PoliMi IdP driver plus a bound federated Service Provider.
 */
export interface FederatedAuthPageDriverPort
  extends AuthPageDriverPort,
    FederatedSsoPageDriverPort {}
