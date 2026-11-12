/**
 * @module @polisdk/poliauth/interfaces/browser-driver-port
 * Browser Automation and Session Pool Ports.
 */

import type {
  FederatedSsoInspectionResult,
  IdentityId,
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
 * Driver port abstracting a single browser page/tab during authentication.
 */
export interface AuthPageDriverPort {
  /**
   * Navigates the underlying page/tab to the given URL.
   */
  goto(url: string, timeoutMs?: number): Promise<void>;

  /**
   * Waits for an in-flight navigation or page load to settle.
   */
  waitForNavigation(timeoutMs?: number): Promise<void>;

  /**
   * Inspects the current PoliMi authentication stage (`authenticated`, `otp`,
   * `credentials`, `sso_handoff`, `session_expired`, or `unknown`).
   */
  inspectPolimiStage(): Promise<PolimiStageInspectionResult>;

  /**
   * Recovers from bare `/aunicalogin/` security violation or expired session pages.
   */
  recoverSessionPage(): Promise<{ ok: boolean; navigatedTo: string }>;

  /**
   * Populates Person Code and Password and submits the PoliMi login form.
   */
  submitCredentials(params: {
    personCode: string;
    password: string;
    stayConnected?: boolean;
  }): Promise<{ ok: boolean; error?: string }>;

  /**
   * Populates the 6-digit 2FA OTP and submits `#form_scelta2fa`.
   */
  submitOtp(params: { otp: string }): Promise<{ ok: boolean; error?: string }>;

  /**
   * Inspects whether the page is on a federated SAML SSO login prompt.
   */
  inspectFederatedSsoPage?(): Promise<FederatedSsoInspectionResult>;

  /**
   * Submits the user's institutional email on a federated SAML SSO discovery page.
   */
  submitFederatedEmailLogin?(
    email: string
  ): Promise<{ ok: boolean; error?: string }>;
}

/**
 * Managed per-user browser session entry with reference-counted lock protection.
 */
export interface ManagedSessionContext<TContext = unknown, TPage = unknown> {
  userId: IdentityId;
  context: TContext;
  primaryPage: TPage | null;
  lastActiveAt: number;
  activeLocks: number;
}

export interface SessionPoolStats {
  activeContexts: number;
  busyContexts: number;
  browserConnected: boolean;
}

/**
 * Port for managing isolated, reference-counted per-user browser contexts
 * with idle TTL eviction and encrypted session state persistence.
 */
export interface SessionContextPoolPort<TContext = unknown, TPage = unknown> {
  acquireUserContext(
    userId: IdentityId
  ): Promise<ManagedSessionContext<TContext, TPage>>;
  releaseUserContext(userId: IdentityId): void;
  getOrCreatePrimaryPage(
    managed: ManagedSessionContext<TContext, TPage>
  ): Promise<TPage>;
  saveUserContextState(userId: IdentityId): Promise<void>;
  destroyUserContext(
    userId: IdentityId,
    options?: { skipSaveState?: boolean; clearPersistedState?: boolean }
  ): Promise<void>;
  evictExpiredContexts(): Promise<void>;
  getStats(): SessionPoolStats;
  closeAll(): Promise<void>;
}
