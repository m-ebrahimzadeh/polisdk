/**
 * @module @polisdk/poliauth/adapters/dom-page-driver
 * Direct DOM implementations of the core and federated page driver ports.
 */

import type {
  PolimiStageInspectionResult,
  FederatedSsoInspectionResult
} from '../domain/entities.js';
import type {
  AuthPageDriverPort,
  FederatedAuthPageDriverPort,
  PageActionResult,
  PageLocationSnapshot,
  PolimiCredentialSubmission,
  PolimiOtpSubmission,
  SessionRecoveryResult
} from '../interfaces/browser-driver-port.js';
import type { FederatedSsoProviderAdapterPort } from '../interfaces/federated-sso-provider-port.js';
import {
  inspectPolimiPageStage,
  recoverPolimiSessionPage,
  submitPolimiCredentials,
  submitPolimiOtp
} from './polimi-dom-adapter.js';

export interface DomAuthPageDriverOptions {
  /**
   * Provider for the current `Document`.
   */
  getDocument: () => Document;
  /**
   * Provider for the current `PageLocationSnapshot`.
   */
  getLocation: () => PageLocationSnapshot;
  /**
   * Optional navigation handler invoked when `goto(url)` is called.
   */
  onNavigate?: (url: string) => Promise<void> | void;
  /**
   * Optional transition hook invoked when `waitForNavigation(timeoutMs)` is called.
   */
  onWaitForNavigation?: (timeoutMs?: number) => Promise<void> | void;
  /**
   * Optional pluggable federated SAML Service Provider adapter.
   */
  federatedProvider?: FederatedSsoProviderAdapterPort;
}

export interface DomFederatedAuthPageDriverOptions extends DomAuthPageDriverOptions {
  /**
   * Federated SAML Service Provider adapter bound to this driver.
   */
  provider: FederatedSsoProviderAdapterPort;
}

/**
 * Direct DOM implementation of the core `AuthPageDriverPort` (PoliMi IdP only).
 * Ideal for browser contexts, content scripts, and JSDOM integration tests.
 */
export class DomAuthPageDriver implements AuthPageDriverPort {
  protected readonly options: DomAuthPageDriverOptions;

  constructor(options: DomAuthPageDriverOptions) {
    this.options = options;
  }

  /**
   * Returns the current document as seen by this driver.
   */
  getDocument(): Document {
    return this.options.getDocument();
  }

  /**
   * Returns the current location snapshot as seen by this driver.
   */
  getLocationSnapshot(): PageLocationSnapshot {
    return this.options.getLocation();
  }

  /**
   * Creates a `DomFederatedAuthPageDriver` sharing this driver's DOM bindings and
   * bound to the given federated SAML Service Provider adapter.
   */
  withFederatedProvider(provider: FederatedSsoProviderAdapterPort): DomFederatedAuthPageDriver {
    return new DomFederatedAuthPageDriver({ ...this.options, provider });
  }

  async goto(url: string, _timeoutMs?: number): Promise<void> {
    if (this.options.onNavigate) {
      await this.options.onNavigate(url);
    }
  }

  async waitForNavigation(timeoutMs?: number): Promise<void> {
    if (this.options.onWaitForNavigation) {
      await this.options.onWaitForNavigation(timeoutMs);
      return;
    }
    if (timeoutMs && timeoutMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, Math.min(timeoutMs, 50)));
    }
  }

  async inspectPolimiStage(): Promise<PolimiStageInspectionResult> {
    return inspectPolimiPageStage(this.getDocument(), this.getLocationSnapshot());
  }

  async recoverSessionPage(): Promise<SessionRecoveryResult> {
    const res = recoverPolimiSessionPage(this.getDocument());
    if (!res.ok && this.options.onNavigate) {
      await this.options.onNavigate(res.navigatedTo);
    }
    return res;
  }

  async submitCredentials(params: PolimiCredentialSubmission): Promise<PageActionResult> {
    return submitPolimiCredentials(this.getDocument(), params);
  }

  async submitOtp(params: PolimiOtpSubmission): Promise<PageActionResult> {
    return submitPolimiOtp(this.getDocument(), params);
  }

  get federatedProviderId(): string | undefined {
    return this.options.federatedProvider?.providerId;
  }

  async inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult> {
    if (!this.options.federatedProvider) {
      throw new Error(
        'Federated SSO provider is not configured on this DomAuthPageDriver. Pass options.federatedProvider or use withFederatedProvider().'
      );
    }
    return this.options.federatedProvider.inspectPage(
      this.getDocument(),
      this.getLocationSnapshot()
    );
  }

  async submitFederatedIdentifier(identifier: string): Promise<PageActionResult> {
    if (!this.options.federatedProvider) {
      throw new Error(
        'Federated SSO provider is not configured on this DomAuthPageDriver. Pass options.federatedProvider or use withFederatedProvider().'
      );
    }
    return this.options.federatedProvider.submitIdentifier(this.getDocument(), identifier);
  }

  async submitFederatedEmailLogin(email: string): Promise<PageActionResult> {
    return this.submitFederatedIdentifier(email);
  }
}

/**
 * Direct DOM implementation of `FederatedAuthPageDriverPort`: PoliMi IdP driving plus
 * a pluggable `FederatedSsoProviderAdapterPort` (Webex, Zoom, GitLab, ...).
 */
export class DomFederatedAuthPageDriver
  extends DomAuthPageDriver
  implements FederatedAuthPageDriverPort
{
  private readonly provider: FederatedSsoProviderAdapterPort;

  constructor(options: DomFederatedAuthPageDriverOptions) {
    super(options);
    this.provider = options.provider;
  }

  get federatedProviderId(): string {
    return this.provider.providerId;
  }

  async inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult> {
    return this.provider.inspectPage(this.getDocument(), this.getLocationSnapshot());
  }

  async submitFederatedIdentifier(identifier: string): Promise<PageActionResult> {
    return this.provider.submitIdentifier(this.getDocument(), identifier);
  }
}
