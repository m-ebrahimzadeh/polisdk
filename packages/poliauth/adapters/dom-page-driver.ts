import type {
  PolimiStageInspectionResult,
  FederatedSsoInspectionResult
} from '../domain/entities.js';
import type { AuthPageDriverPort, PageLocationSnapshot } from '../interfaces/browser-driver-port.js';
import {
  inspectPolimiPageStage,
  recoverPolimiSessionPage,
  submitPolimiCredentials,
  submitPolimiOtp
} from './polimi-dom-adapter.js';
import {
  inspectWebexSsoPage,
  submitWebexEmailLogin
} from './webex-sso-dom-adapter.js';

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
   * Optional CSS selector for authenticated federated SP pages.
   */
  federatedAuthenticatedSelector?: string;
}

/**
 * Direct DOM implementation of `AuthPageDriverPort`.
 * Ideal for browser contexts and JSDOM integration tests.
 */
export class DomAuthPageDriver implements AuthPageDriverPort {
  private readonly options: DomAuthPageDriverOptions;

  constructor(options: DomAuthPageDriverOptions) {
    this.options = options;
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
    return inspectPolimiPageStage(
      this.options.getDocument(),
      this.options.getLocation()
    );
  }

  async recoverSessionPage(): Promise<{ ok: boolean; navigatedTo: string }> {
    const res = recoverPolimiSessionPage(this.options.getDocument());
    if (!res.ok && this.options.onNavigate) {
      await this.options.onNavigate(res.navigatedTo);
    }
    return res;
  }

  async submitCredentials(params: {
    personCode: string;
    password: string;
    stayConnected?: boolean;
  }): Promise<{ ok: boolean; error?: string }> {
    return submitPolimiCredentials(this.options.getDocument(), params);
  }

  async submitOtp(params: { otp: string }): Promise<{ ok: boolean; error?: string }> {
    return submitPolimiOtp(this.options.getDocument(), params);
  }

  async inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult> {
    return inspectWebexSsoPage(this.options.getDocument(), this.options.getLocation(), {
      authenticatedSelector: this.options.federatedAuthenticatedSelector
    });
  }

  async submitFederatedEmailLogin(email: string): Promise<{ ok: boolean; error?: string }> {
    return submitWebexEmailLogin(this.options.getDocument(), email);
  }
}
