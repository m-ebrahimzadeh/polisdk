import type {
  PolimiStageInspectionResult,
  FederatedSsoInspectionResult
} from '../domain/entities.js';
import {
  type PolimiPortalServiceDescriptor,
  RECORDINGS_ARCHIVE_SERVICE
} from '../domain/service-registry.js';
import type { AuthPageDriverPort } from '../interfaces/browser-driver-port.js';

export interface ChromeTabMessengerLike {
  getTabUrl(tabId: number): Promise<string>;
  navigateTab(tabId: number, url: string): Promise<void>;
  waitForTabComplete(tabId: number, timeoutMs?: number): Promise<void>;
  sendTabMessage<TResponse>(tabId: number, message: Record<string, unknown>): Promise<TResponse>;
}

/**
 * `AuthPageDriverPort` adapter for Chrome Extension background service workers
 * communicating with content scripts inside a target browser tab.
 */
export class ChromeExtensionTabDriver implements AuthPageDriverPort {
  private readonly tabId: number;
  private readonly messenger: ChromeTabMessengerLike;

  constructor(tabId: number, messenger: ChromeTabMessengerLike) {
    this.tabId = tabId;
    this.messenger = messenger;
  }

  async goto(url: string, timeoutMs = 20_000): Promise<void> {
    await this.messenger.navigateTab(this.tabId, url);
    await this.messenger.waitForTabComplete(this.tabId, timeoutMs);
  }

  async waitForNavigation(timeoutMs = 15_000): Promise<void> {
    await this.messenger.waitForTabComplete(this.tabId, timeoutMs).catch(() => undefined);
  }

  async inspectPolimiStage(
    targetService?: PolimiPortalServiceDescriptor
  ): Promise<PolimiStageInspectionResult> {
    try {
      return await this.messenger.sendTabMessage<PolimiStageInspectionResult>(this.tabId, {
        type: 'INSPECT_POLIMI_STAGE',
        targetService
      });
    } catch {
      const url = await this.messenger.getTabUrl(this.tabId).catch(() => '');
      return {
        stage: 'sso_handoff',
        url,
        title: ''
      };
    }
  }

  async recoverSessionPage(): Promise<{ ok: boolean; navigatedTo: string }> {
    const res = await this.messenger.sendTabMessage<{ ok: boolean; navigatedTo: string }>(
      this.tabId,
      { type: 'RECOVER_POLIMI_SESSION' }
    );
    if (!res.ok) {
      await this.goto(res.navigatedTo);
    }
    return res;
  }

  async submitCredentials(params: {
    personCode: string;
    password: string;
    stayConnected?: boolean;
  }): Promise<{ ok: boolean; error?: string }> {
    return this.messenger.sendTabMessage<{ ok: boolean; error?: string }>(this.tabId, {
      type: 'SUBMIT_POLIMI_CREDENTIALS',
      credentials: params
    });
  }

  async submitOtp(params: { otp: string }): Promise<{ ok: boolean; error?: string }> {
    return this.messenger.sendTabMessage<{ ok: boolean; error?: string }>(this.tabId, {
      type: 'SUBMIT_POLIMI_OTP',
      otp: params.otp
    });
  }

  async openPortalService(
    service: PolimiPortalServiceDescriptor = RECORDINGS_ARCHIVE_SERVICE
  ): Promise<{ ok: boolean; href?: string; error?: string }> {
    const res = await this.messenger.sendTabMessage<{
      ok: boolean;
      href?: string;
      error?: string;
    }>(this.tabId, {
      type: 'CLICK_PORTAL_ARCHIVE_LINK',
      service
    });
    if (!res.ok && res.href) {
      await this.goto(res.href);
      return { ok: true, href: res.href };
    }
    return res;
  }

  async inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult> {
    try {
      return await this.messenger.sendTabMessage<FederatedSsoInspectionResult>(this.tabId, {
        type: 'INSPECT_WEBEX_PAGE'
      });
    } catch {
      const url = await this.messenger.getTabUrl(this.tabId).catch(() => '');
      return {
        status: 'sso_in_transit',
        isEmailSsoPage: false,
        isSamlTransitPage: true,
        url,
        reason: 'Tab transitioning across SSO redirect'
      };
    }
  }

  async submitFederatedEmailLogin(email: string): Promise<{ ok: boolean; error?: string }> {
    return this.messenger.sendTabMessage<{ ok: boolean; error?: string }>(this.tabId, {
      type: 'SUBMIT_WEBEX_SSO_EMAIL',
      email
    });
  }
}
