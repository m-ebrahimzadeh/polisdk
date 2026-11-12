import { POLIMI_LOGIN_FLOW_SPEC } from '../domain/login-flow-spec.js';
import type {
  PolimiStageInspectionResult,
  FederatedSsoInspectionResult
} from '../domain/entities.js';
import {
  type PolimiPortalServiceDescriptor,
  RECORDINGS_ARCHIVE_SERVICE
} from '../domain/service-registry.js';
import type { AuthPageDriverPort } from '../interfaces/browser-driver-port.js';
import { ensureAuthAdaptersInjected, type EvaluatablePageLike } from './injected-auth-bundle.js';

/**
 * Structural interface matching a Playwright `Page` object.
 */
export interface PlaywrightPageLike extends EvaluatablePageLike {
  url(): string;
  goto(
    url: string,
    options?: { waitUntil?: 'load' | 'domcontentloaded' | 'networkidle' | 'commit'; timeout?: number }
  ): Promise<unknown>;
  waitForLoadState?(
    state?: 'load' | 'domcontentloaded' | 'networkidle',
    options?: { timeout?: number }
  ): Promise<void>;
  waitForTimeout?(timeout: number): Promise<void>;
}

export interface PlaywrightAuthPageDriverOptions {
  /**
   * Default target PoliMi service descriptor used when inspecting stages.
   * Defaults to `RECORDINGS_ARCHIVE_SERVICE` (`idServizio=2314`).
   */
  targetService?: PolimiPortalServiceDescriptor;
  /**
   * Optional CSS selector indicating the user has reached an authenticated Webex page.
   */
  webexAuthenticatedSelector?: string;
  /**
   * Timeout in milliseconds for page navigation. Defaults to `35_000`.
   */
  navigationTimeoutMs?: number;
}

/**
 * `AuthPageDriverPort` implementation backed by a Playwright `Page`.
 * Automatically injects `window.__PoliAuthAdapters` and guards against transient
 * `"Execution context was destroyed"` errors during multi-hop SAML/JAF redirects.
 */
export class PlaywrightAuthPageDriver implements AuthPageDriverPort {
  private readonly page: PlaywrightPageLike;
  private readonly options: PlaywrightAuthPageDriverOptions;

  constructor(page: PlaywrightPageLike, options: PlaywrightAuthPageDriverOptions = {}) {
    this.page = page;
    this.options = options;
  }

  async goto(url: string, timeoutMs?: number): Promise<void> {
    await this.page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: timeoutMs ?? this.options.navigationTimeoutMs ?? 35_000
    });
  }

  async waitForNavigation(timeoutMs = 5_000): Promise<void> {
    if (this.page.waitForLoadState) {
      await this.page
        .waitForLoadState('domcontentloaded', { timeout: timeoutMs })
        .catch(() => undefined);
    }
  }

  async inspectPolimiStage(
    targetService?: PolimiPortalServiceDescriptor
  ): Promise<PolimiStageInspectionResult> {
    const service = targetService ?? this.options.targetService ?? RECORDINGS_ARCHIVE_SERVICE;
    try {
      await ensureAuthAdaptersInjected(this.page);
      return await this.page.evaluate((svc) => {
        const loc = {
          hostname: window.location.hostname,
          pathname: window.location.pathname,
          search: window.location.search,
          href: window.location.href
        };
        return window.__PoliAuthAdapters!.polimi.inspectPolimiPageStage(document, loc, svc);
      }, service);
    } catch {
      return {
        stage: 'sso_handoff',
        url: this.page.url(),
        title: ''
      };
    }
  }

  async recoverSessionPage(): Promise<{ ok: boolean; navigatedTo: string }> {
    try {
      await ensureAuthAdaptersInjected(this.page);
      const recovery = await this.page.evaluate(() => {
        return window.__PoliAuthAdapters!.polimi.recoverPolimiSessionPage(document);
      });
      if (!recovery.ok) {
        await this.goto(recovery.navigatedTo);
      } else {
        await this.waitForNavigation(1800);
      }
      return recovery;
    } catch {
      const fallbackUrl = POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl;
      await this.goto(fallbackUrl);
      return { ok: false, navigatedTo: fallbackUrl };
    }
  }

  async submitCredentials(params: {
    personCode: string;
    password: string;
    stayConnected?: boolean;
  }): Promise<{ ok: boolean; error?: string }> {
    await ensureAuthAdaptersInjected(this.page);
    return await this.page.evaluate((creds) => {
      return window.__PoliAuthAdapters!.polimi.submitPolimiCredentials(document, creds);
    }, params);
  }

  async submitOtp(params: { otp: string }): Promise<{ ok: boolean; error?: string }> {
    await ensureAuthAdaptersInjected(this.page);
    return await this.page.evaluate((p) => {
      return window.__PoliAuthAdapters!.polimi.submitPolimiOtp(document, p);
    }, params);
  }

  async openPortalService(
    service: PolimiPortalServiceDescriptor = RECORDINGS_ARCHIVE_SERVICE
  ): Promise<{ ok: boolean; href?: string; error?: string }> {
    await ensureAuthAdaptersInjected(this.page);
    const result = await this.page.evaluate((svc) => {
      return window.__PoliAuthAdapters!.polimi.clickPortalService(document, svc);
    }, service);

    if (!result.ok && result.href) {
      await this.goto(result.href);
      return { ok: true, href: result.href };
    }
    return result;
  }

  async inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult> {
    try {
      await ensureAuthAdaptersInjected(this.page);
      const selector = this.options.webexAuthenticatedSelector;
      return await this.page.evaluate((authSelector) => {
        const loc = {
          hostname: window.location.hostname,
          pathname: window.location.pathname,
          search: window.location.search,
          href: window.location.href
        };
        return window.__PoliAuthAdapters!.webexSso.inspectWebexSsoPage(document, loc, {
          authenticatedSelector: authSelector
        });
      }, selector);
    } catch {
      return {
        status: 'sso_in_transit',
        isEmailSsoPage: false,
        isSamlTransitPage: true,
        url: this.page.url(),
        reason: 'Page navigating across SAML SSO redirect'
      };
    }
  }

  async submitFederatedEmailLogin(email: string): Promise<{ ok: boolean; error?: string }> {
    await ensureAuthAdaptersInjected(this.page);
    return await this.page.evaluate((mail) => {
      return window.__PoliAuthAdapters!.webexSso.submitWebexEmailLogin(document, mail);
    }, email);
  }
}
