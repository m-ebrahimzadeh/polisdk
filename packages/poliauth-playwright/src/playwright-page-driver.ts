import {
  POLIMI_LOGIN_FLOW_SPEC,
  type PolimiStageInspectionResult,
  type FederatedSsoInspectionResult
} from '@polisdk/poliauth/domain';
import type {
  AuthLoggerPort,
  FederatedAuthPageDriverPort,
  FederatedSsoProviderSpec,
  PageActionResult,
  PolimiCredentialSubmission,
  PolimiOtpSubmission,
  SessionRecoveryResult
} from '@polisdk/poliauth/interfaces';
import { createRedactingLogger, redactSensitiveErrorText } from '@polisdk/poliauth/middleware';
import { ensureAuthAdaptersInjected, type EvaluatablePageLike } from './injected-auth-bundle.js';

/**
 * Structural interface matching a Playwright `Page` object.
 */
export interface PlaywrightPageLike extends EvaluatablePageLike {
  url(): string;
  goto(
    url: string,
    options?: {
      waitUntil?: 'load' | 'domcontentloaded' | 'networkidle' | 'commit';
      timeout?: number;
    }
  ): Promise<unknown>;
  waitForLoadState?(
    state?: 'load' | 'domcontentloaded' | 'networkidle',
    options?: { timeout?: number }
  ): Promise<void>;
  waitForTimeout?(timeout: number): Promise<void>;
}

export interface PlaywrightAuthPageDriverOptions {
  /**
   * Optional declarative, JSON-serialisable federated SAML/Shibboleth Service Provider
   * specification passed into `page.evaluate(...)` during federated SSO operations.
   */
  federatedProviderSpec?: FederatedSsoProviderSpec;
  /**
   * Optional structured logger (automatically wrapped with secret redaction) used to
   * record transient navigation/context-destruction errors during redirects.
   */
  logger?: AuthLoggerPort;
  /**
   * Timeout in milliseconds for page navigation. Defaults to `35_000`.
   */
  navigationTimeoutMs?: number;
  /**
   * Maximum number of retry attempts when a transient execution-context destruction
   * error occurs during a 302/SAML redirect. Defaults to `2`.
   */
  maxTransientRetries?: number;
}

function isTransientNavigationError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /execution context was destroyed|most likely because of a navigation|cannot find context|frame was detached|target closed|navigation/i.test(
    msg
  );
}

/**
 * `FederatedAuthPageDriverPort` implementation backed by a Playwright `Page`.
 * Automatically injects `window.__PoliAuthAdapters`, passes declarative `FederatedSsoProviderSpec`
 * objects into `page.evaluate(...)`, and catches, logs (redacted), and retries transient
 * `"Execution context was destroyed"` errors during multi-hop SAML/JAF redirects.
 */
export class PlaywrightAuthPageDriver implements FederatedAuthPageDriverPort {
  public readonly federatedProviderId: string;
  private readonly page: PlaywrightPageLike;
  private readonly options: PlaywrightAuthPageDriverOptions;
  private readonly logger?: AuthLoggerPort;

  constructor(page: PlaywrightPageLike, options: PlaywrightAuthPageDriverOptions = {}) {
    this.page = page;
    this.options = options;
    this.federatedProviderId = options.federatedProviderSpec?.providerId ?? '';
    this.logger = options.logger ? createRedactingLogger(options.logger) : undefined;
  }

  /**
   * Returns a new `PlaywrightAuthPageDriver` bound to the same Playwright `Page` and
   * configured with the provided `FederatedSsoProviderSpec`.
   */
  withFederatedProviderSpec(spec: FederatedSsoProviderSpec): PlaywrightAuthPageDriver {
    return new PlaywrightAuthPageDriver(this.page, {
      ...this.options,
      federatedProviderSpec: spec
    });
  }

  private requireFederatedSpec(): FederatedSsoProviderSpec {
    const spec = this.options.federatedProviderSpec;
    if (!spec) {
      throw new Error(
        'Federated SSO provider spec is not configured on this PlaywrightAuthPageDriver. Pass options.federatedProviderSpec or call withFederatedProviderSpec(spec).'
      );
    }
    return spec;
  }

  private async evaluateWithRetry<R>(
    operationName: string,
    fn: () => Promise<R>
  ): Promise<R> {
    const maxAttempts = Math.max(1, (this.options.maxTransientRetries ?? 2) + 1);
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const injected = await ensureAuthAdaptersInjected(this.page, this.logger);
        if (!injected) {
          throw new Error(
            'Execution context was destroyed during adapter injection (navigation in progress).'
          );
        }
        return await fn();
      } catch (err) {
        const redacted = redactSensitiveErrorText(err);
        if (!isTransientNavigationError(err)) {
          this.logger?.error(`Playwright ${operationName} failed: ${redacted}`);
          throw err;
        }
        this.logger?.warn(
          `Transient navigation error during Playwright ${operationName} (attempt ${attempt}/${maxAttempts}): ${redacted}`
        );
        if (attempt < maxAttempts) {
          await this.waitForNavigation(1_500);
          if (this.page.waitForTimeout) {
            await this.page.waitForTimeout(25).catch(() => undefined);
          }
          continue;
        }
        throw err;
      }
    }
    throw new Error(`Playwright ${operationName} exhausted transient retry attempts.`);
  }

  async goto(url: string, timeoutMs?: number): Promise<void> {
    await this.page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: timeoutMs ?? this.options.navigationTimeoutMs ?? 35_000
    });
  }

  async waitForNavigation(timeoutMs = 5_000): Promise<void> {
    if (this.page.waitForLoadState) {
      try {
        await this.page.waitForLoadState('domcontentloaded', { timeout: timeoutMs });
      } catch (err) {
        this.logger?.debug(
          `waitForNavigation did not settle within ${timeoutMs}ms: ${redactSensitiveErrorText(err)}`
        );
      }
    }
  }

  async inspectPolimiStage(): Promise<PolimiStageInspectionResult> {
    try {
      return await this.evaluateWithRetry('inspectPolimiStage', () =>
        this.page.evaluate(() => {
          const loc = {
            hostname: window.location.hostname,
            pathname: window.location.pathname,
            search: window.location.search,
            href: window.location.href
          };
          return window.__PoliAuthAdapters!.polimi.inspectPolimiPageStage(document, loc);
        })
      );
    } catch (err) {
      if (!isTransientNavigationError(err)) {
        throw err;
      }
      this.logger?.warn(
        `Playwright inspectPolimiStage interrupted by redirect; treating as sso_handoff: ${redactSensitiveErrorText(err)}`
      );
      return {
        stage: 'sso_handoff',
        url: this.page.url(),
        title: ''
      };
    }
  }

  async recoverSessionPage(): Promise<SessionRecoveryResult> {
    try {
      const recovery = await this.evaluateWithRetry('recoverSessionPage', () =>
        this.page.evaluate(() => {
          return window.__PoliAuthAdapters!.polimi.recoverPolimiSessionPage(document);
        })
      );
      if (!recovery.ok) {
        await this.goto(recovery.navigatedTo);
      } else {
        await this.waitForNavigation(1800);
      }
      return recovery;
    } catch (err) {
      if (!isTransientNavigationError(err)) {
        throw err;
      }
      this.logger?.warn(
        `Playwright recoverSessionPage interrupted by navigation; falling back to serviceEntryUrl: ${redactSensitiveErrorText(err)}`
      );
      const fallbackUrl = POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl;
      await this.goto(fallbackUrl);
      return { ok: false, navigatedTo: fallbackUrl };
    }
  }

  async submitCredentials(params: PolimiCredentialSubmission): Promise<PageActionResult> {
    return this.evaluateWithRetry('submitCredentials', () =>
      this.page.evaluate((creds) => {
        return window.__PoliAuthAdapters!.polimi.submitPolimiCredentials(document, creds);
      }, params)
    );
  }

  async submitOtp(params: PolimiOtpSubmission): Promise<PageActionResult> {
    return this.evaluateWithRetry('submitOtp', () =>
      this.page.evaluate((p) => {
        return window.__PoliAuthAdapters!.polimi.submitPolimiOtp(document, p);
      }, params)
    );
  }

  async inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult> {
    const spec = this.requireFederatedSpec();
    try {
      return await this.evaluateWithRetry('inspectFederatedSsoPage', () =>
        this.page.evaluate((providerSpec) => {
          const loc = {
            hostname: window.location.hostname,
            pathname: window.location.pathname,
            search: window.location.search,
            href: window.location.href
          };
          return window.__PoliAuthAdapters!.federatedSso.inspectFederatedSsoPageBySpec(
            providerSpec,
            document,
            loc
          );
        }, spec)
      );
    } catch (err) {
      if (!isTransientNavigationError(err)) {
        throw err;
      }
      this.logger?.warn(
        `Playwright inspectFederatedSsoPage (${spec.providerId}) interrupted by SAML redirect: ${redactSensitiveErrorText(err)}`
      );
      return {
        providerId: spec.providerId,
        status: 'sso_in_transit',
        isIdentifierPrompt: false,
        isLoginTrigger: false,
        isSamlTransitPage: true,
        url: this.page.url(),
        reason: 'Page navigating across SAML SSO redirect'
      };
    }
  }

  async submitFederatedIdentifier(identifier: string): Promise<PageActionResult> {
    const spec = this.requireFederatedSpec();
    return this.evaluateWithRetry('submitFederatedIdentifier', () =>
      this.page.evaluate(
        ({ providerSpec, id }) => {
          return window.__PoliAuthAdapters!.federatedSso.submitFederatedIdentifierBySpec(
            providerSpec,
            document,
            id
          );
        },
        { providerSpec: spec, id: identifier }
      )
    );
  }

  async triggerFederatedLogin(): Promise<PageActionResult> {
    const spec = this.requireFederatedSpec();
    return this.evaluateWithRetry('triggerFederatedLogin', () =>
      this.page.evaluate((providerSpec) => {
        return window.__PoliAuthAdapters!.federatedSso.triggerFederatedLoginBySpec(
          providerSpec,
          document
        );
      }, spec)
    );
  }
}
