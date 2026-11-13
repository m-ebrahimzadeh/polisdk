import {
  POLIMI_LOGIN_FLOW_SPEC,
  PoliAuthDiagnosticError,
  classifyPolimiFailure,
  type PolimiLoginFlowSpec,
  type PolimiStageInspectionResult,
  type FederatedSsoInspectionResult
} from '@polisdk/poliauth/domain';
import type { PolimiPageActionResult } from '@polisdk/poliauth/adapters';
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
 * Structural interface matching a Playwright `Request` object.
 */
export interface PlaywrightRequestLike {
  url(): string;
  resourceType?(): string;
  method?(): string;
}

/**
 * Structural interface matching a Playwright `Route` object.
 */
export interface PlaywrightRouteLike {
  request?(): PlaywrightRequestLike;
  abort(errorCode?: string): Promise<void> | void;
  continue(): Promise<void> | void;
}

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
  waitForURL?(
    url: string | RegExp | ((url: URL) => boolean),
    options?: {
      timeout?: number;
      waitUntil?: 'load' | 'domcontentloaded' | 'networkidle' | 'commit';
    }
  ): Promise<void>;
  waitForTimeout?(timeout: number): Promise<void>;
  isClosed?(): boolean;
  route?(
    url: string,
    handler: (
      route: PlaywrightRouteLike,
      request?: PlaywrightRequestLike
    ) => Promise<void> | void
  ): Promise<void> | void;
}

/**
 * Configuration options for Tier 2 Playwright fast-path asset blocking (`Spec Sec 7.2`).
 */
export interface FastPathResourceBlockerOptions {
  readonly enableFastPathResourceBlocking?: boolean;
  readonly blockStylesheets?: boolean;
  readonly additionalBlockedResourceTypes?: readonly string[];
  readonly additionalBlockedDomainSubstrings?: readonly string[];
}

export const DEFAULT_FAST_PATH_BLOCKED_RESOURCE_TYPES = [
  'image',
  'font',
  'media'
] as const;

export const DEFAULT_FAST_PATH_BLOCKED_TRACKER_DOMAINS = [
  'google-analytics.com',
  'googletagmanager.com',
  'doubleclick.net',
  'hotjar.com',
  'clarity.ms',
  'connect.facebook.net'
] as const;

const fastPathBlockedPages = new WeakSet<object>();

function extractHostnameSafe(rawUrl: string): string {
  if (!rawUrl) return '';
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    const match = /^[a-z]+:\/\/([^/?#:]+)/i.exec(rawUrl);
    return (match?.[1] ?? '').toLowerCase();
  }
}

/**
 * Evaluates whether a Playwright network request should be aborted under the Tier 2
 * fast-path asset blocker (`Spec Sec 7.2`).
 *
 * Strictly preserves `document`, `script` (first-party JAF/IdP JS), `xhr`, `fetch`,
 * and non-tracker `POST` form submissions, as well as `stylesheet` requests unless
 * `blockStylesheets: true`.
 */
export function shouldBlockFastPathRequest(
  input: { url: string; resourceType?: string; method?: string },
  options?: FastPathResourceBlockerOptions
): boolean {
  if (options?.enableFastPathResourceBlocking === false) {
    return false;
  }

  const resourceType = (input.resourceType ?? '').trim().toLowerCase();
  const method = (input.method ?? 'GET').trim().toUpperCase();
  const rawUrl = (input.url ?? '').trim();
  const lowerUrl = rawUrl.toLowerCase();
  const hostname = extractHostnameSafe(rawUrl);

  if (resourceType === 'document') {
    return false;
  }

  const matchesDefaultTracker =
    hostname.length > 0 &&
    DEFAULT_FAST_PATH_BLOCKED_TRACKER_DOMAINS.some(
      (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
    );

  const matchesCustomTracker = (options?.additionalBlockedDomainSubstrings ?? []).some(
    (rawSub) => {
      const sub = rawSub.trim().toLowerCase();
      if (!sub) return false;
      if (sub.includes('/') || !hostname) {
        return lowerUrl.includes(sub);
      }
      return hostname.includes(sub);
    }
  );

  if (matchesDefaultTracker || matchesCustomTracker) {
    return true;
  }

  if (
    resourceType === 'script' ||
    resourceType === 'xhr' ||
    resourceType === 'fetch' ||
    method === 'POST'
  ) {
    return false;
  }

  if (resourceType === 'stylesheet') {
    return options?.blockStylesheets === true;
  }

  const blockedTypes = new Set<string>(DEFAULT_FAST_PATH_BLOCKED_RESOURCE_TYPES);
  if (options?.additionalBlockedResourceTypes) {
    for (const entry of options.additionalBlockedResourceTypes) {
      const normalized = entry.trim().toLowerCase();
      if (
        normalized &&
        normalized !== 'document' &&
        normalized !== 'script' &&
        normalized !== 'xhr' &&
        normalized !== 'fetch'
      ) {
        blockedTypes.add(normalized);
      }
    }
  }

  return blockedTypes.has(resourceType);
}

/**
 * Idempotently installs a catch-all `page.route(...)` handler on `page` using a `WeakSet`
 * guard so non-essential visual/tracker requests are aborted at most once per `Page`.
 */
export async function ensureFastPathResourceBlockingInstalled(
  page: PlaywrightPageLike,
  options?: FastPathResourceBlockerOptions,
  logger?: AuthLoggerPort
): Promise<boolean> {
  const safeLogger = logger ? createRedactingLogger(logger) : undefined;
  if (options?.enableFastPathResourceBlocking === false) {
    return false;
  }
  if (!page || typeof page !== 'object' || typeof page.route !== 'function') {
    safeLogger?.debug(
      'Skipping Playwright fast-path resource blocking: page.route is unavailable.'
    );
    return false;
  }
  if (fastPathBlockedPages.has(page)) {
    return true;
  }

  fastPathBlockedPages.add(page);
  try {
    await page.route('**/*', async (route, requestArg) => {
      const req =
        requestArg ??
        (typeof route.request === 'function' ? route.request() : undefined);
      const url = req ? req.url() : '';
      const resourceType =
        req && typeof req.resourceType === 'function' ? req.resourceType() : undefined;
      const method =
        req && typeof req.method === 'function' ? req.method() : undefined;

      try {
        if (shouldBlockFastPathRequest({ url, resourceType, method }, options)) {
          await route.abort();
          return;
        }
        await route.continue();
      } catch (routeErr) {
        safeLogger?.debug(
          `Playwright fast-path route handling skipped for settled/closed route: ${redactSensitiveErrorText(routeErr)}`
        );
      }
    });
    return true;
  } catch (err) {
    fastPathBlockedPages.delete(page);
    safeLogger?.warn(
      `Failed to install Playwright fast-path resource blocker: ${redactSensitiveErrorText(err)}`
    );
    return false;
  }
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
  /**
   * Opt-in Tier 2 fast-path resource blocking (`image`, `font`, `media`, tracker domains)
   * automatically installed via `page.route(...)` before navigation.
   */
  enableFastPathResourceBlocking?: boolean;
  /**
   * Fine-grained configuration for Tier 2 fast-path resource blocking.
   */
  fastPathResourceBlockerOptions?: FastPathResourceBlockerOptions;
}

function isTransientNavigationError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  if (
    /target closed|page has been closed|browser has been closed|context has been closed|has been closed/i.test(
      msg
    )
  ) {
    return false;
  }
  return /execution context was destroyed|most likely because of a navigation|cannot find context|frame was detached|navigating to|navigation in progress|interrupted by.*navigation/i.test(
    msg
  );
}

export function resolveFastPathResourceBlockerOptions(options: {
  enableFastPathResourceBlocking?: boolean;
  fastPathResourceBlockerOptions?: FastPathResourceBlockerOptions;
}): FastPathResourceBlockerOptions | undefined {
  const enabled =
    options.enableFastPathResourceBlocking ??
    options.fastPathResourceBlockerOptions?.enableFastPathResourceBlocking ??
    false;
  if (!enabled) {
    return undefined;
  }
  return {
    ...options.fastPathResourceBlockerOptions,
    enableFastPathResourceBlocking: true
  };
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
  private readonly fastPathBlockerOptions?: FastPathResourceBlockerOptions;
  private readonly logger?: AuthLoggerPort;
  private readonly flowSpec: PolimiLoginFlowSpec = POLIMI_LOGIN_FLOW_SPEC;
  private lastNavigationHttpStatus?: number;
  private lastNavigationUrl?: string;

  constructor(page: PlaywrightPageLike, options: PlaywrightAuthPageDriverOptions = {}) {
    this.page = page;
    this.options = options;
    this.federatedProviderId = options.federatedProviderSpec?.providerId ?? '';
    this.fastPathBlockerOptions = resolveFastPathResourceBlockerOptions(options);
    this.logger = options.logger ? createRedactingLogger(options.logger) : undefined;
  }

  /**
   * Installs the Tier 2 fast-path asset blocker (`page.route(...)`) on the
   * bound Playwright `Page` if `enableFastPathResourceBlocking` is enabled.
   */
  public async installFastPathResourceBlocker(): Promise<boolean> {
    if (!this.fastPathBlockerOptions) {
      return false;
    }
    return ensureFastPathResourceBlockingInstalled(
      this.page,
      this.fastPathBlockerOptions,
      this.logger
    );
  }

  private safeCurrentUrl(): string {
    try {
      return this.page.url() || '';
    } catch {
      return '';
    }
  }

  private getCurrentHttpStatus(currentUrl: string): number | undefined {
    if (this.lastNavigationHttpStatus === undefined) {
      return undefined;
    }
    if (this.lastNavigationUrl && currentUrl && this.lastNavigationUrl !== currentUrl) {
      this.lastNavigationHttpStatus = undefined;
      this.lastNavigationUrl = undefined;
      return undefined;
    }
    return this.lastNavigationHttpStatus;
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
          const currentUrl = this.safeCurrentUrl();
          const diagnosticError =
            err instanceof PoliAuthDiagnosticError
              ? err
              : new PoliAuthDiagnosticError(
                  classifyPolimiFailure({
                    component: '@polisdk/poliauth-playwright',
                    operation: operationName,
                    url: currentUrl,
                    httpStatus: this.getCurrentHttpStatus(currentUrl),
                    error: err
                  })
                );
          this.logger?.error(`Playwright ${operationName} failed: ${redacted}`);
          throw diagnosticError;
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
    this.lastNavigationHttpStatus = undefined;
    this.lastNavigationUrl = undefined;
    try {
      await this.installFastPathResourceBlocker();
      const response = await this.page.goto(url, {
        waitUntil: 'domcontentloaded',
        timeout: timeoutMs ?? this.options.navigationTimeoutMs ?? 35_000
      });
      if (response && typeof response === 'object') {
        const statusFn = (response as { status?: unknown }).status;
        if (typeof statusFn === 'function') {
          const numericStatus = Number((statusFn as () => unknown).call(response));
          if (Number.isFinite(numericStatus) && numericStatus > 0) {
            const urlFn = (response as { url?: unknown }).url;
            const resolvedUrl =
              typeof urlFn === 'function'
                ? String((urlFn as () => unknown).call(response) || '')
                : this.safeCurrentUrl();
            this.lastNavigationHttpStatus = numericStatus;
            this.lastNavigationUrl = resolvedUrl || url;
          }
        }
      }
    } catch (err) {
      const diagnosticError =
        err instanceof PoliAuthDiagnosticError
          ? err
          : new PoliAuthDiagnosticError(
              classifyPolimiFailure({
                component: '@polisdk/poliauth-playwright',
                operation: 'goto',
                stage: 'entry',
                url,
                selectorOrEndpoint: url,
                error: err
              })
            );
      this.logger?.error(`Playwright goto failed: ${diagnosticError.message}`);
      throw diagnosticError;
    }
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
      const currentUrl = this.safeCurrentUrl();
      const httpStatus = this.getCurrentHttpStatus(currentUrl);
      const inspection = await this.evaluateWithRetry('inspectPolimiStage', () =>
        this.page.evaluate((status) => {
          const loc = {
            hostname: window.location.hostname,
            pathname: window.location.pathname,
            search: window.location.search,
            href: window.location.href
          };
          return window.__PoliAuthAdapters!.polimi.inspectPolimiPageStage(
            document,
            loc,
            status !== undefined ? { httpStatus: status } : undefined
          );
        }, httpStatus)
      );
      if (inspection.stage === 'unknown' && !inspection.diagnosticError) {
        const effectiveStatus = inspection.httpStatus ?? httpStatus;
        const diagnosticError = classifyPolimiFailure({
          component: '@polisdk/poliauth-playwright',
          operation: 'inspectPolimiStage',
          stage: 'unknown',
          url: inspection.url || currentUrl,
          httpStatus: effectiveStatus,
          diagnosticSnapshot: inspection.diagnosticSnapshot
        });
        return {
          ...inspection,
          ...(effectiveStatus !== undefined ? { httpStatus: effectiveStatus } : {}),
          diagnosticError
        };
      }
      return inspection;
    } catch (err) {
      if (err instanceof PoliAuthDiagnosticError || !isTransientNavigationError(err)) {
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
    const beforeUrl = this.page.url();
    try {
      const recovery = await this.evaluateWithRetry('recoverSessionPage', () =>
        this.page.evaluate(() => {
          return window.__PoliAuthAdapters!.polimi.recoverPolimiSessionPage(document);
        })
      );
      if (!recovery.ok) {
        const targetUrl =
          recovery.navigatedTo || this.flowSpec.entry.serviceEntryUrl;
        await this.goto(targetUrl);
        return { ok: true, navigatedTo: targetUrl };
      }

      if (typeof this.page.waitForURL === 'function') {
        await this.page
          .waitForURL(
            (nextUrl) =>
              nextUrl.href !== beforeUrl ||
              !nextUrl.pathname.includes(this.flowSpec.entry.sessionTerminatedMarker),
            { timeout: 1_800, waitUntil: 'domcontentloaded' }
          )
          .catch(() => undefined);
      } else if (this.page.waitForTimeout) {
        await this.page.waitForTimeout(100).catch(() => undefined);
      }
      await this.waitForNavigation(1_800);

      if (
        beforeUrl.includes(this.flowSpec.entry.sessionTerminatedMarker) &&
        this.page.url().includes(this.flowSpec.entry.sessionTerminatedMarker)
      ) {
        const targetUrl =
          recovery.navigatedTo || this.flowSpec.entry.serviceEntryUrl;
        await this.goto(targetUrl);
        return { ok: false, navigatedTo: targetUrl };
      }

      return recovery;
    } catch (err) {
      if (err instanceof PoliAuthDiagnosticError || !isTransientNavigationError(err)) {
        throw err;
      }
      this.logger?.warn(
        `Playwright recoverSessionPage interrupted by navigation; falling back to serviceEntryUrl: ${redactSensitiveErrorText(err)}`
      );
      const fallbackUrl = this.flowSpec.entry.serviceEntryUrl;
      await this.goto(fallbackUrl);
      return { ok: false, navigatedTo: fallbackUrl };
    }
  }

  async submitCredentials(params: PolimiCredentialSubmission): Promise<PolimiPageActionResult> {
    return this.evaluateWithRetry('submitCredentials', () =>
      this.page.evaluate((creds) => {
        const loc = {
          hostname: window.location.hostname,
          pathname: window.location.pathname,
          search: window.location.search,
          href: window.location.href
        };
        return window.__PoliAuthAdapters!.polimi.submitPolimiCredentials(
          document,
          creds,
          loc
        );
      }, params)
    );
  }

  async submitOtp(params: PolimiOtpSubmission): Promise<PolimiPageActionResult> {
    return this.evaluateWithRetry('submitOtp', () =>
      this.page.evaluate((p) => {
        const loc = {
          hostname: window.location.hostname,
          pathname: window.location.pathname,
          search: window.location.search,
          href: window.location.href
        };
        return window.__PoliAuthAdapters!.polimi.submitPolimiOtp(
          document,
          p,
          loc
        );
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
