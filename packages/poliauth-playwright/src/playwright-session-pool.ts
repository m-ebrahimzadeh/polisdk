import { type IdentityId, normalizeIdentityId } from '@polisdk/poliauth/domain';
import type {
  ManagedSessionContext,
  SessionContextPoolPort,
  SessionPoolStats,
  SessionStateStorePort,
  AuthLoggerPort
} from '@polisdk/poliauth/interfaces';
import { createRedactingLogger, redactSensitiveErrorText } from '@polisdk/poliauth/middleware';
import { getInjectedAuthAdapterBundleCode } from './injected-auth-bundle.js';
import {
  ensureFastPathResourceBlockingInstalled,
  resolveFastPathResourceBlockerOptions,
  type FastPathResourceBlockerOptions,
  type PlaywrightPageLike,
  type PlaywrightRequestLike,
  type PlaywrightRouteLike
} from './playwright-page-driver.js';

function unrefIntervalIfSupported(timer: unknown): void {
  if (
    typeof timer === 'object' &&
    timer !== null &&
    'unref' in timer &&
    typeof (timer as { unref?: unknown }).unref === 'function'
  ) {
    (timer as { unref: () => void }).unref();
  }
}

export interface PlaywrightContextLike<TPage = PlaywrightPageLike> {
  newPage(): Promise<TPage>;
  pages(): TPage[];
  addInitScript(script: string): Promise<void>;
  storageState(): Promise<unknown>;
  close(): Promise<void>;
  route?(
    url: string,
    handler: (
      route: PlaywrightRouteLike,
      request?: PlaywrightRequestLike
    ) => Promise<void> | void
  ): Promise<void> | void;
}

export interface PlaywrightBrowserLike<
  TContext extends PlaywrightContextLike<any> = PlaywrightContextLike<PlaywrightPageLike>,
  TPage = PlaywrightPageLike
> {
  newContext(options?: Record<string, unknown>): Promise<TContext>;
  close(): Promise<void>;
  isConnected?(): boolean;
}

export interface PlaywrightSessionPoolOptions<
  TContext extends PlaywrightContextLike<any> = PlaywrightContextLike<PlaywrightPageLike>,
  TPage = PlaywrightPageLike
> {
  /**
   * Encrypted or persistent session state store for loading/saving Playwright `storageState`.
   */
  sessionStateStore?: SessionStateStorePort<unknown>;
  /**
   * Maximum number of concurrent `BrowserContext` instances before LRU idle eviction.
   * Defaults to `4`.
   */
  maxBrowserContexts?: number;
  /**
   * Idle TTL in milliseconds after which unused `BrowserContext` instances are evicted.
   * Defaults to `900_000` (15 minutes).
   */
  browserContextIdleTtlMs?: number;
  /**
   * Whether to launch Chromium in headless mode when using the default Playwright launcher.
   * Defaults to `true`.
   */
  headless?: boolean;
  /**
   * Optional custom browser launcher (useful for dependency injection and unit testing).
   */
  browserLauncher?: () => Promise<PlaywrightBrowserLike<TContext, TPage>>;
  /**
   * Optional custom init script code to inject into every created `BrowserContext`.
   * Defaults to `getInjectedAuthAdapterBundleCode()`.
   */
  initScriptCode?: string;
  /**
   * Optional viewport and locale configuration for new contexts.
   */
  contextOptions?: Record<string, unknown>;
  /**
   * Optional structured logger.
   */
  logger?: AuthLoggerPort;
  /**
   * Opt-in Tier 2 fast-path resource blocking (`image`, `font`, `media`, tracker domains)
   * automatically installed on every primary page returned by the pool.
   */
  enableFastPathResourceBlocking?: boolean;
  /**
   * Fine-grained configuration for Tier 2 fast-path resource blocking.
   */
  fastPathResourceBlockerOptions?: FastPathResourceBlockerOptions;
}

export type PlaywrightBrowserSessionPoolOptions<
  TContext extends PlaywrightContextLike<any> = PlaywrightContextLike<PlaywrightPageLike>,
  TPage = PlaywrightPageLike
> = PlaywrightSessionPoolOptions<TContext, TPage>;

export interface PlaywrightManagedSessionContext<
  TContext = unknown,
  TPage = unknown
> extends ManagedSessionContext<TContext, TPage> {
  hasRestoredSessionState?: boolean;
}

/**
 * Multi-tenant Playwright `BrowserContext` session pool implementing `SessionContextPoolPort`.
 * Provides per-user cookie/session isolation, reference-counted active locks, LRU capacity eviction,
 * idle TTL cleanup, automatic `storageState` encryption/restoration, and init-script injection.
 */
export class PlaywrightBrowserSessionPool<
  TContext extends PlaywrightContextLike<any> = PlaywrightContextLike<PlaywrightPageLike>,
  TPage = PlaywrightPageLike
> implements SessionContextPoolPort<TContext, TPage>
{
  private browser: PlaywrightBrowserLike<TContext, TPage> | null = null;
  private browserLaunchPromise: Promise<PlaywrightBrowserLike<TContext, TPage>> | null = null;
  private poolMutexTail: Promise<void> = Promise.resolve();
  private readonly entries = new Map<string, PlaywrightManagedSessionContext<TContext, TPage>>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  private readonly sessionStateStore?: SessionStateStorePort<unknown>;
  private readonly maxBrowserContexts: number;
  private readonly browserContextIdleTtlMs: number;
  private readonly headless: boolean;
  private readonly browserLauncher?: () => Promise<PlaywrightBrowserLike<TContext, TPage>>;
  private readonly initScriptCode?: string;
  private readonly contextOptions?: Record<string, unknown>;
  private readonly fastPathResourceBlockerOptions?: FastPathResourceBlockerOptions;
  private readonly logger?: AuthLoggerPort;

  constructor(options: PlaywrightSessionPoolOptions<TContext, TPage> = {}) {
    this.sessionStateStore = options.sessionStateStore;
    this.maxBrowserContexts = Math.max(1, options.maxBrowserContexts ?? 4);
    this.browserContextIdleTtlMs = options.browserContextIdleTtlMs ?? 15 * 60_000;
    this.headless = options.headless ?? true;
    this.browserLauncher = options.browserLauncher;
    this.initScriptCode = options.initScriptCode;
    this.contextOptions = options.contextOptions;
    this.fastPathResourceBlockerOptions = resolveFastPathResourceBlockerOptions(options);
    this.logger = options.logger ? createRedactingLogger(options.logger) : undefined;

    this.cleanupTimer = setInterval(() => {
      void this.evictExpiredContexts();
    }, 60_000);
    unrefIntervalIfSupported(this.cleanupTimer);
  }

  private withPoolMutex<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.poolMutexTail.then(fn, fn);
    this.poolMutexTail = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  }

  private isBrowserConnected(
    browser: PlaywrightBrowserLike<TContext, TPage> | null
  ): browser is PlaywrightBrowserLike<TContext, TPage> {
    if (!browser) return false;
    if (typeof browser.isConnected === 'function') {
      return browser.isConnected();
    }
    return true;
  }

  private async ensureBrowser(): Promise<PlaywrightBrowserLike<TContext, TPage>> {
    if (this.browser) {
      if (this.isBrowserConnected(this.browser)) {
        return this.browser;
      }
      this.logger?.warn(
        'Playwright browser is disconnected; clearing stale pool entries and relaunching.'
      );
      this.entries.clear();
      this.browser = null;
    }

    if (this.browserLaunchPromise) {
      return this.browserLaunchPromise;
    }

    const launchPromise = (async () => {
      if (this.browserLauncher) {
        const launched = await this.browserLauncher();
        this.browser = launched;
        return launched;
      }

      const pw = await import('playwright');
      const launched = (await pw.chromium.launch({
        headless: this.headless,
        args: [
          '--disable-blink-features=AutomationControlled',
          '--no-sandbox',
          '--disable-dev-shm-usage'
        ]
      })) as unknown as PlaywrightBrowserLike<TContext, TPage>;
      this.browser = launched;
      return launched;
    })();

    this.browserLaunchPromise = launchPromise;
    try {
      return await launchPromise;
    } finally {
      if (this.browserLaunchPromise === launchPromise) {
        this.browserLaunchPromise = null;
      }
    }
  }

  private isPageOpen(page: TPage | null | undefined): page is TPage {
    if (!page) return false;
    const maybePage = page as unknown as { isClosed?: () => boolean };
    if (typeof maybePage.isClosed === 'function') {
      return !maybePage.isClosed();
    }
    return true;
  }

  private async applyFastPathBlockerIfEnabled(page: TPage): Promise<void> {
    if (!this.fastPathResourceBlockerOptions) {
      return;
    }
    await ensureFastPathResourceBlockingInstalled(
      page as unknown as PlaywrightPageLike,
      this.fastPathResourceBlockerOptions,
      this.logger
    );
  }

  private async persistEntryState(
    entry: PlaywrightManagedSessionContext<TContext, TPage>
  ): Promise<void> {
    if (!this.sessionStateStore) return;
    const key = normalizeIdentityId(entry.userId);
    try {
      const state = await entry.context.storageState();
      await this.sessionStateStore.saveSessionState(entry.userId, state);
      entry.hasRestoredSessionState = true;
    } catch (err) {
      this.logger?.warn(
        `Failed to persist storageState for user ${key}: ${redactSensitiveErrorText(err)}`
      );
    }
  }

  async acquireUserContext(
    userId: IdentityId
  ): Promise<PlaywrightManagedSessionContext<TContext, TPage>> {
    return this.withPoolMutex(async () => {
      const key = normalizeIdentityId(userId);
      const browser = await this.ensureBrowser();

      const existing = this.entries.get(key);
      if (existing) {
        await this.getOrCreatePrimaryPage(existing);
        existing.activeLocks += 1;
        existing.lastActiveAt = Date.now();
        return existing;
      }

      await this.evictIfAtCapacityLocked();

      const savedState = this.sessionStateStore
        ? await this.sessionStateStore.loadSessionState(userId)
        : null;

      const baseOptions: Record<string, unknown> = {
        acceptDownloads: true,
        viewport: { width: 1366, height: 900 },
        locale: 'it-IT',
        ...this.contextOptions
      };

      let hasRestoredSessionState = false;
      if (savedState && typeof savedState === 'object') {
        baseOptions.storageState = savedState;
        hasRestoredSessionState = true;
      }

      let context: TContext;
      try {
        context = await browser.newContext(baseOptions);
      } catch (err) {
        this.logger?.warn(
          `Failed to restore persisted Playwright storageState for user ${key}; creating fresh BrowserContext: ${redactSensitiveErrorText(err)}`
        );
        delete baseOptions.storageState;
        hasRestoredSessionState = false;
        context = await browser.newContext(baseOptions);
      }

      const scriptToInject = this.initScriptCode ?? getInjectedAuthAdapterBundleCode();
      await context.addInitScript(scriptToInject);

      const primaryPage = await context.newPage();
      await this.applyFastPathBlockerIfEnabled(primaryPage);

      const entry: PlaywrightManagedSessionContext<TContext, TPage> = {
        userId,
        context,
        primaryPage,
        lastActiveAt: Date.now(),
        activeLocks: 1,
        hasRestoredSessionState
      };
      this.entries.set(key, entry);
      return entry;
    });
  }

  releaseUserContext(userId: IdentityId): void {
    const entry = this.entries.get(normalizeIdentityId(userId));
    if (entry) {
      entry.activeLocks = Math.max(0, entry.activeLocks - 1);
      entry.lastActiveAt = Date.now();
    }
  }

  private async resolveOrCreateOpenPage(
    managed: ManagedSessionContext<TContext, TPage>
  ): Promise<TPage> {
    const pages = managed.context.pages();
    if (
      managed.primaryPage &&
      this.isPageOpen(managed.primaryPage) &&
      pages.includes(managed.primaryPage)
    ) {
      return managed.primaryPage;
    }

    const openFallback = pages.find((p) => this.isPageOpen(p));
    if (openFallback) {
      managed.primaryPage = openFallback;
      return openFallback;
    }

    const page = await managed.context.newPage();
    managed.primaryPage = page;
    return page;
  }

  async getOrCreatePrimaryPage(
    managed: ManagedSessionContext<TContext, TPage>
  ): Promise<TPage> {
    const page = await this.resolveOrCreateOpenPage(managed);
    await this.applyFastPathBlockerIfEnabled(page);
    return page;
  }

  async saveUserContextState(userId: IdentityId): Promise<void> {
    if (!this.sessionStateStore) return;
    const key = normalizeIdentityId(userId);
    const entry = this.entries.get(key);
    if (!entry) return;
    await this.persistEntryState(entry);
  }

  async destroyUserContext(
    userId: IdentityId,
    options?: { skipSaveState?: boolean; clearPersistedState?: boolean }
  ): Promise<void> {
    return this.withPoolMutex(async () => {
      const key = normalizeIdentityId(userId);
      const entry = this.entries.get(key);
      if (entry) {
        if (!options?.skipSaveState && !options?.clearPersistedState) {
          await this.persistEntryState(entry);
        }
        this.entries.delete(key);
        await entry.context.close().catch(() => undefined);
      }
      if (options?.clearPersistedState && this.sessionStateStore) {
        await this.sessionStateStore.clearSessionState(userId).catch(() => undefined);
      }
    });
  }

  /**
   * Convenience helper that acquires a user context, executes `fn`, saves `storageState`, and releases the lock.
   */
  async withUserContext<TResult>(
    userId: IdentityId,
    fn: (managed: ManagedSessionContext<TContext, TPage> & { page: TPage }) => Promise<TResult>
  ): Promise<TResult> {
    const managed = await this.acquireUserContext(userId);
    try {
      const page = await this.getOrCreatePrimaryPage(managed);
      const result = await fn({
        ...managed,
        page
      });
      await this.saveUserContextState(userId);
      return result;
    } finally {
      this.releaseUserContext(userId);
    }
  }

  private async evictIfAtCapacityLocked(): Promise<void> {
    if (this.entries.size < this.maxBrowserContexts) {
      return;
    }

    const idleEntries = Array.from(this.entries.entries())
      .filter(([, e]) => e.activeLocks === 0)
      .sort((a, b) => a[1].lastActiveAt - b[1].lastActiveAt);

    while (this.entries.size >= this.maxBrowserContexts && idleEntries.length > 0) {
      const [victimKey, victimEntry] = idleEntries.shift()!;
      this.entries.delete(victimKey);
      await this.persistEntryState(victimEntry);
      await victimEntry.context.close().catch(() => undefined);
    }

    if (this.entries.size >= this.maxBrowserContexts) {
      throw new Error(
        `PlaywrightBrowserSessionPool capacity reached (${this.entries.size}/${this.maxBrowserContexts}): all active contexts are locked.`
      );
    }
  }

  async evictExpiredContexts(now: number = Date.now()): Promise<void> {
    return this.withPoolMutex(async () => {
      for (const [key, entry] of Array.from(this.entries.entries())) {
        if (
          entry.activeLocks === 0 &&
          now - entry.lastActiveAt > this.browserContextIdleTtlMs
        ) {
          this.entries.delete(key);
          await this.persistEntryState(entry);
          await entry.context.close().catch(() => undefined);
        }
      }
    });
  }

  getStats(): SessionPoolStats {
    let busyContexts = 0;
    for (const entry of this.entries.values()) {
      if (entry.activeLocks > 0) {
        busyContexts += 1;
      }
    }
    return {
      activeContexts: this.entries.size,
      busyContexts,
      browserConnected: this.isBrowserConnected(this.browser)
    };
  }

  async closeAll(): Promise<void> {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }

    return this.withPoolMutex(async () => {
      for (const [key, entry] of Array.from(this.entries.entries())) {
        this.entries.delete(key);
        await this.persistEntryState(entry);
        await entry.context.close().catch(() => undefined);
      }

      if (this.browser) {
        await this.browser.close().catch(() => undefined);
        this.browser = null;
      }
    });
  }
}
