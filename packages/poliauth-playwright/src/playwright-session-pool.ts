import { type IdentityId, normalizeIdentityId } from '@polisdk/poliauth/domain';
import type {
  ManagedSessionContext,
  SessionContextPoolPort,
  SessionPoolStats,
  SessionStateStorePort,
  AuthLoggerPort
} from '@polisdk/poliauth/interfaces';
import { getInjectedAuthAdapterBundleCode } from './injected-auth-bundle.js';
import type { PlaywrightPageLike } from './playwright-page-driver.js';

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
}

export interface PlaywrightBrowserLike<
  TContext extends PlaywrightContextLike<any> = PlaywrightContextLike<PlaywrightPageLike>,
  TPage = PlaywrightPageLike
> {
  newContext(options?: Record<string, unknown>): Promise<TContext>;
  close(): Promise<void>;
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
  private readonly entries = new Map<string, ManagedSessionContext<TContext, TPage>>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  private readonly sessionStateStore?: SessionStateStorePort<unknown>;
  private readonly maxBrowserContexts: number;
  private readonly browserContextIdleTtlMs: number;
  private readonly headless: boolean;
  private readonly browserLauncher?: () => Promise<PlaywrightBrowserLike<TContext, TPage>>;
  private readonly initScriptCode?: string;
  private readonly contextOptions?: Record<string, unknown>;
  private readonly logger?: AuthLoggerPort;

  constructor(options: PlaywrightSessionPoolOptions<TContext, TPage> = {}) {
    this.sessionStateStore = options.sessionStateStore;
    this.maxBrowserContexts = options.maxBrowserContexts ?? 4;
    this.browserContextIdleTtlMs = options.browserContextIdleTtlMs ?? 15 * 60_000;
    this.headless = options.headless ?? true;
    this.browserLauncher = options.browserLauncher;
    this.initScriptCode = options.initScriptCode;
    this.contextOptions = options.contextOptions;
    this.logger = options.logger;

    this.cleanupTimer = setInterval(() => {
      void this.evictExpiredContexts();
    }, 60_000);
    unrefIntervalIfSupported(this.cleanupTimer);
  }

  private async ensureBrowser(): Promise<PlaywrightBrowserLike<TContext, TPage>> {
    if (this.browser) {
      return this.browser;
    }

    if (this.browserLauncher) {
      this.browser = await this.browserLauncher();
      return this.browser;
    }

    const pw = await import('playwright');
    this.browser = (await pw.chromium.launch({
      headless: this.headless,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--no-sandbox',
        '--disable-dev-shm-usage'
      ]
    })) as unknown as PlaywrightBrowserLike<TContext, TPage>;
    return this.browser;
  }

  async acquireUserContext(
    userId: IdentityId
  ): Promise<ManagedSessionContext<TContext, TPage>> {
    const key = normalizeIdentityId(userId);
    const existing = this.entries.get(key);
    if (existing) {
      const pages = existing.context.pages();
      if (pages.length === 0 || !existing.primaryPage) {
        existing.primaryPage = await existing.context.newPage();
      }
      existing.activeLocks += 1;
      existing.lastActiveAt = Date.now();
      return existing;
    }

    await this.evictIfAtCapacity();
    const browser = await this.ensureBrowser();

    const savedState = this.sessionStateStore
      ? await this.sessionStateStore.loadSessionState(userId)
      : null;

    const baseOptions: Record<string, unknown> = {
      acceptDownloads: true,
      viewport: { width: 1366, height: 900 },
      locale: 'it-IT',
      ...this.contextOptions
    };

    if (savedState && typeof savedState === 'object') {
      baseOptions.storageState = savedState;
    }

    let context: TContext;
    try {
      context = await browser.newContext(baseOptions);
    } catch {
      delete baseOptions.storageState;
      context = await browser.newContext(baseOptions);
    }

    const scriptToInject = this.initScriptCode ?? getInjectedAuthAdapterBundleCode();
    await context.addInitScript(scriptToInject);

    const primaryPage = await context.newPage();
    const entry: ManagedSessionContext<TContext, TPage> = {
      userId,
      context,
      primaryPage,
      lastActiveAt: Date.now(),
      activeLocks: 1
    };
    this.entries.set(key, entry);
    return entry;
  }

  releaseUserContext(userId: IdentityId): void {
    const entry = this.entries.get(normalizeIdentityId(userId));
    if (entry) {
      entry.activeLocks = Math.max(0, entry.activeLocks - 1);
      entry.lastActiveAt = Date.now();
    }
  }

  async getOrCreatePrimaryPage(
    managed: ManagedSessionContext<TContext, TPage>
  ): Promise<TPage> {
    const pages = managed.context.pages();
    if (pages.length > 0 && managed.primaryPage) {
      return managed.primaryPage;
    }
    const page = await managed.context.newPage();
    managed.primaryPage = page;
    return page;
  }

  async saveUserContextState(userId: IdentityId): Promise<void> {
    if (!this.sessionStateStore) return;
    const key = normalizeIdentityId(userId);
    const entry = this.entries.get(key);
    if (!entry) return;

    try {
      const state = await entry.context.storageState();
      await this.sessionStateStore.saveSessionState(entry.userId, state);
    } catch (err) {
      this.logger?.warn(`Failed to persist storageState for user ${key}`, err);
    }
  }

  async destroyUserContext(
    userId: IdentityId,
    options?: { skipSaveState?: boolean; clearPersistedState?: boolean }
  ): Promise<void> {
    const key = normalizeIdentityId(userId);
    const entry = this.entries.get(key);
    if (entry) {
      if (!options?.skipSaveState && !options?.clearPersistedState) {
        await this.saveUserContextState(userId);
      }
      this.entries.delete(key);
      await entry.context.close().catch(() => undefined);
    }
    if (options?.clearPersistedState && this.sessionStateStore) {
      await this.sessionStateStore.clearSessionState(userId).catch(() => undefined);
    }
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

  private async evictIfAtCapacity(): Promise<void> {
    if (this.entries.size < this.maxBrowserContexts) {
      return;
    }

    const idleEntries = Array.from(this.entries.entries())
      .filter(([, e]) => e.activeLocks === 0)
      .sort((a, b) => a[1].lastActiveAt - b[1].lastActiveAt);

    while (this.entries.size >= this.maxBrowserContexts && idleEntries.length > 0) {
      const [victimKey, victimEntry] = idleEntries.shift()!;
      await this.saveUserContextState(victimEntry.userId);
      this.entries.delete(victimKey);
      await victimEntry.context.close().catch(() => undefined);
    }
  }

  async evictExpiredContexts(now: number = Date.now()): Promise<void> {
    for (const [key, entry] of Array.from(this.entries.entries())) {
      if (
        entry.activeLocks === 0 &&
        now - entry.lastActiveAt > this.browserContextIdleTtlMs
      ) {
        await this.saveUserContextState(entry.userId);
        this.entries.delete(key);
        await entry.context.close().catch(() => undefined);
      }
    }
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
      browserConnected: this.browser !== null
    };
  }

  async closeAll(): Promise<void> {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }

    for (const [key, entry] of Array.from(this.entries.entries())) {
      await this.saveUserContextState(entry.userId);
      this.entries.delete(key);
      await entry.context.close().catch(() => undefined);
    }

    if (this.browser) {
      await this.browser.close().catch(() => undefined);
      this.browser = null;
    }
  }
}
