import { describe, expect, it, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import type { AuthLoggerPort, FederatedSsoProviderSpec } from '@polisdk/poliauth/interfaces';
import { InMemorySessionStateStore } from '@polisdk/poliauth/storage';
import {
  DEFAULT_FAST_PATH_BLOCKED_RESOURCE_TYPES,
  DEFAULT_FAST_PATH_BLOCKED_TRACKER_DOMAINS,
  ensureAuthAdaptersInjected,
  ensureFastPathResourceBlockingInstalled,
  getInjectedAuthAdapterBundleCode,
  PlaywrightAuthPageDriver,
  PlaywrightBrowserSessionPool,
  shouldBlockFastPathRequest,
  type PlaywrightBrowserLike,
  type PlaywrightContextLike,
  type PlaywrightPageLike,
  type PlaywrightRequestLike,
  type PlaywrightRouteLike
} from '../src/index.js';

function createJsdomPage(dom: JSDOM): PlaywrightPageLike {
  return {
    url: () => dom.window.location.href,
    goto: async () => undefined,
    waitForLoadState: async () => undefined,
    waitForTimeout: async () => undefined,
    evaluate: async <R, Arg = void>(
      fnOrStr: ((arg: Arg) => R | Promise<R>) | string,
      arg?: Arg
    ): Promise<R> => {
      if (typeof fnOrStr === 'string') {
        return dom.window.eval(fnOrStr) as R;
      }
      const prevWindow = (globalThis as any).window;
      const prevDoc = (globalThis as any).document;
      try {
        (globalThis as any).window = dom.window;
        (globalThis as any).document = dom.window.document;
        return await fnOrStr(arg as Arg);
      } finally {
        (globalThis as any).window = prevWindow;
        (globalThis as any).document = prevDoc;
      }
    }
  };
}

describe('@polisdk/poliauth-playwright — Driver, Bundle Injection & Session Pool', () => {
  it('embeds precompiled IIFE bundle code exposing only generic polimi and federatedSso adapters', () => {
    const bundleCode = getInjectedAuthAdapterBundleCode();
    expect(bundleCode.length).toBeGreaterThan(500);

    const dom = new JSDOM(`<!DOCTYPE html><html><body><input id="otp" name="otp" /></body></html>`, {
      url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do',
      runScripts: 'outside-only'
    });

    dom.window.eval(bundleCode);
    const injected = (dom.window as unknown as { __PoliAuthAdapters: Record<string, any> })
      .__PoliAuthAdapters;
    expect(injected).toBeDefined();
    expect(typeof injected.polimi.inspectPolimiPageStage).toBe('function');
    expect(typeof injected.federatedSso.inspectFederatedSsoPageBySpec).toBe('function');
    expect(typeof injected.federatedSso.submitFederatedIdentifierBySpec).toBe('function');
    expect(typeof injected.federatedSso.triggerFederatedLoginBySpec).toBe('function');
    expect(Object.keys(injected).sort()).toEqual(['federatedSso', 'polimi']);

    const stage = injected.polimi.inspectPolimiPageStage(
      dom.window.document,
      dom.window.location
    );
    expect(stage.stage).toBe('otp');
  });

  it('executes PlaywrightAuthPageDriver core PoliMi methods against a JSDOM-backed PlaywrightPageLike', async () => {
    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <form action="/aunicalogin/controller/IdentificazioneUnica.do" method="POST">
            <input id="login" name="login" type="text" />
            <input id="password" name="password" type="password" />
            <button type="submit" name="evn_conferma" id="visible-login-btn">Accedi</button>
          </form>
        </body>
      </html>`,
      {
        url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376',
        runScripts: 'outside-only'
      }
    );

    let clicked = false;
    dom.window.document.querySelector('#visible-login-btn')?.addEventListener('click', (e) => {
      e.preventDefault();
      clicked = true;
    });

    const mockPage = createJsdomPage(dom);
    await ensureAuthAdaptersInjected(mockPage);
    const driver = new PlaywrightAuthPageDriver(mockPage);
    expect(driver.federatedProviderId).toBe('');

    const stage = await driver.inspectPolimiStage();
    expect(stage.stage).toBe('credentials');

    const submitRes = await driver.submitCredentials({
      personCode: '10987654',
      password: 'MyPassword!'
    });
    expect(submitRes.ok).toBe(true);
    expect(clicked).toBe(true);

    await expect(driver.inspectFederatedSsoPage()).rejects.toThrow(/not configured/i);
  });

  it('Scenario 4: executes arbitrary custom FederatedSsoProviderSpec configs dynamically in PlaywrightAuthPageDriver (Mode A & Mode B)', async () => {
    // 1. Custom Mode A (identifierPrompt) SP — e.g., Zoom
    const zoomSpec: FederatedSsoProviderSpec = {
      providerId: 'zoom',
      displayName: 'Zoom',
      identifierPrompt: {
        hostnames: ['polimi-it.zoom.us'],
        pathnameSubstrings: ['/signin'],
        identifierInputSelector: 'input#zoom-email',
        submitButtonSelector: 'button#zoom-next',
        forceEnableSubmitButton: true
      },
      transitHostnames: ['polimi-it.zoom.us'],
      transitUrlSubstrings: ['/saml/sso'],
      authenticatedHostnames: ['zoom.us'],
      authenticatedSelectors: ['.zoom-dashboard']
    };

    const zoomDom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <form action="/saml/sso">
            <input id="zoom-email" type="email" />
            <button id="zoom-next" type="button" disabled>Continue</button>
          </form>
        </body>
      </html>`,
      { url: 'https://polimi-it.zoom.us/signin', runScripts: 'outside-only' }
    );
    let zoomClicked = false;
    zoomDom.window.document.querySelector('#zoom-next')?.addEventListener('click', () => {
      zoomClicked = true;
    });

    const zoomDriver = new PlaywrightAuthPageDriver(createJsdomPage(zoomDom), {
      federatedProviderSpec: zoomSpec
    });
    expect(zoomDriver.federatedProviderId).toBe('zoom');

    const zoomInspect = await zoomDriver.inspectFederatedSsoPage();
    expect(zoomInspect.providerId).toBe('zoom');
    expect(zoomInspect.status).toBe('login_required');
    expect(zoomInspect.isIdentifierPrompt).toBe(true);
    expect(zoomInspect.isLoginTrigger).toBe(false);

    const zoomSubmit = await zoomDriver.submitFederatedIdentifier('student@mail.polimi.it');
    expect(zoomSubmit.ok).toBe(true);
    expect(zoomClicked).toBe(true);

    // 2. Custom Mode B (loginTrigger) SP — e.g., WeBeep
    const webeepSpec: FederatedSsoProviderSpec = {
      providerId: 'webeep',
      displayName: 'WeBeep',
      entryUrl: 'https://webeep.polimi.it/login/index.php',
      loginTrigger: {
        hostnames: ['webeep.polimi.it'],
        pathnameSubstrings: ['/login/index.php'],
        triggerSelector: 'a.shibboleth-cta'
      },
      transitHostnames: ['shibidp.polimi.it'],
      transitUrlSubstrings: ['/auth/shibboleth/'],
      authenticatedHostnames: ['webeep.polimi.it'],
      authenticatedSelectors: ['.usermenu']
    };

    const webeepDom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <a class="shibboleth-cta" href="/auth/shibboleth/index.php">Login with PoliMi</a>
        </body>
      </html>`,
      { url: 'https://webeep.polimi.it/login/index.php', runScripts: 'outside-only' }
    );
    let webeepClicked = false;
    webeepDom.window.document.querySelector('.shibboleth-cta')?.addEventListener('click', (e) => {
      e.preventDefault();
      webeepClicked = true;
    });

    const webeepDriver = new PlaywrightAuthPageDriver(createJsdomPage(webeepDom)).withFederatedProviderSpec(
      webeepSpec
    );
    expect(webeepDriver.federatedProviderId).toBe('webeep');

    const webeepInspect = await webeepDriver.inspectFederatedSsoPage();
    expect(webeepInspect.providerId).toBe('webeep');
    expect(webeepInspect.status).toBe('login_required');
    expect(webeepInspect.isIdentifierPrompt).toBe(false);
    expect(webeepInspect.isLoginTrigger).toBe(true);

    const webeepTrigger = await webeepDriver.triggerFederatedLogin();
    expect(webeepTrigger.ok).toBe(true);
    expect(webeepClicked).toBe(true);
  });

  it('catches, logs (with secrets redacted), and retries transient Execution context was destroyed errors during 302 redirects', async () => {
    const dom = new JSDOM(
      `<!DOCTYPE html><html><body><div class="usermenu">OK</div></body></html>`,
      { url: 'https://webeep.polimi.it/my/', runScripts: 'outside-only' }
    );

    const logs: Array<{ level: string; message: string }> = [];
    const logger: AuthLoggerPort = {
      debug: (msg) => logs.push({ level: 'debug', message: msg }),
      info: (msg) => logs.push({ level: 'info', message: msg }),
      warn: (msg) => logs.push({ level: 'warn', message: msg }),
      error: (msg) => logs.push({ level: 'error', message: msg })
    };

    let evalCount = 0;
    const basePage = createJsdomPage(dom);
    const flakyPage: PlaywrightPageLike = {
      ...basePage,
      evaluate: async <R, Arg = void>(
        fnOrStr: ((arg: Arg) => R | Promise<R>) | string,
        arg?: Arg
      ): Promise<R> => {
        evalCount += 1;
        if (evalCount === 1) {
          throw new Error(
            'Execution context was destroyed, most likely because of a navigation to https://aunicalogin.polimi.it/?__pj1=SECRET_HMAC'
          );
        }
        return basePage.evaluate(fnOrStr, arg);
      }
    };

    const spec: FederatedSsoProviderSpec = {
      providerId: 'webeep',
      displayName: 'WeBeep',
      transitHostnames: ['shibidp.polimi.it'],
      transitUrlSubstrings: ['/auth/shibboleth/'],
      authenticatedHostnames: ['webeep.polimi.it'],
      authenticatedSelectors: ['.usermenu']
    };

    const driver = new PlaywrightAuthPageDriver(flakyPage, {
      federatedProviderSpec: spec,
      logger
    });

    const result = await driver.inspectFederatedSsoPage();
    expect(result.status).toBe('authenticated');
    expect(evalCount).toBeGreaterThan(1);
    expect(logs.some((l) => l.level === 'warn' && l.message.includes('Execution context was destroyed'))).toBe(
      true
    );
    expect(logs.some((l) => l.message.includes('SECRET_HMAC'))).toBe(false);
    expect(logs.some((l) => l.message.includes('__pj1=[REDACTED]'))).toBe(true);
  });

  it('manages per-user Playwright BrowserContexts with LRU eviction, active lock protection, and encrypted storageState persistence', async () => {
    const sessionStore = new InMemorySessionStateStore();
    const closedContexts: number[] = [];
    let contextSeq = 0;

    interface MockPage {
      id: number;
    }
    interface MockContext extends PlaywrightContextLike<MockPage> {
      id: number;
      restoredState?: unknown;
    }

    const mockBrowser: PlaywrightBrowserLike<MockContext, MockPage> = {
      async newContext(options?: Record<string, unknown>): Promise<MockContext> {
        contextSeq += 1;
        const id = contextSeq;
        const pagesList: MockPage[] = [];
        return {
          id,
          restoredState: options?.storageState,
          async newPage() {
            const p = { id };
            pagesList.push(p);
            return p;
          },
          pages() {
            return pagesList;
          },
          async addInitScript(_script: string) {},
          async storageState() {
            return { cookies: [{ name: 'user_ctx', value: `ctx-${id}` }] };
          },
          async close() {
            closedContexts.push(id);
          }
        };
      },
      async close() {}
    };

    const pool = new PlaywrightBrowserSessionPool<MockContext, MockPage>({
      sessionStateStore: sessionStore,
      maxBrowserContexts: 2,
      browserContextIdleTtlMs: 5_000,
      browserLauncher: async () => mockBrowser,
      initScriptCode: '// mock init script'
    });

    try {
      await pool.withUserContext(1, async ({ context }) => {
        expect(context.id).toBe(1);
      });
      await pool.withUserContext(2, async ({ context }) => {
        expect(context.id).toBe(2);
      });
      expect(pool.getStats().activeContexts).toBe(2);

      // Acquiring context for user 3 evicts LRU idle context (user 1) and persists its state
      await pool.withUserContext(3, async ({ context }) => {
        expect(context.id).toBe(3);
      });
      expect(closedContexts).toContain(1);
      expect(pool.getStats().activeContexts).toBe(2);

      // Re-acquiring context for user 1 restores its persisted storageState
      await pool.withUserContext(1, async ({ context }) => {
        expect(context.restoredState).toEqual({
          cookies: [{ name: 'user_ctx', value: 'ctx-1' }]
        });
      });

      await pool.destroyUserContext(1, { clearPersistedState: true });
      expect(await sessionStore.loadSessionState(1)).toBeNull();
    } finally {
      await pool.closeAll();
    }
  });
});

describe('TASK-7.3: Tier 2 Playwright Fast-Path Resource Blocker & Restored State Tracking', () => {
  type RouteHandler = (route: PlaywrightRouteLike, request: PlaywrightRequestLike) => Promise<void> | void;

  function createFastPathMockPage(initialUrl = 'https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376') {
    const events: string[] = [];
    const handlers: RouteHandler[] = [];
    let currentUrl = initialUrl;

    const routeMock = vi.fn(async (_pattern: string, handler: RouteHandler) => {
      events.push('route');
      handlers.push(handler);
    });

    const gotoMock = vi.fn(async (url: string) => {
      events.push(`goto:${url}`);
      currentUrl = url;
      return null;
    });

    const page = {
      url: () => currentUrl,
      title: vi.fn(async () => 'PoliMI Login'),
      goto: gotoMock,
      waitForLoadState: vi.fn(async () => {}),
      waitForSelector: vi.fn(async () => null),
      waitForFunction: vi.fn(async () => undefined),
      click: vi.fn(async () => {}),
      fill: vi.fn(async () => {}),
      type: vi.fn(async () => {}),
      press: vi.fn(async () => {}),
      evaluate: vi.fn(async () => undefined),
      content: vi.fn(async () => '<html></html>'),
      locator: vi.fn(() => ({
        first: () => ({
          count: vi.fn(async () => 0),
          isVisible: vi.fn(async () => false),
          textContent: vi.fn(async () => null),
        }),
      })),
      route: routeMock,
    };

    return {
      page,
      events,
      handlers,
      routeMock,
      gotoMock,
      async dispatch(req: { url: string; resourceType?: string; method?: string }) {
        const handler = handlers[0];
        if (!handler) {
          throw new Error('Expected route handler to be registered');
        }
        const abort = vi.fn(async () => {});
        const continueFn = vi.fn(async () => {});
        const route: PlaywrightRouteLike = {
          abort,
          continue: continueFn,
          request: () => ({
            url: () => req.url,
            resourceType: () => req.resourceType ?? 'other',
            method: () => req.method ?? 'GET',
          }),
        };
        const request: PlaywrightRequestLike = {
          url: () => req.url,
          resourceType: () => req.resourceType ?? 'other',
          method: () => req.method ?? 'GET',
        };
        await handler(route, request);
        return { abort, continue: continueFn };
      },
    };
  }

  it('evaluates shouldBlockFastPathRequest safely and guarantees WeakSet idempotency', async () => {
    expect(DEFAULT_FAST_PATH_BLOCKED_RESOURCE_TYPES).toEqual(['image', 'font', 'media']);
    expect(DEFAULT_FAST_PATH_BLOCKED_TRACKER_DOMAINS).toContain('google-analytics.com');

    expect(
      shouldBlockFastPathRequest({
        url: 'https://servizionline.polimi.it/assets/logo.png',
        resourceType: 'image',
        method: 'GET',
      }),
    ).toBe(true);
    expect(
      shouldBlockFastPathRequest({
        url: 'https://servizionline.polimi.it/assets/font.woff2',
        resourceType: 'font',
      }),
    ).toBe(true);
    expect(
      shouldBlockFastPathRequest({
        url: 'https://servizionline.polimi.it/assets/intro.mp4',
        resourceType: 'media',
      }),
    ).toBe(true);

    // Critical functional requests and default stylesheets stay allowed.
    expect(
      shouldBlockFastPathRequest({
        url: 'https://servizionline.polimi.it/portaleservizi/',
        resourceType: 'document',
        method: 'GET',
      }),
    ).toBe(false);
    expect(
      shouldBlockFastPathRequest({
        url: 'https://aunicalogin.polimi.it/aunicalogin/login.js',
        resourceType: 'script',
      }),
    ).toBe(false);
    expect(
      shouldBlockFastPathRequest({
        url: 'https://aunicalogin.polimi.it/aunicalogin/api/session',
        resourceType: 'xhr',
      }),
    ).toBe(false);
    expect(
      shouldBlockFastPathRequest({
        url: 'https://aunicalogin.polimi.it/aunicalogin/submit',
        resourceType: 'document',
        method: 'POST',
      }),
    ).toBe(false);
    expect(
      shouldBlockFastPathRequest({
        url: 'https://servizionline.polimi.it/app.css',
        resourceType: 'stylesheet',
      }),
    ).toBe(false);
    expect(
      shouldBlockFastPathRequest(
        {
          url: 'https://servizionline.polimi.it/app.css',
          resourceType: 'stylesheet',
        },
        { blockStylesheets: true },
      ),
    ).toBe(true);

    // Trackers (including tracker scripts / beacons) and custom overrides are blocked.
    expect(
      shouldBlockFastPathRequest({
        url: 'https://www.google-analytics.com/analytics.js',
        resourceType: 'script',
      }),
    ).toBe(true);
    expect(
      shouldBlockFastPathRequest({
        url: 'https://www.googletagmanager.com/gtm.js?id=GTM-123',
        resourceType: 'script',
      }),
    ).toBe(true);
    expect(
      shouldBlockFastPathRequest({
        url: 'https://www.clarity.ms/collect',
        resourceType: 'fetch',
        method: 'POST',
      }),
    ).toBe(true);
    expect(
      shouldBlockFastPathRequest(
        {
          url: 'https://cdn.example-tracker.test/pixel',
          resourceType: 'xhr',
        },
        { additionalBlockedDomainSubstrings: ['example-tracker.test'] },
      ),
    ).toBe(true);
    expect(
      shouldBlockFastPathRequest(
        {
          url: 'https://servizionline.polimi.it/favicon.ico',
          resourceType: 'other',
        },
        { additionalBlockedResourceTypes: ['other'] },
      ),
    ).toBe(true);

    const mock = createFastPathMockPage();
    expect(await ensureFastPathResourceBlockingInstalled({} as unknown as Parameters<typeof ensureFastPathResourceBlockingInstalled>[0])).toBe(false);
    expect(
      await ensureFastPathResourceBlockingInstalled(
        mock.page as unknown as Parameters<typeof ensureFastPathResourceBlockingInstalled>[0],
        { enableFastPathResourceBlocking: false },
      ),
    ).toBe(false);
    expect(mock.routeMock).not.toHaveBeenCalled();

    const first = await ensureFastPathResourceBlockingInstalled(
      mock.page as unknown as Parameters<typeof ensureFastPathResourceBlockingInstalled>[0],
    );
    const second = await ensureFastPathResourceBlockingInstalled(
      mock.page as unknown as Parameters<typeof ensureFastPathResourceBlockingInstalled>[0],
    );
    expect(first).toBe(true);
    expect(second).toBe(true);
    expect(mock.routeMock).toHaveBeenCalledTimes(1);
    expect(mock.routeMock).toHaveBeenCalledWith('**/*', expect.any(Function));

    const blockedRes = await mock.dispatch({
      url: 'https://servizionline.polimi.it/banner.png',
      resourceType: 'image',
    });
    expect(blockedRes.abort).toHaveBeenCalledTimes(1);
    expect(blockedRes.continue).not.toHaveBeenCalled();

    const allowedRes = await mock.dispatch({
      url: 'https://aunicalogin.polimi.it/aunicalogin/form',
      resourceType: 'document',
      method: 'POST',
    });
    expect(allowedRes.continue).toHaveBeenCalledTimes(1);
    expect(allowedRes.abort).not.toHaveBeenCalled();
  });

  it('registers route blocker before goto() once per page on PlaywrightAuthPageDriver', async () => {
    const mock = createFastPathMockPage();
    const driver = new PlaywrightAuthPageDriver(
      mock.page as unknown as ConstructorParameters<typeof PlaywrightAuthPageDriver>[0],
      {
        enableFastPathResourceBlocking: true,
        fastPathResourceBlockerOptions: {
          additionalBlockedResourceTypes: ['manifest'],
          additionalBlockedDomainSubstrings: ['analytics.vendor.test'],
        },
      },
    );

    await driver.goto('https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376');
    await driver.goto('https://servizionline.polimi.it/portaleservizi/');

    expect(mock.routeMock).toHaveBeenCalledTimes(1);
    expect(mock.events[0]).toBe('route');
    expect(mock.events[1]).toMatch(/^goto:/);
    expect(mock.gotoMock).toHaveBeenCalledTimes(2);

    for (const req of [
      { url: 'https://servizionline.polimi.it/img.webp', resourceType: 'image' },
      { url: 'https://servizionline.polimi.it/roboto.woff2', resourceType: 'font' },
      { url: 'https://servizionline.polimi.it/video.webm', resourceType: 'media' },
      { url: 'https://www.google-analytics.com/analytics.js', resourceType: 'script' },
      { url: 'https://www.googletagmanager.com/gtm.js', resourceType: 'script' },
      { url: 'https://c.clarity.ms/collect', resourceType: 'fetch', method: 'POST' },
      { url: 'https://servizionline.polimi.it/app.webmanifest', resourceType: 'manifest' },
      { url: 'https://analytics.vendor.test/sdk.js', resourceType: 'script' },
    ]) {
      const outcome = await mock.dispatch(req);
      expect(outcome.abort).toHaveBeenCalledTimes(1);
      expect(outcome.continue).not.toHaveBeenCalled();
    }

    for (const req of [
      { url: 'https://servizionline.polimi.it/portaleservizi/', resourceType: 'document', method: 'GET' },
      { url: 'https://aunicalogin.polimi.it/login.js', resourceType: 'script', method: 'GET' },
      { url: 'https://aunicalogin.polimi.it/api/me', resourceType: 'xhr', method: 'GET' },
      { url: 'https://aunicalogin.polimi.it/api/otp', resourceType: 'fetch', method: 'POST' },
      { url: 'https://aunicalogin.polimi.it/idp/Authn', resourceType: 'document', method: 'POST' },
      { url: 'https://servizionline.polimi.it/styles.css', resourceType: 'stylesheet', method: 'GET' },
    ]) {
      const outcome = await mock.dispatch(req);
      expect(outcome.continue).toHaveBeenCalledTimes(1);
      expect(outcome.abort).not.toHaveBeenCalled();
    }
  });

  it('installs blocker once per page on PlaywrightBrowserSessionPool and tracks hasRestoredSessionState', async () => {
    const sessionStore = new InMemorySessionStateStore();
    await sessionStore.saveSessionState(2, {
      cookies: [{ name: 'JSESSIONID', value: 'restored-token', domain: 'servizionline.polimi.it', path: '/' }],
      origins: [],
    });

    const pagesByUser = new Map<string, ReturnType<typeof createFastPathMockPage>>();
    const capturedStorageStates: unknown[] = [];

    const pool = new PlaywrightBrowserSessionPool({
      sessionStateStore: sessionStore,
      enableFastPathResourceBlocking: true,
      fastPathResourceBlockerOptions: { blockStylesheets: true },
      browserLauncher: async () => ({
        newContext: async (options?: { storageState?: unknown }) => {
          capturedStorageStates.push(options?.storageState ?? null);
          const key = options?.storageState ? 'restored' : 'fresh';
          const mockPage = createFastPathMockPage();
          pagesByUser.set(key, mockPage);
          const pages = [mockPage.page as unknown as PlaywrightPageLike];
          return {
            pages: () => pages,
            newPage: async () => mockPage.page as unknown as PlaywrightPageLike,
            addInitScript: vi.fn(async () => {}),
            storageState: async () => ({
              cookies: [{ name: 'SESSION', value: key, domain: 'servizionline.polimi.it', path: '/' }],
              origins: [],
            }),
            close: async () => {},
          };
        },
        close: async () => {},
      }),
    });

    try {
      // User 1 has no persisted state -> fresh context
      const freshManaged = await pool.acquireUserContext(1);
      expect(freshManaged.hasRestoredSessionState).toBe(false);
      await pool.getOrCreatePrimaryPage(freshManaged);
      await pool.getOrCreatePrimaryPage(freshManaged);
      const freshPage = pagesByUser.get('fresh');
      expect(freshPage).toBeDefined();
      expect(freshPage?.routeMock).toHaveBeenCalledTimes(1);

      // Verify blockStylesheets: true actually aborts stylesheets via pool blocker
      const cssOutcome = await freshPage!.dispatch({
        url: 'https://servizionline.polimi.it/theme.css',
        resourceType: 'stylesheet',
      });
      expect(cssOutcome.abort).toHaveBeenCalledTimes(1);

      // User 2 has persisted state -> restored context
      const restoredManaged = await pool.acquireUserContext(2);
      expect(restoredManaged.hasRestoredSessionState).toBe(true);
      expect(capturedStorageStates[1]).toBeTruthy();
      const restoredPage = pagesByUser.get('restored');
      expect(restoredPage).toBeDefined();
      expect(restoredPage?.routeMock).toHaveBeenCalledTimes(1);

      // Persisting state for User 1 marks hasRestoredSessionState as true on active entry
      await pool.saveUserContextState(1);
      expect(freshManaged.hasRestoredSessionState).toBe(true);
    } finally {
      await pool.closeAll();
    }
  });
});
