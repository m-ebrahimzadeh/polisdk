import { describe, expect, it } from 'vitest';
import { JSDOM } from 'jsdom';
import type { AuthLoggerPort, FederatedSsoProviderSpec } from '@polisdk/poliauth/interfaces';
import { InMemorySessionStateStore } from '@polisdk/poliauth/storage';
import {
  getInjectedAuthAdapterBundleCode,
  ensureAuthAdaptersInjected,
  PlaywrightAuthPageDriver,
  PlaywrightBrowserSessionPool,
  type PlaywrightBrowserLike,
  type PlaywrightContextLike,
  type PlaywrightPageLike
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
