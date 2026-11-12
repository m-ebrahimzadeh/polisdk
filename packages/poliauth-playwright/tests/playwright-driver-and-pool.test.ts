import { describe, expect, it } from 'vitest';
import { JSDOM } from 'jsdom';
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

describe('@polisdk/poliauth-playwright — Driver, Bundle Injection & Session Pool', () => {
  it('embeds precompiled IIFE bundle code without runtime esbuild or filesystem calls and evaluates in browser DOM', () => {
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
    expect(typeof injected.webexSso.submitWebexEmailLogin).toBe('function');

    const stage = injected.polimi.inspectPolimiPageStage(
      dom.window.document,
      dom.window.location
    );
    expect(stage.stage).toBe('otp');
  });

  it('executes PlaywrightAuthPageDriver methods against a JSDOM-backed PlaywrightPageLike', async () => {
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

    const mockPage: PlaywrightPageLike = {
      url: () => dom.window.location.href,
      goto: async () => undefined,
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

    await ensureAuthAdaptersInjected(mockPage);
    const driver = new PlaywrightAuthPageDriver(mockPage);
    const stage = await driver.inspectPolimiStage();
    expect(stage.stage).toBe('credentials');

    const submitRes = await driver.submitCredentials({
      personCode: '10987654',
      password: 'MyPassword!'
    });
    expect(submitRes.ok).toBe(true);
    expect(clicked).toBe(true);
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
