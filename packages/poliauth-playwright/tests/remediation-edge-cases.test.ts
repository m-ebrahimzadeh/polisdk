import { describe, expect, it } from 'vitest';
import {
  PlaywrightAuthPageDriver,
  PlaywrightBrowserSessionPool,
  ensureAuthAdaptersInjected,
  type PlaywrightBrowserLike,
  type PlaywrightContextLike,
  type PlaywrightPageLike
} from '../src/index.js';

function createMockPage(
  overrides: Partial<PlaywrightPageLike> = {}
): PlaywrightPageLike {
  return {
    url: () => 'https://aunicalogin.polimi.it/aunicalogin/',
    goto: async () => {},
    waitForLoadState: async () => {},
    waitForTimeout: async () => {},
    evaluate: async <R, _Arg = void>() => undefined as unknown as R,
    ...overrides
  };
}

describe('Phase 5B Remediation Edge Cases (@polisdk/poliauth-playwright)', () => {
  it('fails fast on closed target/page/browser errors instead of faking sso_handoff', async () => {
    let evalCount = 0;
    const closedPage = createMockPage({
      evaluate: async <R, _Arg = void>() => {
        evalCount += 1;
        throw new Error('Target page, context or browser has been closed');
      }
    });

    const driver = new PlaywrightAuthPageDriver(closedPage, {
      maxTransientRetries: 3
    });

    await expect(driver.inspectPolimiStage()).rejects.toThrow(/has been closed/i);
    // Should throw on first inspect attempt without retrying closed target errors
    expect(evalCount).toBe(1);
  });

  it('falls back to page.addScriptTag when CSP blocks page.evaluate(bundleCode)', async () => {
    const addedScripts: Array<{ content?: string }> = [];
    let adaptersPresent = false;

    const cspPage = createMockPage({
      evaluate: async <R, _Arg = void>(
        fnOrCode: ((arg: _Arg) => R | Promise<R>) | string
      ): Promise<R> => {
        if (typeof fnOrCode === 'function') {
          return adaptersPresent as unknown as R;
        }
        throw new Error(
          "EvalError: Refused to evaluate a string as JavaScript because 'unsafe-eval' is blocked by Content Security Policy"
        );
      },
      addScriptTag: async (options) => {
        addedScripts.push({ content: options.content });
        adaptersPresent = true;
      }
    });

    const ok = await ensureAuthAdaptersInjected(cspPage);
    expect(ok).toBe(true);
    expect(addedScripts).toHaveLength(1);
    expect(addedScripts[0]?.content).toContain('__PoliAuthAdapters');
  });

  it('waits for URL change in recoverSessionPage and falls back to goto when still on SessioneTerminata', async () => {
    const gotoUrls: string[] = [];
    let currentUrl =
      'https://aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/logout/SessioneTerminataLogoutSSO.do';
    let waitForUrlCalled = false;

    const stuckPage = createMockPage({
      url: () => currentUrl,
      goto: async (targetUrl) => {
        gotoUrls.push(targetUrl);
        currentUrl = targetUrl;
      },
      waitForURL: async () => {
        waitForUrlCalled = true;
        // Simulates click that left browser stuck on SessioneTerminata
      },
      evaluate: async <R, _Arg = void>(
        fnOrCode: ((arg: _Arg) => R | Promise<R>) | string
      ): Promise<R> => {
        if (typeof fnOrCode === 'function') {
          const src = fnOrCode.toString();
          if (src.includes('recoverPolimiSessionPage')) {
            return { ok: true, navigatedTo: 'clicked-continue' } as unknown as R;
          }
          if (src.includes('__PoliAuthAdapters')) {
            return true as unknown as R;
          }
        }
        return undefined as unknown as R;
      }
    });

    const driver = new PlaywrightAuthPageDriver(stuckPage);
    const res = await driver.recoverSessionPage();
    expect(waitForUrlCalled).toBe(true);
    expect(res.ok).toBe(false);
    expect(gotoUrls).toHaveLength(1);
    expect(gotoUrls[0]).toBe('clicked-continue');
  });

  it('deduplicates concurrent cold-start browser launches, serializes same-user context creation, rejects over-capacity when locked, and relaunches disconnected browsers', async () => {
    let launchCount = 0;
    let contextCount = 0;
    let connected = true;

    const pool = new PlaywrightBrowserSessionPool<
      PlaywrightContextLike<PlaywrightPageLike>,
      PlaywrightPageLike
    >({
      maxBrowserContexts: 2,
      initScriptCode: '/* noop */',
      browserLauncher: async (): Promise<PlaywrightBrowserLike> => {
        launchCount += 1;
        await new Promise((r) => setTimeout(r, 15));
        const activeConnected = connected;
        return {
          isConnected: () => connected && activeConnected,
          close: async () => {},
          newContext: async () => {
            contextCount += 1;
            const page = createMockPage({ isClosed: () => false });
            const pages = [page];
            return {
              pages: () => pages,
              newPage: async () => page,
              addInitScript: async () => {},
              storageState: async () => ({ cookies: [], origins: [] }),
              close: async () => {}
            };
          }
        };
      }
    });

    // 1. Concurrent cold starts share one browser launch AND concurrent same-user acquires create one context
    const [m1, m2, m3] = await Promise.all([
      pool.acquireUserContext('alice'),
      pool.acquireUserContext('alice'),
      pool.acquireUserContext('bob')
    ]);

    expect(launchCount).toBe(1);
    expect(contextCount).toBe(2);
    expect(m1.context).toBe(m2.context);
    expect(m2.activeLocks).toBe(2);
    expect(m3.activeLocks).toBe(1);

    // 2. Capacity exhausted while both contexts remain locked -> deterministic error instead of evicting locked user
    await expect(pool.acquireUserContext('charlie')).rejects.toThrow(
      /capacity reached \(2\/2\)/i
    );

    pool.releaseUserContext('alice');
    pool.releaseUserContext('alice');
    pool.releaseUserContext('bob');
    await pool.closeAll();

    // 3. Disconnected browser clears stale entries and relaunches cleanly
    const browserInstances: Array<{ connected: boolean }> = [];
    const poolDisconnect = new PlaywrightBrowserSessionPool({
      maxBrowserContexts: 2,
      initScriptCode: '/* noop */',
      browserLauncher: async (): Promise<PlaywrightBrowserLike> => {
        const instanceState = { connected: true };
        browserInstances.push(instanceState);
        return {
          isConnected: () => instanceState.connected,
          close: async () => {},
          newContext: async () => {
            contextCount += 1;
            const page = createMockPage({ isClosed: () => false });
            return {
              pages: () => [page],
              newPage: async () => page,
              addInitScript: async () => {},
              storageState: async () => ({ cookies: [], origins: [] }),
              close: async () => {}
            };
          }
        };
      }
    });

    const first = await poolDisconnect.acquireUserContext('dave');
    poolDisconnect.releaseUserContext('dave');
    browserInstances[0]!.connected = false;
    const second = await poolDisconnect.acquireUserContext('dave');
    expect(browserInstances).toHaveLength(2);
    expect(second.context).not.toBe(first.context);

    await poolDisconnect.closeAll();
  });
});
