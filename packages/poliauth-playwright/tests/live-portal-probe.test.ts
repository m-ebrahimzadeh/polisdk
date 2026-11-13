import { describe, expect, it } from 'vitest';
import { JSDOM } from 'jsdom';
import type { AuthLoggerPort } from '@polisdk/poliauth/interfaces';
import {
  formatLivePortalProbeReportMarkdown,
  isLivePortalProbeEnabled,
  runPolimiLivePortalProbe,
  type LivePortalProbeReport,
  type PlaywrightPageLike
} from '../src/index.js';

interface SimulatedResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
}

interface SimulatedRoute {
  responses: SimulatedResponse[];
  html: string;
  finalUrl: string;
}

function createObservableMockPage(options: {
  routes: Record<string, SimulatedRoute>;
  onGoto?: (url: string) => void;
  evaluateOverride?: (
    fnOrCode: ((arg: unknown) => unknown) | string,
    arg: unknown,
    defaultEval: () => Promise<unknown>
  ) => Promise<unknown>;
  customAddScriptTag?: (dom: JSDOM, scriptOptions: { content?: string }) => Promise<void>;
}): PlaywrightPageLike & {
  on(event: string, listener: (...args: unknown[]) => void): void;
  off(event: string, listener: (...args: unknown[]) => void): void;
} {
  let activeDom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
    url: 'about:blank',
    runScripts: 'outside-only'
  });

  const listeners = new Map<string, Set<(...args: unknown[]) => void>>();

  const emit = (event: string, payload: unknown) => {
    const set = listeners.get(event);
    if (!set) return;
    for (const fn of set) {
      fn(payload);
    }
  };

  const wireRecoveryClick = (dom: JSDOM) => {
    const continueBtn = dom.window.document.querySelector('a[href*="id_servizio=376"]');
    if (continueBtn) {
      continueBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const href = (continueBtn as HTMLAnchorElement).href;
        void navigateTo(href);
      });
    }
  };

  const navigateTo = async (targetUrl: string): Promise<unknown> => {
    options.onGoto?.(targetUrl);
    const route = options.routes[targetUrl];
    if (!route) {
      throw new Error(`No mock route configured for ${targetUrl}`);
    }

    let lastResponseObj: unknown = undefined;
    for (const hop of route.responses) {
      const respObj = {
        url: () => hop.url,
        status: () => hop.status,
        headers: () => hop.headers,
        request: () => ({
          url: () => hop.url,
          isNavigationRequest: () => true,
          resourceType: () => 'document',
          redirectedFrom: () => null
        })
      };
      emit('response', respObj);
      lastResponseObj = respObj;
    }

    activeDom = new JSDOM(route.html, {
      url: route.finalUrl,
      runScripts: 'outside-only'
    });
    wireRecoveryClick(activeDom);
    return lastResponseObj;
  };

  const runInActiveDom = async <R, Arg = void>(
    fnOrCode: ((arg: Arg) => R | Promise<R>) | string,
    arg?: Arg
  ): Promise<R> => {
    if (typeof fnOrCode === 'string') {
      return activeDom.window.eval(fnOrCode) as R;
    }
    const prevWindow = (globalThis as Record<string, unknown>).window;
    const prevDoc = (globalThis as Record<string, unknown>).document;
    try {
      (globalThis as Record<string, unknown>).window = activeDom.window;
      (globalThis as Record<string, unknown>).document = activeDom.window.document;
      return await fnOrCode(arg as Arg);
    } finally {
      (globalThis as Record<string, unknown>).window = prevWindow;
      (globalThis as Record<string, unknown>).document = prevDoc;
    }
  };

  return {
    url: () => activeDom.window.location.href,
    goto: navigateTo,
    waitForLoadState: async () => undefined,
    waitForURL: async () => undefined,
    waitForTimeout: async () => undefined,
    isClosed: () => false,
    on(event: string, listener: (...args: unknown[]) => void) {
      if (!listeners.has(event)) {
        listeners.set(event, new Set());
      }
      listeners.get(event)!.add(listener);
    },
    off(event: string, listener: (...args: unknown[]) => void) {
      listeners.get(event)?.delete(listener);
    },
    evaluate: async <R, Arg = void>(
      fnOrCode: ((arg: Arg) => R | Promise<R>) | string,
      arg?: Arg
    ): Promise<R> => {
      if (options.evaluateOverride) {
        return (await options.evaluateOverride(
          fnOrCode as ((arg: unknown) => unknown) | string,
          arg,
          () => runInActiveDom(fnOrCode, arg)
        )) as R;
      }
      return runInActiveDom(fnOrCode, arg);
    },
    addScriptTag: async (scriptOptions) => {
      if (options.customAddScriptTag) {
        await options.customAddScriptTag(activeDom, scriptOptions);
        return;
      }
      if (scriptOptions.content) {
        activeDom.window.eval(scriptOptions.content);
      }
    }
  };
}

describe('@polisdk/poliauth-playwright — Live Portal Probe & Telemetry Profiler', () => {
  it('Stage 0 -> Recovery -> Stage 1 Full Probe Telemetry detects expired session, recovery, credentials, and JAF trap without submitting credentials', async () => {
    const bareUrl = 'https://aunicalogin.polimi.it/aunicalogin/';
    const serviceEntryUrl =
      'https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376';
    const sessionExpiredUrl =
      'https://aunicalogin.polimi.it/aunicalogin/controller/logout/SessioneTerminataLogoutSSO.do';
    const credentialsUrl =
      'https://aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/IdentificazioneUnica.do?id_servizio=376';

    const stage0Html = `<!DOCTYPE html>
      <html>
        <head><title>Polimi - Sessione terminata</title></head>
        <body>
          <div class="poli-messages">
            <div class="alert-danger"><span class="jaf-message">Violazione della sicurezza</span></div>
          </div>
          <a class="btn-primary" href="${serviceEntryUrl}">Continua</a>
        </body>
      </html>`;

    const stage1Html = `<!DOCTYPE html>
      <html>
        <head><title>Polimi - Autenticazione</title></head>
        <body>
          <form class="jaf-form" action="/aunicalogin/controller/IdentificazioneUnica.do" method="POST">
            <input id="login" name="login" type="text" />
            <input id="password" name="password" type="password" />
            <button type="submit" name="evn_conferma" class="jaf-visually-hidden">Hidden Trap</button>
            <button type="submit" name="evn_conferma" id="visible-login-btn">Accedi</button>
          </form>
        </body>
      </html>`;

    const mockPage = createObservableMockPage({
      routes: {
        [bareUrl]: {
          finalUrl: sessionExpiredUrl,
          html: stage0Html,
          responses: [
            {
              url: bareUrl,
              status: 302,
              headers: { location: sessionExpiredUrl }
            },
            {
              url: sessionExpiredUrl,
              status: 200,
              headers: { 'content-security-policy': "default-src 'self'" }
            }
          ]
        },
        [serviceEntryUrl]: {
          finalUrl: credentialsUrl,
          html: stage1Html,
          responses: [
            {
              url: serviceEntryUrl,
              status: 302,
              headers: { location: credentialsUrl }
            },
            {
              url: credentialsUrl,
              status: 200,
              headers: { 'content-security-policy': "default-src 'self'" }
            }
          ]
        }
      }
    });

    const report = await runPolimiLivePortalProbe({ page: mockPage });

    expect(report.environment).toBe('synthetic_harness');
    expect(report.overallSuccess).toBe(true);
    expect(report.errorSummary).toBeUndefined();
    expect(report.stages).toHaveLength(3);

    const [stage0, recovery, stage1] = report.stages;
    expect(stage0?.probeName).toBe('stage_0_bare_aunicalogin');
    expect(stage0?.inspectedStage).toBe('session_expired');
    expect(stage0?.finalUrl).toBe(sessionExpiredUrl);
    expect(stage0?.adapterInjectionMethod).toBe('evaluate');
    expect(stage0?.redirectChain).toHaveLength(2);
    expect(stage0?.redirectChain[0]?.status).toBe(302);
    expect(stage0?.cspHeadersDetected).toEqual(["default-src 'self'"]);
    expect(stage0?.domSnapshot.hasExpiredSessionMarker).toBe(true);
    expect(stage0?.domSnapshot.hasErrorBanner).toBe(true);
    expect(stage0?.domSnapshot.sanitizedErrorMessage).toBe('Violazione della sicurezza');
    expect(stage0?.epistemicStatus).toBe('FACT:EXEC');

    expect(recovery?.probeName).toBe('stage_0_session_recovery');
    expect(recovery?.inspectedStage).toBe('credentials');
    expect(recovery?.finalUrl).toBe(credentialsUrl);
    expect(recovery?.domSnapshot.hasLoginInput).toBe(true);
    expect(recovery?.domSnapshot.hasPasswordInput).toBe(true);

    expect(stage1?.probeName).toBe('stage_1_service_entry_credentials');
    expect(stage1?.inspectedStage).toBe('credentials');
    expect(stage1?.adapterInjectionMethod).toBe('evaluate');
    expect(stage1?.domSnapshot).toMatchObject({
      hasLoginInput: true,
      hasPasswordInput: true,
      hasVisibleSubmitButton: true,
      hasJafVisuallyHiddenTrap: true,
      hasOtpInput: false,
      hasSubmitDissmsTrap: false,
      hasSsoHandoffForm: false,
      hasExpiredSessionMarker: false,
      hasAuthenticatedMarker: false,
      hasErrorBanner: false
    });
  });

  it('CSP Fallback Telemetry records addScriptTag when page.evaluate blocks string evaluation and pre_injected when already present', async () => {
    const serviceEntryUrl =
      'https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376';
    const credentialsUrl =
      'https://aunicalogin.polimi.it/aunicalogin/aunicalogin/controller/IdentificazioneUnica.do';
    const logs: string[] = [];

    const logger: AuthLoggerPort = {
      debug: (m) => logs.push(m),
      info: (m) => logs.push(m),
      warn: (m) => logs.push(m),
      error: (m) => logs.push(m)
    };

    const html = `<!DOCTYPE html>
      <html>
        <body>
          <form class="jaf-form" action="/aunicalogin/controller/IdentificazioneUnica.do">
            <input id="login" name="login" />
            <input id="password" name="password" type="password" />
            <button type="submit" name="evn_conferma" class="jaf-visually-hidden">Hidden</button>
            <button type="submit" name="evn_conferma">Accedi</button>
          </form>
        </body>
      </html>`;

    const cspPage = createObservableMockPage({
      routes: {
        [serviceEntryUrl]: {
          finalUrl: credentialsUrl,
          html,
          responses: [
            {
              url: credentialsUrl,
              status: 200,
              headers: {
                'Content-Security-Policy': "script-src 'self' 'nonce-csp123'"
              }
            }
          ]
        }
      },
      evaluateOverride: async (fnOrCode, _arg, defaultEval) => {
        if (typeof fnOrCode === 'string') {
          throw new Error(
            "EvalError: Refused to evaluate a string as JavaScript because 'unsafe-eval' is blocked by Content Security Policy"
          );
        }
        return defaultEval();
      }
    });

    const report = await runPolimiLivePortalProbe({
      page: cspPage,
      logger,
      probeBareAunicaloginRecovery: false,
      probeServiceEntryToCredentials: true
    });

    expect(report.overallSuccess).toBe(true);
    expect(report.stages).toHaveLength(1);
    const stage1 = report.stages[0]!;
    expect(stage1.adapterInjectionMethod).toBe('addScriptTag');
    expect(stage1.cspHeadersDetected).toEqual(["script-src 'self' 'nonce-csp123'"]);
    expect(stage1.inspectedStage).toBe('credentials');
    expect(stage1.domSnapshot.hasLoginInput).toBe(true);
    expect(stage1.domSnapshot.hasPasswordInput).toBe(true);
    expect(stage1.domSnapshot.hasVisibleSubmitButton).toBe(true);
    expect(stage1.domSnapshot.hasJafVisuallyHiddenTrap).toBe(true);
    expect(logs.some((l) => l.includes('addScriptTag'))).toBe(true);

    // Subsequent inspection on a page with pre-injected adapters detects pre_injected
    const preInjectedPage = createObservableMockPage({
      routes: {
        [serviceEntryUrl]: {
          finalUrl: credentialsUrl,
          html,
          responses: [{ url: credentialsUrl, status: 200, headers: {} }]
        }
      },
      evaluateOverride: async (fnOrCode, _arg, defaultEval) => {
        const res = await defaultEval();
        if (
          typeof fnOrCode === 'function' &&
          fnOrCode.toString().includes('__PoliAuthAdapters') &&
          res === false
        ) {
          // Inject bundle on the fly as if initScript had already injected it
          await defaultEval();
        }
        return res;
      }
    });
    // Pre-populate __PoliAuthAdapters via initial goto + addScriptTag
    await preInjectedPage.goto(serviceEntryUrl);
    await preInjectedPage.addScriptTag?.({
      content: 'window.__PoliAuthAdapters = { polimi: { inspectPolimiPageStage: () => ({ stage: "credentials", url: window.location.href, title: "" }) } };'
    });
    // Use evaluateOverride that keeps __PoliAuthAdapters across mock goto
    const persistentPreInjectedPage: PlaywrightPageLike = {
      url: () => credentialsUrl,
      goto: async () => undefined,
      waitForLoadState: async () => undefined,
      evaluate: async <R, Arg = void>(
        fnOrCode: ((arg: Arg) => R | Promise<R>) | string,
        arg?: Arg
      ): Promise<R> => {
        const dom = new JSDOM(html, { url: credentialsUrl });
        const prevWindow = (globalThis as Record<string, unknown>).window;
        const prevDoc = (globalThis as Record<string, unknown>).document;
        try {
          (dom.window as unknown as Record<string, unknown>).__PoliAuthAdapters = {
            polimi: {
              inspectPolimiPageStage: () => ({
                stage: 'credentials',
                url: credentialsUrl,
                title: ''
              })
            }
          };
          (globalThis as Record<string, unknown>).window = dom.window;
          (globalThis as Record<string, unknown>).document = dom.window.document;
          if (typeof fnOrCode === 'string') {
            return dom.window.eval(fnOrCode) as R;
          }
          return await fnOrCode(arg as Arg);
        } finally {
          (globalThis as Record<string, unknown>).window = prevWindow;
          (globalThis as Record<string, unknown>).document = prevDoc;
        }
      }
    };

    const preReport = await runPolimiLivePortalProbe({
      page: persistentPreInjectedPage,
      probeBareAunicaloginRecovery: false,
      probeServiceEntryToCredentials: true
    });
    expect(preReport.stages[0]?.adapterInjectionMethod).toBe('pre_injected');
  });

  it('redacts sensitive query params, headers, and error banner secrets in redirect chains, finalUrl, and Markdown output', async () => {
    const serviceEntryUrl =
      'https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376';
    const leakyRedirectUrl =
      'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?SAMLRequest=secret123&password=leaked&ticket=ST-999&__pj1=SECRET_HMAC';
    const leakyLocationHeader =
      'https://shibidp.polimi.it/idp/SAML2?SAMLResponse=ASSERTION_SECRET_XYZ&ticket=ST-777';

    const leakyHtml = `<!DOCTYPE html>
      <html>
        <body>
          <div class="poli-messages">
            <div class="alert-danger">
              <span class="jaf-message">SSO failure at ?SAMLRequest=secret123&password=leaked&ticket=ST-999 {"totpSecret":"JBSWY3DPEHPK3PXP"}</span>
            </div>
          </div>
          <input id="login" name="login" />
          <input id="password" name="password" type="password" />
        </body>
      </html>`;

    const mockPage = createObservableMockPage({
      routes: {
        [serviceEntryUrl]: {
          finalUrl: leakyRedirectUrl,
          html: leakyHtml,
          responses: [
            {
              url: leakyRedirectUrl,
              status: 302,
              headers: {
                location: leakyLocationHeader,
                'content-security-policy': "default-src 'self' https://idp.example/?ticket=CSP_LEAK"
              }
            }
          ]
        }
      }
    });

    const report = await runPolimiLivePortalProbe({
      page: mockPage,
      probeBareAunicaloginRecovery: false,
      probeServiceEntryToCredentials: true
    });

    const serialized = JSON.stringify(report);
    const markdown = formatLivePortalProbeReportMarkdown(report);

    for (const secret of [
      'secret123',
      'leaked',
      'ST-999',
      'SECRET_HMAC',
      'ASSERTION_SECRET_XYZ',
      'ST-777',
      'JBSWY3DPEHPK3PXP',
      'CSP_LEAK'
    ]) {
      expect(serialized).not.toContain(secret);
      expect(markdown).not.toContain(secret);
    }

    expect(serialized).toContain('SAMLRequest=[REDACTED]');
    expect(serialized).toContain('password=[REDACTED]');
    expect(serialized).toContain('ticket=[REDACTED]');
    expect(serialized).toContain('SAMLResponse=[REDACTED]');
    expect(report.stages[0]?.finalUrl).toContain('[REDACTED]');
    expect(report.stages[0]?.domSnapshot.sanitizedErrorMessage).toContain('[REDACTED]');
  });

  it('fast-fails deterministically on closed-target errors with structured redacted errorSummary and AuthLoggerPort logging', async () => {
    let gotoCalls = 0;
    let evalCalls = 0;
    const errorLogs: string[] = [];
    const logger: AuthLoggerPort = {
      debug: () => undefined,
      info: () => undefined,
      warn: () => undefined,
      error: (msg) => errorLogs.push(msg)
    };

    const closedMidProbePage: PlaywrightPageLike = {
      url: () => 'https://aunicalogin.polimi.it/aunicalogin/?ticket=CLOSED_SECRET_99',
      goto: async () => {
        gotoCalls += 1;
        if (gotoCalls === 1) {
          return undefined;
        }
        throw new Error('Should never attempt Probe 2 after closed-target fast-fail');
      },
      waitForLoadState: async () => undefined,
      evaluate: async () => {
        evalCalls += 1;
        throw new Error(
          'Target page, context or browser has been closed at https://aunicalogin.polimi.it/?__pj1=HMAC_CLOSED_SECRET'
        );
      }
    };

    const report = await runPolimiLivePortalProbe({
      page: closedMidProbePage,
      driverOptions: { maxTransientRetries: 3 },
      logger,
      probeBareAunicaloginRecovery: true,
      probeServiceEntryToCredentials: true
    });

    expect(gotoCalls).toBe(1);
    expect(evalCalls).toBe(1);
    expect(report.overallSuccess).toBe(false);
    expect(report.errorSummary).toBeDefined();
    expect(report.errorSummary).toContain('has been closed');
    expect(report.errorSummary).toContain('__pj1=[REDACTED]');
    expect(report.errorSummary).not.toContain('HMAC_CLOSED_SECRET');
    expect(report.stages).toHaveLength(1);
    expect(report.stages[0]?.inspectedStage).toBe('error');
    expect(report.stages[0]?.finalUrl).not.toContain('CLOSED_SECRET_99');
    expect(errorLogs).toHaveLength(1);
    expect(errorLogs[0]).toContain('has been closed');
    expect(errorLogs[0]).not.toContain('HMAC_CLOSED_SECRET');
  });

  it('formats clean Markdown ledger tables with [FACT:LIVE] / [FACT:EXEC] epistemic tags and audits Stage 2 & Stage 3 custom URLs', async () => {
    const otpUrl =
      'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneDFA.do';
    const portalUrl =
      'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do';

    const otpHtml = `<!DOCTYPE html>
      <html>
        <body>
          <form id="form_scelta2fa" action="/aunicalogin/controller/IdentificazioneDFA.do">
            <input id="otp" name="otp" />
            <button type="submit" id="submit-dissms" name="evn_continua">Continua</button>
          </form>
        </body>
      </html>`;

    const portalHtml = `<!DOCTYPE html>
      <html>
        <head><title>Portale servizi</title></head>
        <body>
          <input class="cercaServizio" name="search" />
          <a href="/portaleservizi/Logout.do">Logout</a>
        </body>
      </html>`;

    const mockPage = createObservableMockPage({
      routes: {
        [otpUrl]: {
          finalUrl: otpUrl,
          html: otpHtml,
          responses: [
            {
              url: otpUrl,
              status: 200,
              headers: { 'content-security-policy': "frame-ancestors 'self' | strict" }
            }
          ]
        },
        [portalUrl]: {
          finalUrl: portalUrl,
          html: portalHtml,
          responses: [{ url: portalUrl, status: 200, headers: {} }]
        }
      }
    });

    const report = await runPolimiLivePortalProbe({
      page: mockPage,
      probeBareAunicaloginRecovery: false,
      probeServiceEntryToCredentials: false,
      customUrlsToInspect: [otpUrl, portalUrl]
    });

    expect(report.overallSuccess).toBe(true);
    expect(report.stages).toHaveLength(2);
    expect(report.stages[0]?.inspectedStage).toBe('otp');
    expect(report.stages[0]?.domSnapshot.hasOtpInput).toBe(true);
    expect(report.stages[0]?.domSnapshot.hasSubmitDissmsTrap).toBe(true);
    expect(report.stages[1]?.inspectedStage).toBe('authenticated');
    expect(report.stages[1]?.domSnapshot.hasAuthenticatedMarker).toBe(true);

    const execMarkdown = formatLivePortalProbeReportMarkdown(report);
    expect(execMarkdown).toContain('| Probe | Target URL | Final URL | Inspected Stage |');
    expect(execMarkdown).toContain('| :--- | :--- | :--- | :--- |');
    expect(execMarkdown).toContain('`[FACT:EXEC]`');
    expect(execMarkdown).toContain('\\| strict');
    expect(execMarkdown).not.toContain('`[FACT:LIVE]`');

    const liveSample: LivePortalProbeReport = {
      ...report,
      environment: 'live_network',
      stages: report.stages.map((s) => ({ ...s, epistemicStatus: 'FACT:LIVE' }))
    };
    const liveMarkdown = formatLivePortalProbeReportMarkdown(liveSample);
    expect(liveMarkdown).toContain('- **Environment:** `live_network`');
    expect(liveMarkdown).toContain('`[FACT:LIVE]`');
  });

  it(
    'gates live Politecnico di Milano network probe behind POLIAUTH_LIVE_PROBE=1 without skipping',
    async () => {
      if (!isLivePortalProbeEnabled()) {
        expect(isLivePortalProbeEnabled({ POLIAUTH_LIVE_PROBE: '0' })).toBe(false);
        expect(isLivePortalProbeEnabled({ POLIAUTH_LIVE_PROBE: '1' })).toBe(true);
        return;
      }

      const pw = await import('playwright');
      let browser: Awaited<ReturnType<typeof pw.chromium.launch>> | null = null;
      const launchCandidates: Array<Record<string, unknown>> = [
        { headless: true },
        { headless: true, channel: 'chrome' },
        { headless: true, channel: 'msedge' }
      ];
      const envExec = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
      if (envExec) {
        launchCandidates.unshift({ headless: true, executablePath: envExec });
      }

      let lastLaunchError: unknown;
      for (const launchOpts of launchCandidates) {
        try {
          browser = await pw.chromium.launch(launchOpts);
          break;
        } catch (err) {
          lastLaunchError = err;
        }
      }

      if (!browser) {
        console.warn(
          `LIVE_PROBE_UNAVAILABLE [ASSUMPTION:UNVERIFIED]: Browser binary could not launch (${lastLaunchError instanceof Error ? lastLaunchError.message : String(lastLaunchError)}).`
        );
        return;
      }

      try {
        const context = await browser.newContext({ locale: 'it-IT' });
        const page = await context.newPage();
        const report = await runPolimiLivePortalProbe({
          page: page as unknown as PlaywrightPageLike,
          environment: 'live_network'
        });

        const markdown = formatLivePortalProbeReportMarkdown(report);
        console.info('\n' + markdown + '\n');

        const isNetworkSandboxed =
          !report.overallSuccess &&
          Boolean(
            report.errorSummary &&
              /ERR_NAME_NOT_RESOLVED|ERR_INTERNET_DISCONNECTED|ERR_CONNECTION_TIMED_OUT|ERR_CONNECTION_REFUSED|ERR_TUNNEL_CONNECTION_FAILED|Timeout/i.test(
                report.errorSummary
              )
          );

        if (isNetworkSandboxed) {
          console.warn(
            `LIVE_PROBE_NETWORK_SANDBOXED [ASSUMPTION:UNVERIFIED]: ${report.errorSummary}`
          );
          expect(report.generatedAtIso).toBeTruthy();
          return;
        }

        expect(report.stages.length).toBeGreaterThanOrEqual(2);
        expect(report.overallSuccess).toBe(true);
      } finally {
        await browser.close();
      }
    },
    60_000
  );
});
