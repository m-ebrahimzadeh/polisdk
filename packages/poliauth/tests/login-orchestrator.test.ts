import { describe, expect, it } from 'vitest';
import { JSDOM } from 'jsdom';
import { PoliAuthOrchestrator } from '../application/login-orchestrator.js';
import { OtpChallengeCoordinator } from '../application/otp-challenge.js';
import { TotpService } from '../domain/totp.js';
import type {
  PoliAuthDiagnosticErrorPayload,
  PolimiStageInspectionResult,
  FederatedSsoInspectionResult
} from '../domain/entities.js';
import type {
  FederatedAuthPageDriverPort,
  PageActionResult,
  PolimiCredentialSubmission,
  PolimiOtpSubmission,
  SessionRecoveryResult
} from '../interfaces/browser-driver-port.js';
import type { FederatedSsoProviderSpec } from '../interfaces/federated-sso-provider-port.js';
import { SelectorFederatedSsoProviderAdapter } from '../adapters/federated-sso-dom-adapter.js';
import { DomFederatedAuthPageDriver } from '../adapters/dom-page-driver.js';

class SimulatedPolimiPageDriver implements FederatedAuthPageDriverPort {
  public readonly federatedProviderId: string;
  public stages: PolimiStageInspectionResult[];
  public ssoStates: FederatedSsoInspectionResult[] = [];
  public submittedCreds: PolimiCredentialSubmission[] = [];
  public submittedOtps: string[] = [];
  public submittedIdentifiers: string[] = [];
  public triggeredLoginCount = 0;
  public recoveredCount = 0;
  public navigatedUrls: string[] = [];

  constructor(
    stages: PolimiStageInspectionResult[],
    ssoStates: FederatedSsoInspectionResult[] = [],
    federatedProviderId = 'webex'
  ) {
    this.stages = [...stages];
    this.ssoStates = [...ssoStates];
    this.federatedProviderId = federatedProviderId;
  }

  async goto(url: string, _timeoutMs?: number): Promise<void> {
    this.navigatedUrls.push(url);
  }

  async waitForNavigation(_timeoutMs?: number): Promise<void> {}

  async inspectPolimiStage(): Promise<PolimiStageInspectionResult> {
    if (this.stages.length > 1) {
      return this.stages.shift()!;
    }
    return (
      this.stages[0] ?? {
        stage: 'authenticated',
        url: 'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do',
        title: 'Portale servizi'
      }
    );
  }

  async recoverSessionPage(): Promise<SessionRecoveryResult> {
    this.recoveredCount += 1;
    return {
      ok: true,
      navigatedTo: 'https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376'
    };
  }

  async submitCredentials(params: PolimiCredentialSubmission): Promise<PageActionResult> {
    this.submittedCreds.push(params);
    return { ok: true };
  }

  async submitOtp(params: PolimiOtpSubmission): Promise<PageActionResult> {
    this.submittedOtps.push(params.otp);
    return { ok: true };
  }

  async inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult> {
    if (this.ssoStates.length > 1) {
      return this.ssoStates.shift()!;
    }
    return (
      this.ssoStates[0] ?? {
        providerId: this.federatedProviderId,
        status: 'authenticated',
        isIdentifierPrompt: false,
        isLoginTrigger: false,
        isSamlTransitPage: false,
        url: 'https://polimi.webex.com/webappng/sites/polimi/dashboard'
      }
    );
  }

  async submitFederatedIdentifier(identifier: string): Promise<PageActionResult> {
    this.submittedIdentifiers.push(identifier);
    return { ok: true };
  }

  async triggerFederatedLogin(): Promise<PageActionResult> {
    this.triggeredLoginCount += 1;
    return { ok: true };
  }
}

describe('PoliAuthOrchestrator', () => {
  it('completes the PoliMi authentication flow (session_expired -> credentials -> auto-TOTP -> authenticated session)', async () => {
    const totp = new TotpService();
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: totp });
    const orchestrator = new PoliAuthOrchestrator(otpCoordinator);

    const driver = new SimulatedPolimiPageDriver([
      {
        stage: 'unknown',
        url: 'about:blank',
        title: ''
      },
      {
        stage: 'session_expired',
        url: 'https://aunicalogin.polimi.it/SessioneTerminata.do',
        title: 'Session Expired'
      },
      {
        stage: 'credentials',
        url: 'https://aunicalogin.polimi.it/aunicalogin.jsp?id_servizio=376',
        title: 'Autenticazione'
      },
      {
        stage: 'otp',
        url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do',
        title: 'Autenticazione 2FA'
      },
      {
        stage: 'authenticated',
        url: 'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do',
        title: 'Portale servizi'
      }
    ]);

    const statusHistory: string[] = [];
    const outcome = await orchestrator.authenticate({
      userId: 1001,
      driver,
      pollDelayMs: 0,
      credentials: {
        personCode: '10987654',
        password: 'MyPoliPassword!',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        polimiEmail: 'mario.rossi@mail.polimi.it'
      },
      callbacks: {
        onStatusChange: async (status) => {
          statusHistory.push(status);
        }
      }
    });

    expect(outcome.ok).toBe(true);
    expect(outcome.status).toBe('authenticated');
    expect(driver.recoveredCount).toBe(1);
    expect(driver.submittedCreds).toHaveLength(1);
    expect(driver.submittedOtps).toHaveLength(1);
    expect(driver.submittedOtps[0]).toMatch(/^\d{6}$/);
    expect(statusHistory).toContain('recovering_session');
    expect(statusHistory).toContain('submitting_credentials');
    expect(statusHistory).toContain('submitting_otp');
    expect(statusHistory).toContain('authenticated');
  });

  it('falls back to manual OTP when auto-generated TOTP is rejected and page stays on otp stage', async () => {
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orchestrator = new PoliAuthOrchestrator(otpCoordinator);

    const driver = new SimulatedPolimiPageDriver([
      {
        stage: 'unknown',
        url: 'about:blank',
        title: ''
      },
      {
        stage: 'otp',
        url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do',
        title: '2FA OTP'
      },
      {
        stage: 'otp',
        url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do',
        title: '2FA OTP retry'
      },
      {
        stage: 'authenticated',
        url: 'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do',
        title: 'Portale servizi'
      }
    ]);

    const outcomePromise = orchestrator.authenticate({
      userId: 42,
      driver,
      pollDelayMs: 0,
      credentials: {
        personCode: '10987654',
        password: 'MyPoliPassword!',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      },
      callbacks: {
        onOtpRequired: async () => {
          setTimeout(() => {
            otpCoordinator.submitManualOtpForUser(42, '987654');
          }, 10);
        }
      }
    });

    const outcome = await outcomePromise;
    expect(outcome.ok).toBe(true);
    expect(driver.submittedOtps).toHaveLength(2);
    expect(driver.submittedOtps[1]).toBe('987654');
  });

  it('returns failed status when credentials are required on page but empty', async () => {
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orchestrator = new PoliAuthOrchestrator(otpCoordinator);

    const driver = new SimulatedPolimiPageDriver([
      {
        stage: 'unknown',
        url: 'about:blank',
        title: ''
      },
      {
        stage: 'credentials',
        url: 'https://aunicalogin.polimi.it/aunicalogin.jsp?id_servizio=376',
        title: 'Credentials'
      }
    ]);

    const outcome = await orchestrator.authenticate({
      userId: 99,
      driver,
      pollDelayMs: 0,
      credentials: {
        personCode: '',
        password: ''
      }
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.status).toBe('failed');
  });

  it('Scenario 1: orchestrates multi-hop Mode A identifierPrompt SAML 2.0 SSO (email prompt -> PoliMi SAML credentials + 2FA -> authenticated)', async () => {
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orchestrator = new PoliAuthOrchestrator(otpCoordinator);

    const driver = new SimulatedPolimiPageDriver(
      [
        {
          stage: 'unknown',
          url: 'https://idbroker-eu.webex.com/idb/saml2/jsp/doSSO.jsp',
          title: 'Sign In'
        },
        {
          stage: 'credentials',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=2070',
          title: 'PoliMi SAML IdP'
        },
        {
          stage: 'credentials',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=2070',
          title: 'PoliMi SAML IdP'
        },
        {
          stage: 'otp',
          url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do',
          title: 'PoliMi SAML 2FA'
        },
        {
          stage: 'unknown',
          url: 'https://polimi.webex.com/webappng/sites/polimi/dashboard',
          title: 'Authenticated SP'
        }
      ],
      [
        {
          providerId: 'webex',
          status: 'login_required',
          isIdentifierPrompt: true,
          isLoginTrigger: false,
          isSamlTransitPage: true,
          url: 'https://idbroker-eu.webex.com/idb/saml2/jsp/doSSO.jsp'
        },
        {
          providerId: 'webex',
          status: 'authenticated',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: false,
          url: 'https://polimi.webex.com/webappng/sites/polimi/dashboard'
        }
      ]
    );

    const outcome = await orchestrator.authenticateFederatedSaml({
      userId: 1001,
      driver,
      pollIntervalMs: 0,
      credentials: {
        personCode: '10987654',
        password: 'MyPoliPassword!',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        polimiEmail: 'mario.rossi@mail.polimi.it'
      }
    });

    expect(outcome.ok).toBe(true);
    expect(outcome.status).toBe('authenticated');
    expect(driver.submittedIdentifiers).toEqual(['mario.rossi@mail.polimi.it']);
    expect(driver.submittedCreds).toHaveLength(1);
    expect(driver.submittedOtps).toHaveLength(1);
  });

  it('returns a clear diagnostic error when an identifierPrompt SP is reached without federatedIdentifier or polimiEmail', async () => {
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orchestrator = new PoliAuthOrchestrator(otpCoordinator);

    const driver = new SimulatedPolimiPageDriver(
      [{ stage: 'unknown', url: 'https://polimi-it.zoom.us/signin', title: 'Zoom SSO' }],
      [
        {
          providerId: 'zoom',
          status: 'login_required',
          isIdentifierPrompt: true,
          isLoginTrigger: false,
          isSamlTransitPage: true,
          url: 'https://polimi-it.zoom.us/signin'
        }
      ],
      'zoom'
    );

    const outcome = await orchestrator.authenticateFederatedSaml({
      userId: 1001,
      driver,
      pollIntervalMs: 0,
      credentials: {
        personCode: '10987654',
        password: 'MyPoliPassword!'
      }
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.status).toBe('waiting_for_login');
    expect(outcome.error).toMatch(/federatedIdentifier|polimiEmail/i);
  });

  it('Scenario 2: orchestrates Mode B click-through loginTrigger Shibboleth SP without requiring federatedIdentifier', async () => {
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orchestrator = new PoliAuthOrchestrator(otpCoordinator);

    const webeepSpec: FederatedSsoProviderSpec = {
      providerId: 'webeep',
      displayName: 'WeBeep',
      entryUrl: 'https://webeep.polimi.it/login/index.php',
      loginTrigger: {
        hostnames: ['webeep.polimi.it'],
        pathnameSubstrings: ['/login/index.php'],
        triggerSelector: 'a.btn-shibboleth'
      },
      transitHostnames: ['shibidp.polimi.it'],
      transitUrlSubstrings: ['/auth/shibboleth/'],
      authenticatedHostnames: ['webeep.polimi.it'],
      authenticatedSelectors: ['.usermenu']
    };

    let currentDom = new JSDOM(
      `<!DOCTYPE html><html><body><a class="btn-shibboleth" href="/auth/shibboleth/index.php">PoliMi</a></body></html>`,
      { url: 'https://webeep.polimi.it/login/index.php' }
    );

    const bindTriggerListener = () => {
      currentDom.window.document
        .querySelector('.btn-shibboleth')
        ?.addEventListener('click', (e) => {
          e.preventDefault();
          currentDom = new JSDOM(
            `<!DOCTYPE html><html><body>
              <form action="https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do" method="POST">
                <input id="login" name="login" />
                <input id="password" name="password" type="password" />
                <button type="submit" name="evn_conferma" id="btn-login">Accedi</button>
              </form>
            </body></html>`,
            { url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=2166' }
          );
          currentDom.window.document
            .querySelector('#btn-login')
            ?.addEventListener('click', (ev) => {
              ev.preventDefault();
              currentDom = new JSDOM(
                `<!DOCTYPE html><html><body>
                  <form id="form_scelta2fa" action="/aunicalogin/controller/IdentificazioneDFA.do">
                    <input id="otp" name="otp" />
                    <button type="submit" id="submit-dissms" name="evn_continua">Continua</button>
                  </form>
                </body></html>`,
                { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do' }
              );
              currentDom.window.document
                .querySelector('#submit-dissms')
                ?.addEventListener('click', (ev2) => {
                  ev2.preventDefault();
                  currentDom = new JSDOM(
                    `<!DOCTYPE html><html><body><div class="usermenu">Student</div></body></html>`,
                    { url: 'https://webeep.polimi.it/my/' }
                  );
                });
            });
        });
    };
    bindTriggerListener();

    const driver = new DomFederatedAuthPageDriver({
      getDocument: () => currentDom.window.document,
      getLocation: () => currentDom.window.location,
      provider: new SelectorFederatedSsoProviderAdapter(webeepSpec)
    });

    const outcome = await orchestrator.authenticateFederatedSaml({
      userId: 1002,
      driver,
      pollIntervalMs: 0,
      credentials: {
        personCode: '10987654',
        password: 'MyPoliPassword!',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      }
    });

    expect(outcome.ok).toBe(true);
    expect(outcome.status).toBe('authenticated');
  });

  it('Scenario 3: orchestrates Mode C direct-redirect Shibboleth SP (transit -> session_expired -> credentials + 2FA -> authenticated)', async () => {
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orchestrator = new PoliAuthOrchestrator(otpCoordinator);

    const driver = new SimulatedPolimiPageDriver(
      [
        {
          stage: 'unknown',
          url: 'https://webeep.polimi.it/auth/shibboleth/index.php',
          title: 'Shibboleth Redirect'
        },
        {
          stage: 'session_expired',
          url: 'https://aunicalogin.polimi.it/aunicalogin/controller/SessioneTerminata.do',
          title: 'Session Expired'
        },
        {
          stage: 'sso_handoff',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp',
          title: 'SSO Handoff'
        },
        {
          stage: 'credentials',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp',
          title: 'PoliMi IdP'
        },
        {
          stage: 'credentials',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp',
          title: 'PoliMi IdP'
        },
        {
          stage: 'otp',
          url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do',
          title: 'PoliMi 2FA'
        },
        {
          stage: 'unknown',
          url: 'https://webeep.polimi.it/my/',
          title: 'WeBeep Dashboard'
        }
      ],
      [
        {
          providerId: 'webeep-direct',
          status: 'login_required',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: false,
          url: 'about:blank'
        },
        {
          providerId: 'webeep-direct',
          status: 'sso_in_transit',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: true,
          url: 'https://webeep.polimi.it/auth/shibboleth/index.php'
        },
        {
          providerId: 'webeep-direct',
          status: 'authenticated',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: false,
          url: 'https://webeep.polimi.it/my/'
        }
      ],
      'webeep-direct'
    );

    const outcome = await orchestrator.authenticateFederatedSaml({
      userId: 1003,
      driver,
      entryUrl: 'https://webeep.polimi.it/auth/shibboleth/index.php',
      pollIntervalMs: 0,
      credentials: {
        personCode: '10987654',
        password: 'MyPoliPassword!',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      }
    });

    expect(outcome.ok).toBe(true);
    expect(outcome.status).toBe('authenticated');
    expect(driver.navigatedUrls).toEqual(['https://webeep.polimi.it/auth/shibboleth/index.php']);
    expect(driver.recoveredCount).toBe(1);
    expect(driver.submittedIdentifiers).toHaveLength(0);
    expect(driver.triggeredLoginCount).toBe(0);
    expect(driver.submittedCreds).toHaveLength(1);
    expect(driver.submittedOtps).toHaveLength(1);
  });

  it('short-circuits on PORTAL_OUTAGE_OR_NETWORK_ERROR (ETIMEDOUT / 503 maintenance) without misreporting drift', async () => {
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orchestrator = new PoliAuthOrchestrator(otpCoordinator);
    let gotoAttempted = false;
    let afterGotoInspectCalls = 0;

    const timeoutDriver: FederatedAuthPageDriverPort = {
      federatedProviderId: 'polimi',
      goto: async () => {
        gotoAttempted = true;
        throw new Error('net::ERR_CONNECTION_TIMED_OUT (ETIMEDOUT) navigating to aunicalogin.polimi.it');
      },
      waitForNavigation: async () => undefined,
      inspectPolimiStage: async () => {
        if (gotoAttempted) {
          afterGotoInspectCalls += 1;
        }
        return {
          stage: 'unknown',
          url: 'https://aunicalogin.polimi.it/',
          title: ''
        };
      },
      recoverSessionPage: async () => ({ ok: false, navigatedTo: '' }),
      submitCredentials: async () => ({ ok: false }),
      submitOtp: async () => ({ ok: false }),
      inspectFederatedSsoPage: async () => ({
        providerId: 'polimi',
        status: 'error',
        isIdentifierPrompt: false,
        isLoginTrigger: false,
        isSamlTransitPage: false,
        url: ''
      }),
      submitFederatedIdentifier: async () => ({ ok: false }),
      triggerFederatedLogin: async () => ({ ok: false })
    };

    const netOutcome = await orchestrator.authenticate({
      userId: 2001,
      driver: timeoutDriver,
      pollDelayMs: 0,
      credentials: {
        personCode: '10987654',
        password: 'MyPoliPassword!',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      }
    });

    expect(netOutcome.ok).toBe(false);
    expect(netOutcome.status).toBe('failed');
    expect(netOutcome.classification).toBe('PORTAL_OUTAGE_OR_NETWORK_ERROR');
    expect(netOutcome.diagnostic?.classification).toBe('PORTAL_OUTAGE_OR_NETWORK_ERROR');
    expect(afterGotoInspectCalls).toBe(0);

    // Also verify HTTP 503 unknown stage short-circuit on first post-navigation inspection
    let maintGotoDone = false;
    let maintAfterGotoInspectCount = 0;
    const outageDiagnostic: PoliAuthDiagnosticErrorPayload = {
      component: '@polisdk/poliauth/adapters/polimi-dom-adapter',
      operation: 'inspectPolimiPageStage',
      stage: 'unknown',
      classification: 'PORTAL_OUTAGE_OR_NETWORK_ERROR',
      selectorOrEndpoint: 'HTTP 503',
      message: 'PoliMi portal outage detected (HTTP 503)',
      diagnosticSnapshot: {
        url: 'https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376',
        pathname: '/aunicalogin/getservizio.xml',
        httpStatus: 503,
        hasEmptyBody: false,
        hasLoginInput: false,
        hasPasswordInput: false,
        hasOtpInput: false,
        hasSsoHandoffForm: false,
        hasExpiredSessionMarker: false,
        hasAuthenticatedMarker: false,
        hasErrorBanner: false,
        hasMaintenanceBanner: true
      }
    };
    const outageDriver: FederatedAuthPageDriverPort = {
      ...timeoutDriver,
      goto: async () => {
        maintGotoDone = true;
      },
      inspectPolimiStage: async () => {
        if (maintGotoDone) {
          maintAfterGotoInspectCount += 1;
        }
        return {
          stage: 'unknown',
          url: 'https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376',
          title: '503 Maintenance',
          httpStatus: 503,
          diagnosticSnapshot: outageDiagnostic.diagnosticSnapshot,
          diagnosticError: outageDiagnostic
        };
      }
    };

    const outageOutcome = await orchestrator.authenticate({
      userId: 2002,
      driver: outageDriver,
      pollDelayMs: 0,
      credentials: {
        personCode: '10987654',
        password: 'MyPoliPassword!',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      }
    });

    expect(outageOutcome.ok).toBe(false);
    expect(outageOutcome.classification).toBe('PORTAL_OUTAGE_OR_NETWORK_ERROR');
    expect(maintAfterGotoInspectCount).toBe(1);
  });

  it('short-circuits on DOM_SELECTOR_DRIFT when populated HTTP 200 PoliMi IdP page has unknown selectors', async () => {
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orchestrator = new PoliAuthOrchestrator(otpCoordinator);
    let gotoDone = false;
    let afterGotoInspectCalls = 0;

    const driftDiagnostic: PoliAuthDiagnosticErrorPayload = {
      component: '@polisdk/poliauth/adapters/polimi-dom-adapter',
      operation: 'inspectPolimiPageStage',
      stage: 'unknown',
      classification: 'DOM_SELECTOR_DRIFT',
      selectorOrEndpoint: 'input#login[name="login"]',
      message: 'PoliMi DOM selector drift detected on aunicalogin.polimi.it.',
      diagnosticSnapshot: {
        url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp',
        pathname: '/aunicalogin/aunicalogin.jsp',
        httpStatus: 200,
        hasEmptyBody: false,
        hasLoginInput: false,
        hasPasswordInput: false,
        hasOtpInput: false,
        hasSsoHandoffForm: false,
        hasExpiredSessionMarker: false,
        hasAuthenticatedMarker: false,
        hasErrorBanner: false,
        hasMaintenanceBanner: false
      }
    };

    const driftDriver: FederatedAuthPageDriverPort = {
      federatedProviderId: 'polimi',
      goto: async () => {
        gotoDone = true;
      },
      waitForNavigation: async () => undefined,
      inspectPolimiStage: async () => {
        if (gotoDone) {
          afterGotoInspectCalls += 1;
        }
        return {
          stage: 'unknown',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp',
          title: 'Politecnico di Milano - New SSO UI',
          httpStatus: 200,
          diagnosticSnapshot: driftDiagnostic.diagnosticSnapshot,
          diagnosticError: driftDiagnostic
        };
      },
      recoverSessionPage: async () => ({ ok: false, navigatedTo: '' }),
      submitCredentials: async () => ({ ok: false }),
      submitOtp: async () => ({ ok: false }),
      inspectFederatedSsoPage: async () => ({
        providerId: 'polimi',
        status: 'error',
        isIdentifierPrompt: false,
        isLoginTrigger: false,
        isSamlTransitPage: false,
        url: ''
      }),
      submitFederatedIdentifier: async () => ({ ok: false }),
      triggerFederatedLogin: async () => ({ ok: false })
    };

    const outcome = await orchestrator.authenticate({
      userId: 2003,
      driver: driftDriver,
      pollDelayMs: 0,
      credentials: {
        personCode: '10987654',
        password: 'MyPoliPassword!',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      }
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.status).toBe('failed');
    expect(outcome.classification).toBe('DOM_SELECTOR_DRIFT');
    expect(outcome.diagnostic?.classification).toBe('DOM_SELECTOR_DRIFT');
    expect(afterGotoInspectCalls).toBe(1);
  });
});
