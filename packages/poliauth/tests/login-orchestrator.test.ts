import { describe, expect, it, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import { PoliAuthOrchestrator } from '../application/login-orchestrator.js';
import { OtpChallengeCoordinator } from '../application/otp-challenge.js';
import { TotpService } from '../domain/totp.js';
import { InMemoryUserIdentityRepository } from '../storage/memory-storage.js';
import { PoliAuth } from '../src/poliauth-client.js';
import type { SessionContextPoolPort } from '../interfaces/session-pool-port.js';
import type { AuthLoggerPort } from '../interfaces/logger-port.js';
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

  it('trips reauth_required with zero retries on Stage 1 INVALID_CREDENTIALS, PASSWORD_EXPIRED, and ACCOUNT_LOCKED', async () => {
    const users = new InMemoryUserIdentityRepository();
    await users.ensureUser(7001, { username: 'mario.rossi' });
    const coordinator = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orchestrator = new PoliAuthOrchestrator({
      otpCoordinator: coordinator,
      identityRepository: users
    });

    // 1. INVALID_CREDENTIALS -> immediate trip, 1 submitCredentials call total (0 retries)
    const invalidDriver = new SimulatedPolimiPageDriver([
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do', title: 'Login' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do', title: 'Login' },
      {
        stage: 'credentials',
        url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do',
        title: 'Login',
        errorMessage: 'Credenziali non valide',
        semanticErrorCode: 'INVALID_CREDENTIALS'
      }
    ]);
    const invalidOutcome = await orchestrator.authenticate({
      userId: 7001,
      driver: invalidDriver,
      pollDelayMs: 0,
      credentials: { personCode: '10987654', password: 'WrongPassword!' }
    });
    expect(invalidOutcome.ok).toBe(false);
    expect(invalidOutcome.classification).toBe('AUTHENTICATION_REJECTED');
    expect(invalidOutcome.semanticErrorCode).toBe('INVALID_CREDENTIALS');
    expect(invalidOutcome.reauthRequired).toBe(true);
    expect(invalidDriver.submittedCreds.length).toBe(1);
    const lockedUser = await users.getUser(7001);
    expect(lockedUser?.loginStatus).toBe('reauth_required');
    expect(lockedUser?.loginError).toContain('Credenziali non valide');

    // Reset to idle and test PASSWORD_EXPIRED
    await users.updateLoginStatus(7001, 'idle', null);
    const expiredDriver = new SimulatedPolimiPageDriver([
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do', title: 'Login' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do', title: 'Login' },
      {
        stage: 'credentials',
        url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do',
        title: 'Login',
        errorMessage: 'Password scaduta: cambio password obbligatorio',
        semanticErrorCode: 'PASSWORD_EXPIRED'
      }
    ]);
    const expiredOutcome = await orchestrator.authenticate({
      userId: 7001,
      driver: expiredDriver,
      pollDelayMs: 0,
      credentials: { personCode: '10987654', password: 'ExpiredPassword!' }
    });
    expect(expiredOutcome.ok).toBe(false);
    expect(expiredOutcome.semanticErrorCode).toBe('PASSWORD_EXPIRED');
    expect(expiredOutcome.reauthRequired).toBe(true);
    expect(expiredDriver.submittedCreds.length).toBe(1);
    expect((await users.getUser(7001))?.loginStatus).toBe('reauth_required');

    // Reset to idle and test ACCOUNT_LOCKED detected on Stage 2 OTP page -> immediate abort
    await users.updateLoginStatus(7001, 'idle', null);
    const lockedDriver = new SimulatedPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      {
        stage: 'otp',
        url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do',
        title: '2FA',
        errorMessage: 'Account bloccato per troppi tentativi',
        semanticErrorCode: 'ACCOUNT_LOCKED'
      }
    ]);
    const lockedOutcome = await orchestrator.authenticate({
      userId: 7001,
      driver: lockedDriver,
      pollDelayMs: 0,
      credentials: { personCode: '10987654', password: 'MyPoliPassword!', totpSecret: 'JBSWY3DPEHPK3PXP' }
    });
    expect(lockedOutcome.ok).toBe(false);
    expect(lockedOutcome.semanticErrorCode).toBe('ACCOUNT_LOCKED');
    expect(lockedOutcome.reauthRequired).toBe(true);
    expect(lockedDriver.submittedOtps.length).toBe(0);
    expect((await users.getUser(7001))?.loginStatus).toBe('reauth_required');
  });

  it('fast-fails before launching or calling browser driver when user loginStatus is reauth_required', async () => {
    const users = new InMemoryUserIdentityRepository();
    await users.ensureUser(7002, { username: 'mario.rossi' });
    await users.updateLoginStatus(7002, 'reauth_required', 'Previous invalid credentials');

    const acquireSpy = vi.fn(async () => {
      throw new Error('sessionPool should not be leased during reauth_required fast-fail');
    });
    const mockPool: SessionContextPoolPort = {
      acquireUserContext: acquireSpy,
      releaseUserContext: vi.fn(),
      getOrCreatePrimaryPage: vi.fn(async () => {
        throw new Error('sessionPool page should not be created during reauth_required fast-fail');
      }),
      saveUserContextState: vi.fn(async () => {}),
      destroyUserContext: vi.fn(async () => {}),
      evictExpiredContexts: vi.fn(async () => {}),
      closeAll: vi.fn(async () => {}),
      getStats: () => ({ activeContexts: 0, busyContexts: 0, browserConnected: false })
    };
    const warnSpy = vi.fn();
    const logger: AuthLoggerPort = {
      debug: vi.fn(),
      info: vi.fn(),
      warn: warnSpy,
      error: vi.fn()
    };

    const client = new PoliAuth({
      identityRepository: users,
      sessionPool: mockPool,
      logger
    });

    const driver = new SimulatedPolimiPageDriver([
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do', title: 'Login' }
    ]);
    const statuses: string[] = [];

    const outcome = await client.authenticate({
      userId: 7002,
      driver,
      pollDelayMs: 0,
      credentials: { personCode: '10987654', password: 'MyPoliPassword!' },
      callbacks: {
        onStatusChange: (status) => {
          statuses.push(status);
        }
      }
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.status).toBe('reauth_required');
    expect(outcome.reauthRequired).toBe(true);
    expect(outcome.classification).toBe('AUTHENTICATION_REJECTED');
    expect(driver.navigatedUrls.length).toBe(0);
    expect(driver.submittedCreds.length).toBe(0);
    expect(acquireSpy).toHaveBeenCalledTimes(0);
    expect(warnSpy).toHaveBeenCalled();
    expect(statuses).toContain('reauth_required');

    // Same invariant holds for Federated SAML entry point
    const samlOutcome = await client.authenticateFederatedSaml({
      userId: 7002,
      driver,
      entryUrl: 'https://webeep.polimi.it/login/index.php',
      pollIntervalMs: 0,
      credentials: { personCode: '10987654', password: 'MyPoliPassword!' }
    });
    expect(samlOutcome.ok).toBe(false);
    expect(samlOutcome.status).toBe('reauth_required');
    expect(samlOutcome.reauthRequired).toBe(true);
    expect(driver.navigatedUrls.length).toBe(0);
  });

  it('handles Stage 2 OTP_REJECTED: Case 4a retries once in next 30s TOTP window without tripping; Case 4b and manual limit trip reauth_required', async () => {
    // Case 4a (Real TotpService + Date.now mock + waitForNextTotpWindow crossing 30s boundary)
    let fakeNowMs = new Date('2026-11-13T12:00:28.000Z').getTime();
    const dateNowSpy = vi.spyOn(Date, 'now').mockImplementation(() => fakeNowMs);
    try {
      const usersA = new InMemoryUserIdentityRepository();
      await usersA.ensureUser(7003, { username: 'mario.rossi' });
      const orchestratorA = new PoliAuthOrchestrator({
        otpCoordinator: new OtpChallengeCoordinator({ totpGenerator: new TotpService() }),
        identityRepository: usersA
      });

      const driverA = new SimulatedPolimiPageDriver([
        { stage: 'unknown', url: 'about:blank', title: '' },
        { stage: 'otp', url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do', title: '2FA' },
        {
          stage: 'otp',
          url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do',
          title: '2FA',
          errorMessage: 'Codice OTP non valido',
          semanticErrorCode: 'OTP_REJECTED'
        },
        {
          stage: 'authenticated',
          url: 'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do',
          title: 'Portale'
        }
      ]);

      const waitCalls: number[] = [];
      const statusDuringWait: Array<string | undefined> = [];
      const outcomeA = await orchestratorA.authenticate({
        userId: 7003,
        driver: driverA,
        pollDelayMs: 0,
        waitForNextTotpWindow: async (waitMs) => {
          waitCalls.push(waitMs);
          statusDuringWait.push((await usersA.getUser(7003))?.loginStatus);
          fakeNowMs += waitMs;
        },
        credentials: {
          personCode: '10987654',
          password: 'MyPoliPassword!',
          totpSecret: 'JBSWY3DPEHPK3PXP'
        }
      });

      expect(outcomeA.ok).toBe(true);
      expect(outcomeA.status).toBe('authenticated');
      expect(waitCalls).toEqual([2_250]);
      expect(statusDuringWait).toEqual(['idle']);
      expect(driverA.submittedOtps.length).toBe(2);
      expect(driverA.submittedOtps[0]).not.toBe(driverA.submittedOtps[1]);
      expect((await usersA.getUser(7003))?.loginStatus).toBe('idle');
    } finally {
      dateNowSpy.mockRestore();
    }

    // Case 4a-timer (Fake timers verifying sleep(computedWaitMs) when pollDelayMs > 0)
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-11-13T12:00:27.000Z'));
      const usersTimer = new InMemoryUserIdentityRepository();
      await usersTimer.ensureUser(7007, { username: 'mario.rossi' });
      const realTotp = new TotpService();
      const deterministicTotp: TotpService = {
        cleanSecret: (s: string) => realTotp.cleanSecret(s),
        isValidSecret: (s: string) => realTotp.isValidSecret(s),
        getRemainingSeconds: (nowMs?: number) => realTotp.getRemainingSeconds(nowMs),
        generate: async () => String(Math.floor(Date.now() / 30_000)).slice(-6).padStart(6, '0'),
        generateStable: async () => ({
          code: String(Math.floor(Date.now() / 30_000)).slice(-6).padStart(6, '0'),
          remainingSeconds: realTotp.getRemainingSeconds(Date.now()),
          waitedForNextWindow: false
        })
      } as unknown as TotpService;
      const orchestratorTimer = new PoliAuthOrchestrator({
        otpCoordinator: new OtpChallengeCoordinator({
          totpGenerator: deterministicTotp,
          minTotpRemainingSeconds: 0
        }),
        identityRepository: usersTimer
      });
      const driverTimer = new SimulatedPolimiPageDriver([
        { stage: 'unknown', url: 'about:blank', title: '' },
        { stage: 'otp', url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do', title: '2FA' },
        {
          stage: 'otp',
          url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do',
          title: '2FA',
          errorMessage: 'Codice OTP non valido',
          semanticErrorCode: 'OTP_REJECTED'
        },
        {
          stage: 'authenticated',
          url: 'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do',
          title: 'Portale'
        }
      ]);

      const promiseTimer = orchestratorTimer.authenticate({
        userId: 7007,
        driver: driverTimer,
        pollDelayMs: 400,
        postSubmitDebounceMs: 0,
        credentials: {
          personCode: '10987654',
          password: 'MyPoliPassword!',
          totpSecret: 'JBSWY3DPEHPK3PXP'
        }
      });

      await vi.advanceTimersByTimeAsync(500);
      expect(driverTimer.submittedOtps.length).toBe(1);
      expect((await usersTimer.getUser(7007))?.loginStatus).toBe('idle');

      await vi.advanceTimersByTimeAsync(5_000);
      const outcomeTimer = await promiseTimer;
      expect(outcomeTimer.ok).toBe(true);
      expect(driverTimer.submittedOtps.length).toBe(2);
      expect(driverTimer.submittedOtps[0]).not.toBe(driverTimer.submittedOtps[1]);
    } finally {
      vi.useRealTimers();
    }

    // Case 4b: 2nd consecutive auto-TOTP rejection trips reauth_required and aborts
    const usersB = new InMemoryUserIdentityRepository();
    await usersB.ensureUser(7004, { username: 'mario.rossi' });
    const orchestratorB = new PoliAuthOrchestrator({
      otpCoordinator: new OtpChallengeCoordinator({ totpGenerator: new TotpService() }),
      identityRepository: usersB
    });
    const driverB = new SimulatedPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'otp', url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do', title: '2FA' },
      {
        stage: 'otp',
        url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do',
        title: '2FA',
        errorMessage: 'Codice OTP non valido',
        semanticErrorCode: 'OTP_REJECTED'
      },
      {
        stage: 'otp',
        url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do',
        title: '2FA',
        errorMessage: 'Codice OTP non valido',
        semanticErrorCode: 'OTP_REJECTED'
      }
    ]);

    const outcomeB = await orchestratorB.authenticate({
      userId: 7004,
      driver: driverB,
      pollDelayMs: 0,
      credentials: {
        personCode: '10987654',
        password: 'MyPoliPassword!',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      }
    });

    expect(outcomeB.ok).toBe(false);
    expect(outcomeB.classification).toBe('OTP_CHALLENGE_FAILED');
    expect(outcomeB.semanticErrorCode).toBe('OTP_REJECTED');
    expect(outcomeB.reauthRequired).toBe(true);
    expect(driverB.submittedOtps.length).toBe(2);
    expect((await usersB.getUser(7004))?.loginStatus).toBe('reauth_required');

    // Case 4c: Manual OTP attempts reaching maxManualOtpAttempts trip reauth_required
    const usersC = new InMemoryUserIdentityRepository();
    await usersC.ensureUser(7006, { username: 'mario.rossi' });
    const coordinatorC = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orchestratorC = new PoliAuthOrchestrator({
      otpCoordinator: coordinatorC,
      identityRepository: usersC
    });
    const driverC = new SimulatedPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'otp', url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do', title: '2FA' },
      { stage: 'otp', url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do', title: '2FA' },
      { stage: 'otp', url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do', title: '2FA' }
    ]);
    const manualPromise = orchestratorC.authenticate({
      userId: 7006,
      driver: driverC,
      pollDelayMs: 0,
      maxManualOtpAttempts: 2,
      credentials: { personCode: '10987654', password: 'MyPoliPassword!' },
      callbacks: {
        onOtpRequired: () => {
          setTimeout(() => {
            coordinatorC.submitManualOtpForUser(7006, '111222');
          }, 5);
        }
      }
    });
    const manualOutcome = await manualPromise;
    expect(manualOutcome.ok).toBe(false);
    expect(manualOutcome.semanticErrorCode).toBe('OTP_REJECTED');
    expect(manualOutcome.reauthRequired).toBe(true);
    expect(driverC.submittedOtps.length).toBe(2);
    expect((await usersC.getUser(7006))?.loginStatus).toBe('reauth_required');
  });

  it('preserves user loginStatus when IDP_MAINTENANCE or DOM_SELECTOR_DRIFT occurs', async () => {
    const users = new InMemoryUserIdentityRepository();
    await users.ensureUser(7005, { username: 'mario.rossi' });
    const orchestrator = new PoliAuthOrchestrator({
      otpCoordinator: new OtpChallengeCoordinator({ totpGenerator: new TotpService() }),
      identityRepository: users
    });

    // 1. IDP_MAINTENANCE must not set reauth_required
    const outageDriver = new SimulatedPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      {
        stage: 'unknown',
        url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do',
        title: 'Manutenzione',
        httpStatus: 503,
        errorMessage: 'Servizio momentaneamente non disponibile',
        semanticErrorCode: 'IDP_MAINTENANCE',
        diagnosticError: {
          component: 'test',
          operation: 'inspectPolimiPageStage',
          stage: 'unknown',
          classification: 'PORTAL_OUTAGE_OR_NETWORK_ERROR',
          semanticErrorCode: 'IDP_MAINTENANCE',
          selectorOrEndpoint: 'IdentificazioneUnica.do',
          message: 'Servizio momentaneamente non disponibile'
        }
      }
    ]);
    const outageOutcome = await orchestrator.authenticate({
      userId: 7005,
      driver: outageDriver,
      pollDelayMs: 0,
      credentials: { personCode: '10987654', password: 'MyPoliPassword!' }
    });
    expect(outageOutcome.ok).toBe(false);
    expect(outageOutcome.classification).toBe('PORTAL_OUTAGE_OR_NETWORK_ERROR');
    expect(outageOutcome.semanticErrorCode).toBe('IDP_MAINTENANCE');
    expect(outageOutcome.reauthRequired).toBe(false);
    expect((await users.getUser(7005))?.loginStatus).toBe('idle');

    // 2. DOM_SELECTOR_DRIFT must not set reauth_required
    const driftDriver = new SimulatedPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      {
        stage: 'unknown',
        url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do',
        title: 'Polimi New Layout',
        httpStatus: 200,
        semanticErrorCode: 'DOM_SELECTOR_DRIFT',
        diagnosticError: {
          component: 'test',
          operation: 'inspectPolimiPageStage',
          stage: 'unknown',
          classification: 'DOM_SELECTOR_DRIFT',
          semanticErrorCode: 'DOM_SELECTOR_DRIFT',
          selectorOrEndpoint: 'form#login',
          message: 'Selector drift'
        }
      }
    ]);
    const driftOutcome = await orchestrator.authenticate({
      userId: 7005,
      driver: driftDriver,
      pollDelayMs: 0,
      credentials: { personCode: '10987654', password: 'MyPoliPassword!' }
    });
    expect(driftOutcome.ok).toBe(false);
    expect(driftOutcome.classification).toBe('DOM_SELECTOR_DRIFT');
    expect(driftOutcome.semanticErrorCode).toBe('DOM_SELECTOR_DRIFT');
    expect(driftOutcome.reauthRequired).toBe(false);
    expect((await users.getUser(7005))?.loginStatus).toBe('idle');
  });
});
