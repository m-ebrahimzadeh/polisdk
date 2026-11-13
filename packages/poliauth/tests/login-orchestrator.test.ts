import { describe, expect, it, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import { PoliAuthOrchestrator } from '../application/login-orchestrator.js';
import { OtpChallengeCoordinator } from '../application/otp-challenge.js';
import { TotpService } from '../domain/totp.js';
import {
  InMemoryUserIdentityRepository,
  InMemoryUserVaultStorageFactory
} from '../storage/memory-storage.js';
import { PoliAuth } from '../src/poliauth-client.js';
import type {
  ManagedSessionContext,
  SessionContextPoolPort
} from '../interfaces/session-pool-port.js';
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

function createDeferred<T = void>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

class BarrierPolimiPageDriver extends SimulatedPolimiPageDriver {
  public onBeforeSubmitCredentials?: (params: PolimiCredentialSubmission) => Promise<void>;
  public onBeforeSubmitOtp?: (params: PolimiOtpSubmission) => Promise<void>;
  public onBeforeTriggerFederatedLogin?: () => Promise<void>;

  override async submitCredentials(params: PolimiCredentialSubmission): Promise<PageActionResult> {
    if (this.onBeforeSubmitCredentials) {
      await this.onBeforeSubmitCredentials(params);
    }
    return super.submitCredentials(params);
  }

  override async submitOtp(params: PolimiOtpSubmission): Promise<PageActionResult> {
    if (this.onBeforeSubmitOtp) {
      await this.onBeforeSubmitOtp(params);
    }
    return super.submitOtp(params);
  }

  override async triggerFederatedLogin(): Promise<PageActionResult> {
    if (this.onBeforeTriggerFederatedLogin) {
      await this.onBeforeTriggerFederatedLogin();
    }
    return super.triggerFederatedLogin();
  }
}

function createTrackingSessionPool(acquireShouldFail = false): {
  pool: SessionContextPoolPort<{ id: string }, { pageId: number }>;
  acquireSpy: ReturnType<typeof vi.fn>;
  releaseSpy: ReturnType<typeof vi.fn>;
  primaryPageSpy: ReturnType<typeof vi.fn>;
  saveStateSpy: ReturnType<typeof vi.fn>;
} {
  let nextPageId = 1;
  const contexts = new Map<string, ManagedSessionContext<{ id: string }, { pageId: number }>>();

  const acquireSpy = vi.fn(async (userId: string | number) => {
    if (acquireShouldFail) {
      throw new Error('sessionPool should not be acquired during fast-fail');
    }
    const key = String(userId);
    const existing = contexts.get(key) ?? {
      userId,
      context: { id: `ctx-${key}` },
      primaryPage: null,
      lastActiveAt: Date.now(),
      activeLocks: 0
    };
    existing.activeLocks += 1;
    contexts.set(key, existing);
    return existing;
  });

  const primaryPageSpy = vi.fn(
    async (managed: ManagedSessionContext<{ id: string }, { pageId: number }>) => {
      if (!managed.primaryPage) {
        managed.primaryPage = { pageId: nextPageId++ };
      }
      return managed.primaryPage;
    }
  );

  const releaseSpy = vi.fn((userId: string | number) => {
    const existing = contexts.get(String(userId));
    if (existing && existing.activeLocks > 0) {
      existing.activeLocks -= 1;
    }
  });

  const saveStateSpy = vi.fn(async () => {});

  const pool: SessionContextPoolPort<{ id: string }, { pageId: number }> = {
    acquireUserContext: acquireSpy,
    releaseUserContext: releaseSpy,
    getOrCreatePrimaryPage: primaryPageSpy,
    saveUserContextState: saveStateSpy,
    destroyUserContext: vi.fn(async () => {}),
    evictExpiredContexts: vi.fn(async () => {}),
    closeAll: vi.fn(async () => {}),
    getStats: () => ({
      activeContexts: contexts.size,
      busyContexts: Array.from(contexts.values()).filter((c) => c.activeLocks > 0).length,
      browserConnected: true
    })
  };

  return { pool, acquireSpy, releaseSpy, primaryPageSpy, saveStateSpy };
}

describe('TASK-7.2: Per-User Singleflight Login Deduplication', () => {
  it('deduplicates 5 concurrent same-user authenticate calls into 1 credential/OTP/TOTP execution and cleans up on settlement', async () => {
    const totp = new TotpService();
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: totp });
    const obtainOtpSpy = vi.spyOn(otpCoordinator, 'obtainOtpCodeForUser');

    const infoCalls: Array<{ message: string; meta?: unknown }> = [];
    const logger: AuthLoggerPort = {
      debug: vi.fn(),
      info: vi.fn((message: string, meta?: unknown) => {
        infoCalls.push({ message, meta });
      }),
      warn: vi.fn(),
      error: vi.fn()
    };

    const orchestrator = new PoliAuthOrchestrator({
      otpCoordinator,
      logger
    });

    const driver = new BarrierPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/aunicalogin.jsp', title: 'Login' },
      { stage: 'otp', url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do', title: '2FA' },
      {
        stage: 'authenticated',
        url: 'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do',
        title: 'Portale'
      }
    ]);

    const enteredCreds = createDeferred();
    const releaseCreds = createDeferred();
    const enteredOtp = createDeferred();
    const releaseOtp = createDeferred();

    driver.onBeforeSubmitCredentials = async () => {
      enteredCreds.resolve();
      await releaseCreds.promise;
    };
    driver.onBeforeSubmitOtp = async () => {
      enteredOtp.resolve();
      await releaseOtp.promise;
    };

    const sharedSecret = 'JBSWY3DPEHPK3PXP';
    const rawPassword = 'SingleflightSecretPassword!';
    const calls = Array.from({ length: 5 }, () =>
      orchestrator.authenticate({
        userId: 'student-1',
        driver,
        pollDelayMs: 0,
        credentials: {
          personCode: '10987654',
          password: rawPassword,
          totpSecret: sharedSecret
        }
      })
    );

    await enteredCreds.promise;
    expect(orchestrator.isUserAuthenticationInFlight('student-1')).toBe(true);
    expect(orchestrator.getInFlightCount()).toBe(1);
    expect(driver.submittedCreds).toHaveLength(0);

    releaseCreds.resolve();
    await enteredOtp.promise;
    expect(driver.submittedCreds).toHaveLength(1);
    expect(orchestrator.isUserAuthenticationInFlight('student-1')).toBe(true);
    expect(orchestrator.getInFlightCount()).toBe(1);

    releaseOtp.resolve();
    const outcomes = await Promise.all(calls);

    expect(outcomes).toHaveLength(5);
    for (const outcome of outcomes) {
      expect(outcome.ok).toBe(true);
      expect(outcome.status).toBe('authenticated');
      expect(outcome.url).toBe(
        'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do'
      );
      expect(outcome).toBe(outcomes[0]);
    }
    expect(driver.submittedCreds).toHaveLength(1);
    expect(driver.submittedOtps).toHaveLength(1);
    expect(obtainOtpSpy).toHaveBeenCalledTimes(1);
    expect(orchestrator.isUserAuthenticationInFlight('student-1')).toBe(false);
    expect(orchestrator.getInFlightCount()).toBe(0);

    const joinLogs = infoCalls.filter((entry) =>
      entry.message.includes('Joining existing in-flight PoliMi authentication flow')
    );
    expect(joinLogs).toHaveLength(4);
    const serializedLogs = JSON.stringify(infoCalls);
    expect(serializedLogs).not.toContain(rawPassword);
    expect(serializedLogs).not.toContain(sharedSecret);
  });

  it('supports personCode fallback key when userId is empty, post-settlement fresh re-execution, and enableSingleflight opt-out', async () => {
    const orchestrator = new PoliAuthOrchestrator({
      otpCoordinator: new OtpChallengeCoordinator({ totpGenerator: new TotpService() })
    });

    // 1) Empty userId falls back to personCode:<personCode> singleflight key
    const gate = createDeferred();
    const entered = createDeferred();
    const fallbackDriver = new BarrierPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'authenticated', url: 'https://servizionline.polimi.it/home', title: 'Home' }
    ]);
    fallbackDriver.onBeforeSubmitCredentials = async () => {
      entered.resolve();
      await gate.promise;
    };

    const p1 = orchestrator.authenticate({
      userId: '   ',
      driver: fallbackDriver,
      pollDelayMs: 0,
      credentials: { personCode: '10555666', password: 'SecretPassword1!' }
    });
    const p2 = orchestrator.authenticate({
      userId: '',
      driver: fallbackDriver,
      pollDelayMs: 0,
      credentials: { personCode: '10555666', password: 'SecretPassword1!' }
    });

    await entered.promise;
    expect(orchestrator.getInFlightCount()).toBe(1);
    gate.resolve();
    const [r1, r2] = await Promise.all([p1, p2]);
    expect(r1.ok).toBe(true);
    expect(r2).toBe(r1);
    expect(fallbackDriver.submittedCreds).toHaveLength(1);
    expect(orchestrator.getInFlightCount()).toBe(0);

    // 2) Sequential call after settlement runs a fresh authentication flow (not stale cache)
    fallbackDriver.stages = [
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'authenticated', url: 'https://servizionline.polimi.it/home', title: 'Home' }
    ];
    fallbackDriver.onBeforeSubmitCredentials = undefined;
    const r3 = await orchestrator.authenticate({
      userId: '   ',
      driver: fallbackDriver,
      pollDelayMs: 0,
      credentials: { personCode: '10555666', password: 'SecretPassword1!' }
    });
    expect(r3.ok).toBe(true);
    expect(fallbackDriver.submittedCreds).toHaveLength(2);
    expect(orchestrator.getInFlightCount()).toBe(0);

    // 3) Opt-out via per-call { enableSingleflight: false } and constructor { enableSingleflight: false }
    const dOptOutA = new SimulatedPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'authenticated', url: 'https://servizionline.polimi.it/home', title: 'Home' }
    ]);
    const dOptOutB = new SimulatedPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'authenticated', url: 'https://servizionline.polimi.it/home', title: 'Home' }
    ]);
    await Promise.all([
      orchestrator.authenticate(
        {
          userId: 'student-optout',
          driver: dOptOutA,
          pollDelayMs: 0,
          credentials: { personCode: '10555667', password: 'SecretPassword1!' }
        },
        { enableSingleflight: false }
      ),
      orchestrator.authenticate(
        {
          userId: 'student-optout',
          driver: dOptOutB,
          pollDelayMs: 0,
          credentials: { personCode: '10555667', password: 'SecretPassword1!' }
        },
        { enableSingleflight: false }
      )
    ]);
    expect(dOptOutA.submittedCreds).toHaveLength(1);
    expect(dOptOutB.submittedCreds).toHaveLength(1);

    const disabledOrch = new PoliAuthOrchestrator({
      otpCoordinator: new OtpChallengeCoordinator({ totpGenerator: new TotpService() }),
      enableSingleflight: false
    });
    const dDisabledA = new SimulatedPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'authenticated', url: 'https://servizionline.polimi.it/home', title: 'Home' }
    ]);
    const dDisabledB = new SimulatedPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'authenticated', url: 'https://servizionline.polimi.it/home', title: 'Home' }
    ]);
    await Promise.all([
      disabledOrch.authenticate({
        userId: 'student-disabled',
        driver: dDisabledA,
        pollDelayMs: 0,
        credentials: { personCode: '10555668', password: 'SecretPassword1!' }
      }),
      disabledOrch.authenticate({
        userId: 'student-disabled',
        driver: dDisabledB,
        pollDelayMs: 0,
        credentials: { personCode: '10555668', password: 'SecretPassword1!' }
      })
    ]);
    expect(dDisabledA.submittedCreds).toHaveLength(1);
    expect(dDisabledB.submittedCreds).toHaveLength(1);
  });

  it('cleans up singleflight map after INVALID_CREDENTIALS failures and unexpected thrown rejections', async () => {
    const users = new InMemoryUserIdentityRepository();
    await users.ensureUser(8101, { username: 'bad.creds' });

    const orchestrator = new PoliAuthOrchestrator({
      otpCoordinator: new OtpChallengeCoordinator({ totpGenerator: new TotpService() }),
      identityRepository: users
    });

    // Part A: 3 simultaneous calls hit INVALID_CREDENTIALS
    const failEntered = createDeferred();
    const failRelease = createDeferred();
    const failDriver = new BarrierPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      {
        stage: 'credentials',
        url: 'https://aunicalogin.polimi.it/login',
        title: 'Login',
        errorMessage: 'Credenziali non valide / Invalid username or password',
        semanticErrorCode: 'INVALID_CREDENTIALS'
      }
    ]);
    failDriver.onBeforeSubmitCredentials = async () => {
      failEntered.resolve();
      await failRelease.promise;
    };

    const failCalls = Array.from({ length: 3 }, () =>
      orchestrator.authenticate({
        userId: 8101,
        driver: failDriver,
        pollDelayMs: 0,
        credentials: { personCode: '10987654', password: 'WrongPassword!' }
      })
    );
    await failEntered.promise;
    expect(orchestrator.getInFlightCount()).toBe(1);
    failRelease.resolve();

    const failOutcomes = await Promise.all(failCalls);
    for (const outcome of failOutcomes) {
      expect(outcome.ok).toBe(false);
      expect(outcome.semanticErrorCode).toBe('INVALID_CREDENTIALS');
      expect(outcome.reauthRequired).toBe(true);
    }
    expect(failDriver.submittedCreds).toHaveLength(1);
    expect(orchestrator.getInFlightCount()).toBe(0);
    expect(orchestrator.isUserAuthenticationInFlight(8101)).toBe(false);
    expect((await users.getUser(8101))?.loginStatus).toBe('reauth_required');

    // Part B: 3 simultaneous calls hit an unexpected driver throw (caught by orchestrator -> shared failure outcome)
    // followed by 3 simultaneous calls where callback rejects outside try/catch (rejected Promise propagation)
    const crashEntered = createDeferred();
    const crashRelease = createDeferred();
    let crashAttempts = 0;
    const crashDriver = new BarrierPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'authenticated', url: 'https://servizionline.polimi.it/home', title: 'Home' }
    ]);
    crashDriver.submitCredentials = async () => {
      crashAttempts += 1;
      crashEntered.resolve();
      await crashRelease.promise;
      throw new Error('Unexpected browser process termination');
    };

    const crashCalls = Array.from({ length: 3 }, () =>
      orchestrator.authenticate({
        userId: 8102,
        driver: crashDriver,
        pollDelayMs: 0,
        credentials: { personCode: '10987655', password: 'SecretPassword1!' }
      })
    );

    await crashEntered.promise;
    expect(orchestrator.getInFlightCount()).toBe(1);
    crashRelease.resolve();

    const crashOutcomes = await Promise.all(crashCalls);
    expect(crashOutcomes).toHaveLength(3);
    for (const entry of crashOutcomes) {
      expect(entry.ok).toBe(false);
      expect(entry.status).toBe('failed');
      expect(entry.error).toContain('Unexpected browser process termination');
      expect(entry).toBe(crashOutcomes[0]);
    }
    expect(crashAttempts).toBe(1);
    expect(orchestrator.getInFlightCount()).toBe(0);
    expect(orchestrator.isUserAuthenticationInFlight(8102)).toBe(false);

    // Part C: Unhandled Promise rejection propagates to all 3 waiters AND cleans up registry
    const rejectEntered = createDeferred();
    const rejectRelease = createDeferred();
    const rejectDriver = new BarrierPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'authenticated', url: 'https://servizionline.polimi.it/home', title: 'Home' }
    ]);
    let rejectCallbackCalls = 0;
    const rejectCalls = Array.from({ length: 3 }, () =>
      orchestrator.authenticate({
        userId: 8103,
        driver: rejectDriver,
        pollDelayMs: 0,
        credentials: { personCode: '10987656', password: 'SecretPassword1!' },
        callbacks: {
          onStatusChange: async (status) => {
            if (status === 'opening_login') {
              rejectCallbackCalls += 1;
              rejectEntered.resolve();
              await rejectRelease.promise;
              throw new Error('Callback sink exploded mid-flight');
            }
            if (status === 'failed') {
              throw new Error('Callback sink exploded mid-flight');
            }
          }
        }
      })
    );

    await rejectEntered.promise;
    expect(orchestrator.getInFlightCount()).toBe(1);
    rejectRelease.resolve();

    const settled = await Promise.allSettled(rejectCalls);
    expect(settled).toHaveLength(3);
    for (const entry of settled) {
      expect(entry.status).toBe('rejected');
      if (entry.status === 'rejected') {
        expect(String(entry.reason)).toContain('Callback sink exploded mid-flight');
      }
    }
    expect(rejectCallbackCalls).toBe(1);
    expect(orchestrator.getInFlightCount()).toBe(0);
    expect(orchestrator.isUserAuthenticationInFlight(8103)).toBe(false);

    // Subsequent call for user 8102 must execute fresh without poisoned promise
    const recoveryDriver = new SimulatedPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'authenticated', url: 'https://servizionline.polimi.it/home', title: 'Home' }
    ]);
    const recovered = await orchestrator.authenticate({
      userId: 8102,
      driver: recoveryDriver,
      pollDelayMs: 0,
      credentials: { personCode: '10987655', password: 'SecretPassword1!' }
    });
    expect(recovered.ok).toBe(true);
    expect(recoveryDriver.submittedCreds).toHaveLength(1);
    expect(orchestrator.getInFlightCount()).toBe(0);
  });

  it('isolates different users in parallel without blocking student-B behind student-A', async () => {
    const orchestrator = new PoliAuthOrchestrator({
      otpCoordinator: new OtpChallengeCoordinator({ totpGenerator: new TotpService() })
    });

    const enteredA = createDeferred();
    const enteredB = createDeferred();
    const releaseA = createDeferred();
    const releaseB = createDeferred();

    const driverA = new BarrierPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'authenticated', url: 'https://servizionline.polimi.it/home', title: 'Home' }
    ]);
    driverA.onBeforeSubmitCredentials = async () => {
      enteredA.resolve();
      await releaseA.promise;
    };

    const driverB = new BarrierPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'authenticated', url: 'https://servizionline.polimi.it/home', title: 'Home' }
    ]);
    driverB.onBeforeSubmitCredentials = async () => {
      enteredB.resolve();
      await releaseB.promise;
    };

    const promiseA = orchestrator.authenticate({
      userId: 'student-A',
      driver: driverA,
      pollDelayMs: 0,
      credentials: { personCode: '10000001', password: 'PasswordA!' }
    });
    const promiseB = orchestrator.authenticate({
      userId: 'student-B',
      driver: driverB,
      pollDelayMs: 0,
      credentials: { personCode: '10000002', password: 'PasswordB!' }
    });

    // Both enter submitCredentials concurrently before either barrier is released
    await Promise.all([enteredA.promise, enteredB.promise]);
    expect(orchestrator.getInFlightCount()).toBe(2);
    expect(orchestrator.isUserAuthenticationInFlight('student-A')).toBe(true);
    expect(orchestrator.isUserAuthenticationInFlight('student-B')).toBe(true);

    // Release student-B first to prove independent non-blocking execution
    releaseB.resolve();
    const outcomeB = await promiseB;
    expect(outcomeB.ok).toBe(true);
    expect(orchestrator.isUserAuthenticationInFlight('student-B')).toBe(false);
    expect(orchestrator.isUserAuthenticationInFlight('student-A')).toBe(true);
    expect(orchestrator.getInFlightCount()).toBe(1);

    releaseA.resolve();
    const outcomeA = await promiseA;
    expect(outcomeA.ok).toBe(true);
    expect(orchestrator.getInFlightCount()).toBe(0);
    expect(driverA.submittedCreds.map((c) => c.personCode)).toEqual(['10000001']);
    expect(driverB.submittedCreds.map((c) => c.personCode)).toEqual(['10000002']);
  });

  it('deduplicates federated SAML calls per user+target and deduplicates PoliAuth facade pooled leases', async () => {
    // 1) Orchestrator federated SAML singleflight scoped by user + target
    const orchestrator = new PoliAuthOrchestrator({
      otpCoordinator: new OtpChallengeCoordinator({ totpGenerator: new TotpService() })
    });

    const webexEntered = createDeferred();
    const webexRelease = createDeferred();
    const webexDriver = new BarrierPolimiPageDriver(
      [{ stage: 'unknown', url: 'https://polimi.webex.com', title: 'Webex' }],
      [
        {
          providerId: 'webex',
          status: 'login_required',
          isIdentifierPrompt: false,
          isLoginTrigger: true,
          isSamlTransitPage: false,
          url: 'https://polimi.webex.com'
        },
        {
          providerId: 'webex',
          status: 'login_required',
          isIdentifierPrompt: false,
          isLoginTrigger: true,
          isSamlTransitPage: false,
          url: 'https://polimi.webex.com'
        },
        {
          providerId: 'webex',
          status: 'authenticated',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: false,
          url: 'https://polimi.webex.com/webappng/sites/polimi/dashboard'
        }
      ],
      'webex'
    );
    webexDriver.onBeforeTriggerFederatedLogin = async () => {
      webexEntered.resolve();
      await webexRelease.promise;
    };

    const webeepEntered = createDeferred();
    const webeepRelease = createDeferred();
    const webeepDriver = new BarrierPolimiPageDriver(
      [{ stage: 'unknown', url: 'https://webeep.polimi.it', title: 'WeBeep' }],
      [
        {
          providerId: 'webeep',
          status: 'login_required',
          isIdentifierPrompt: false,
          isLoginTrigger: true,
          isSamlTransitPage: false,
          url: 'https://webeep.polimi.it'
        },
        {
          providerId: 'webeep',
          status: 'login_required',
          isIdentifierPrompt: false,
          isLoginTrigger: true,
          isSamlTransitPage: false,
          url: 'https://webeep.polimi.it'
        },
        {
          providerId: 'webeep',
          status: 'authenticated',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: false,
          url: 'https://webeep.polimi.it/my/'
        }
      ],
      'webeep'
    );
    webeepDriver.onBeforeTriggerFederatedLogin = async () => {
      webeepEntered.resolve();
      await webeepRelease.promise;
    };

    const ssoWebexCalls = Array.from({ length: 3 }, () =>
      orchestrator.authenticateFederatedSaml({
        userId: 9001,
        driver: webexDriver,
        entryUrl: 'https://polimi.webex.com',
        pollIntervalMs: 0,
        credentials: { personCode: '10990001', password: 'SecretPassword!' }
      })
    );
    const ssoWeBeepCall = orchestrator.authenticateFederatedSaml({
      userId: 9001,
      driver: webeepDriver,
      entryUrl: 'https://webeep.polimi.it',
      pollIntervalMs: 0,
      credentials: { personCode: '10990001', password: 'SecretPassword!' }
    });

    await Promise.all([webexEntered.promise, webeepEntered.promise]);
    expect(orchestrator.isUserAuthenticationInFlight(9001)).toBe(true);
    expect(orchestrator.getInFlightCount()).toBe(2);

    webexRelease.resolve();
    webeepRelease.resolve();

    const [webexOutcomes, webeepOutcome] = await Promise.all([
      Promise.all(ssoWebexCalls),
      ssoWeBeepCall
    ]);
    for (const o of webexOutcomes) {
      expect(o.ok).toBe(true);
      expect(o).toBe(webexOutcomes[0]);
    }
    expect(webeepOutcome.ok).toBe(true);
    expect(webexDriver.triggeredLoginCount).toBe(1);
    expect(webeepDriver.triggeredLoginCount).toBe(1);
    expect(orchestrator.getInFlightCount()).toBe(0);

    // 2) PoliAuth facade pooled authenticate deduplicates acquireUserContext/driverFactory/vault/save/release
    const users = new InMemoryUserIdentityRepository();
    const { pool, acquireSpy, releaseSpy, primaryPageSpy, saveStateSpy } =
      createTrackingSessionPool();
    const createdDrivers: BarrierPolimiPageDriver[] = [];
    const pooledEnteredCreds = createDeferred();
    const pooledReleaseCreds = createDeferred();

    const driverFactorySpy = vi.fn(async () => {
      const driver = new BarrierPolimiPageDriver([
        { stage: 'unknown', url: 'about:blank', title: '' },
        { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
        { stage: 'otp', url: 'https://aunicalogin.polimi.it/otp', title: '2FA' },
        {
          stage: 'authenticated',
          url: 'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do',
          title: 'Home'
        }
      ]);
      driver.onBeforeSubmitCredentials = async () => {
        pooledEnteredCreds.resolve();
        await pooledReleaseCreds.promise;
      };
      createdDrivers.push(driver);
      return driver;
    });

    const client = new PoliAuth({
      userStorageFactory: new InMemoryUserVaultStorageFactory(),
      identityRepository: users,
      sessionPool: pool,
      driverFactory: driverFactorySpy
    });

    await client.saveCredentials(
      {
        personCode: '10992001',
        password: 'PooledVaultPassword!',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      },
      9201
    );

    const facadeCalls = Array.from({ length: 4 }, () =>
      client.authenticate({
        userId: 9201,
        pollDelayMs: 0
      })
    );

    await pooledEnteredCreds.promise;
    expect(client.isUserAuthenticationInFlight(9201)).toBe(true);
    expect(client.orchestrator.getInFlightCount()).toBe(1);

    pooledReleaseCreds.resolve();
    const facadeOutcomes = await Promise.all(facadeCalls);

    for (const outcome of facadeOutcomes) {
      expect(outcome.ok).toBe(true);
      expect(outcome.status).toBe('authenticated');
      expect(outcome).toBe(facadeOutcomes[0]);
    }
    expect(acquireSpy).toHaveBeenCalledTimes(1);
    expect(primaryPageSpy).toHaveBeenCalledTimes(1);
    expect(driverFactorySpy).toHaveBeenCalledTimes(1);
    expect(saveStateSpy).toHaveBeenCalledTimes(1);
    expect(releaseSpy).toHaveBeenCalledTimes(1);
    expect(createdDrivers).toHaveLength(1);
    expect(createdDrivers[0]!.submittedCreds).toHaveLength(1);
    expect(createdDrivers[0]!.submittedOtps).toHaveLength(1);
    expect(client.isUserAuthenticationInFlight(9201)).toBe(false);

    // 3) PoliAuth pooled authenticateFederatedSaml singleflight
    await client.saveCredentials(
      {
        personCode: '10992002',
        password: 'PooledFedPassword!'
      },
      9202
    );
    acquireSpy.mockClear();
    primaryPageSpy.mockClear();
    driverFactorySpy.mockClear();
    saveStateSpy.mockClear();
    releaseSpy.mockClear();

    const fedEntered = createDeferred();
    const fedRelease = createDeferred();
    let fedTriggerCount = 0;
    const fedFactorySpy = vi.fn(async () => {
      const driver = new BarrierPolimiPageDriver(
        [{ stage: 'unknown', url: 'https://polimi.webex.com', title: 'Webex' }],
        [
          {
            providerId: 'webex',
            status: 'login_required',
            isIdentifierPrompt: false,
            isLoginTrigger: true,
            isSamlTransitPage: false,
            url: 'https://polimi.webex.com'
          },
          {
            providerId: 'webex',
            status: 'login_required',
            isIdentifierPrompt: false,
            isLoginTrigger: true,
            isSamlTransitPage: false,
            url: 'https://polimi.webex.com'
          },
          {
            providerId: 'webex',
            status: 'authenticated',
            isIdentifierPrompt: false,
            isLoginTrigger: false,
            isSamlTransitPage: false,
            url: 'https://polimi.webex.com/webappng/sites/polimi/dashboard'
          }
        ],
        'webex'
      );
      driver.onBeforeTriggerFederatedLogin = async () => {
        fedTriggerCount += 1;
        fedEntered.resolve();
        await fedRelease.promise;
      };
      return driver;
    });

    const fedClient = new PoliAuth({
      userStorageFactory: new InMemoryUserVaultStorageFactory(),
      identityRepository: users,
      sessionPool: pool,
      driverFactory: fedFactorySpy
    });
    await fedClient.saveCredentials(
      {
        personCode: '10992002',
        password: 'PooledFedPassword!'
      },
      9202
    );

    const fedCalls = Array.from({ length: 3 }, () =>
      fedClient.authenticateFederatedSaml({
        userId: 9202,
        entryUrl: 'https://polimi.webex.com',
        pollIntervalMs: 0
      })
    );
    await fedEntered.promise;
    expect(fedClient.isUserAuthenticationInFlight(9202)).toBe(true);
    fedRelease.resolve();
    const fedResults = await Promise.all(fedCalls);
    for (const res of fedResults) {
      expect(res.ok).toBe(true);
      expect(res).toBe(fedResults[0]);
    }
    expect(acquireSpy).toHaveBeenCalledTimes(1);
    expect(fedFactorySpy).toHaveBeenCalledTimes(1);
    expect(saveStateSpy).toHaveBeenCalledTimes(1);
    expect(releaseSpy).toHaveBeenCalledTimes(1);
    expect(fedTriggerCount).toBe(1);
    expect(fedClient.isUserAuthenticationInFlight(9202)).toBe(false);

    // 4) PoliAuth pre-browser reauth_required fast-fail skips pool lease completely
    await users.updateLoginStatus(9203, 'reauth_required', 'Account locked');
    acquireSpy.mockClear();
    const blockedOutcome = await client.authenticate({
      userId: 9203,
      pollDelayMs: 0
    });
    expect(blockedOutcome.ok).toBe(false);
    expect(blockedOutcome.status).toBe('reauth_required');
    expect(blockedOutcome.reauthRequired).toBe(true);
    expect(acquireSpy).not.toHaveBeenCalled();

    // 5) PoliAuth releases pool context and clears facade singleflight map on driverFactory failure
    const failingPoolTracking = createTrackingSessionPool();
    const failingGate = createDeferred();
    const failingEntered = createDeferred();
    const failingFactory = vi.fn(async () => {
      failingEntered.resolve();
      await failingGate.promise;
      throw new Error('driverFactory exploded');
    });
    const failingClient = new PoliAuth({
      userStorageFactory: new InMemoryUserVaultStorageFactory(),
      identityRepository: users,
      sessionPool: failingPoolTracking.pool,
      createPageDriver: failingFactory
    });
    await failingClient.saveCredentials(
      { personCode: '10992004', password: 'ValidPassword!' },
      9204
    );

    const failingPromises = Array.from({ length: 2 }, () =>
      failingClient.authenticate({ userId: 9204, pollDelayMs: 0 })
    );
    await failingEntered.promise;
    expect(failingClient.isUserAuthenticationInFlight(9204)).toBe(true);
    failingGate.resolve();
    const failingSettled = await Promise.allSettled(failingPromises);
    expect(failingSettled.every((r) => r.status === 'rejected')).toBe(true);
    expect(failingPoolTracking.acquireSpy).toHaveBeenCalledTimes(1);
    expect(failingPoolTracking.saveStateSpy).not.toHaveBeenCalled();
    expect(failingPoolTracking.releaseSpy).toHaveBeenCalledTimes(1);
    expect(failingClient.isUserAuthenticationInFlight(9204)).toBe(false);

    // 6) Descriptive error when driver is omitted without sessionPool or driverFactory,
    //    and Path 1 explicit-driver backward compatibility without touching sessionPool
    const poollessClient = new PoliAuth({ identityRepository: users });
    await expect(poollessClient.authenticate({ userId: 9201 })).rejects.toThrow(
      /requires sessionPool/i
    );
    acquireSpy.mockClear();
    const explicitDriver = new SimulatedPolimiPageDriver([
      { stage: 'unknown', url: 'about:blank', title: '' },
      { stage: 'credentials', url: 'https://aunicalogin.polimi.it/login', title: 'Login' },
      { stage: 'otp', url: 'https://aunicalogin.polimi.it/otp', title: '2FA' },
      {
        stage: 'authenticated',
        url: 'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do',
        title: 'Home'
      }
    ]);
    const explicitOutcome = await client.authenticate({
      userId: 9201,
      driver: explicitDriver,
      pollDelayMs: 0
    });
    expect(explicitOutcome.ok).toBe(true);
    expect(explicitDriver.submittedCreds).toHaveLength(1);
    expect(explicitDriver.submittedOtps).toHaveLength(1);
    expect(acquireSpy).not.toHaveBeenCalled();
  });
});
