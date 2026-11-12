import { describe, expect, it } from 'vitest';
import { PoliAuthOrchestrator } from '../domain/login-orchestrator.js';
import { OtpChallengeCoordinator } from '../domain/otp-challenge.js';
import { TotpService } from '../domain/totp.js';
import type {
  PolimiStageInspectionResult,
  FederatedSsoInspectionResult
} from '../domain/entities.js';
import type { AuthPageDriverPort } from '../interfaces/browser-driver-port.js';

class SimulatedPolimiPageDriver implements AuthPageDriverPort {
  public stages: PolimiStageInspectionResult[];
  public ssoStates: FederatedSsoInspectionResult[] = [];
  public submittedCreds: Array<{ personCode: string; password: string; stayConnected?: boolean }> =
    [];
  public submittedOtps: string[] = [];
  public submittedSsoEmails: string[] = [];
  public recoveredCount = 0;
  public navigatedUrls: string[] = [];

  constructor(
    stages: PolimiStageInspectionResult[],
    ssoStates: FederatedSsoInspectionResult[] = []
  ) {
    this.stages = [...stages];
    this.ssoStates = [...ssoStates];
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

  async recoverSessionPage(): Promise<{ ok: boolean; navigatedTo: string }> {
    this.recoveredCount += 1;
    return {
      ok: true,
      navigatedTo: 'https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376'
    };
  }

  async submitCredentials(params: {
    personCode: string;
    password: string;
    stayConnected?: boolean;
  }): Promise<{ ok: boolean; error?: string }> {
    this.submittedCreds.push(params);
    return { ok: true };
  }

  async submitOtp(params: { otp: string }): Promise<{ ok: boolean; error?: string }> {
    this.submittedOtps.push(params.otp);
    return { ok: true };
  }

  async inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult> {
    if (this.ssoStates.length > 1) {
      return this.ssoStates.shift()!;
    }
    return (
      this.ssoStates[0] ?? {
        status: 'authenticated',
        isEmailSsoPage: false,
        isSamlTransitPage: false,
        url: 'https://polimi.webex.com/webappng/sites/polimi/dashboard'
      }
    );
  }

  async submitFederatedEmailLogin(email: string): Promise<{ ok: boolean; error?: string }> {
    this.submittedSsoEmails.push(email);
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

  it('orchestrates multi-hop Federated SAML 2.0 SSO (email prompt -> PoliMi SAML credentials + 2FA -> authenticated)', async () => {
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
          status: 'login_required',
          isEmailSsoPage: true,
          isSamlTransitPage: true,
          url: 'https://idbroker-eu.webex.com/idb/saml2/jsp/doSSO.jsp'
        },
        {
          status: 'authenticated',
          isEmailSsoPage: false,
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
    expect(driver.submittedSsoEmails).toEqual(['mario.rossi@mail.polimi.it']);
    expect(driver.submittedCreds).toHaveLength(1);
    expect(driver.submittedOtps).toHaveLength(1);
  });
});
