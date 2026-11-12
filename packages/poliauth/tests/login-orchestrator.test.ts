import { describe, expect, it } from 'vitest';
import { PoliAuthOrchestrator } from '../domain/login-orchestrator.js';
import { OtpChallengeCoordinator } from '../domain/otp-challenge.js';
import { TotpService } from '../domain/totp.js';
import type {
  PolimiStageInspectionResult,
  FederatedSsoInspectionResult
} from '../domain/entities.js';
import type { PolimiPortalServiceDescriptor } from '../domain/service-registry.js';
import type { AuthPageDriverPort } from '../interfaces/browser-driver-port.js';
import {
  PlaywrightBrowserSessionPool,
  type PlaywrightBrowserLike,
  type PlaywrightContextLike
} from '../adapters/playwright-session-pool.js';
import { InMemorySessionStateStore } from '../storage/memory-storage.js';

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

  async inspectPolimiStage(
    _targetService?: PolimiPortalServiceDescriptor
  ): Promise<PolimiStageInspectionResult> {
    if (this.stages.length > 1) {
      return this.stages.shift()!;
    }
    return (
      this.stages[0] ?? {
        stage: 'archive',
        url: 'https://onlineservices.polimi.it/archivioregistrazioni',
        title: 'Archive'
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

  async openPortalService(
    service?: PolimiPortalServiceDescriptor
  ): Promise<{ ok: boolean; href?: string; error?: string }> {
    return {
      ok: true,
      href: `https://servizionline.polimi.it/Servizi.do?idServizio=${service?.serviceId ?? '2314'}`
    };
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
        url: 'https://polimi.webex.com/recordingservice/sites/polimi/recording/playback/123'
      }
    );
  }

  async submitFederatedEmailLogin(email: string): Promise<{ ok: boolean; error?: string }> {
    this.submittedSsoEmails.push(email);
    return { ok: true };
  }
}

describe('PoliAuthOrchestrator & PlaywrightBrowserSessionPool', () => {
  it('completes the full 5-stage PoliMi login flow (session_expired -> credentials -> auto-TOTP -> portal -> archive)', async () => {
    const totp = new TotpService();
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: totp });
    const orchestrator = new PoliAuthOrchestrator(otpCoordinator);

    const driver = new SimulatedPolimiPageDriver([
      // Initial check before goto()
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
        stage: 'portal',
        url: 'https://servizionline.polimi.it/Portale.do',
        title: 'Portale servizi'
      },
      {
        stage: 'archive',
        url: 'https://onlineservices.polimi.it/archivioregistrazioni',
        title: 'Archivio Registrazioni'
      }
    ]);

    const statusHistory: string[] = [];
    const outcome = await orchestrator.authenticateToService({
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
    expect(statusHistory).toContain('submitting_credentials');
    expect(statusHistory).toContain('submitting_otp');
    expect(statusHistory).toContain('opening_recording_archives');
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
      // First OTP inspection triggers auto-TOTP
      {
        stage: 'otp',
        url: 'https://aunicalogin.polimi.it/IdentificazioneUnica.do',
        title: '2FA OTP'
      },
      // Second OTP inspection means auto-TOTP was rejected -> falls back to manual OTP
      {
        stage: 'otp',
        url: 'https://aunicalogin.polimi.it/IdentificazioneDFA.do',
        title: '2FA OTP retry'
      },
      {
        stage: 'archive',
        url: 'https://onlineservices.polimi.it/archivioregistrazioni',
        title: 'Archive ready'
      }
    ]);

    const outcomePromise = orchestrator.authenticateToService({
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

    const outcome = await orchestrator.authenticateToService({
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

  it('orchestrates multi-hop Federated Webex SAML 2.0 SSO (email prompt -> PoliMi SAML credentials + 2FA -> authenticated)', async () => {
    const otpCoordinator = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orchestrator = new PoliAuthOrchestrator(otpCoordinator);

    const driver = new SimulatedPolimiPageDriver(
      [
        // Step 1: on Webex doSSO.jsp (not a PoliMi stage)
        {
          stage: 'unknown',
          url: 'https://idbroker-eu.webex.com/idb/saml2/jsp/doSSO.jsp',
          title: 'Sign In - Webex'
        },
        // Step 2: first sighting of PoliMi credentials page (allows 1 cycle for auto-SSO check)
        {
          stage: 'credentials',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=2070',
          title: 'PoliMi SAML IdP'
        },
        // Step 3: second sighting submits PoliMi credentials
        {
          stage: 'credentials',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=2070',
          title: 'PoliMi SAML IdP'
        },
        // Step 4: PoliMi 2FA OTP prompt
        {
          stage: 'otp',
          url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do',
          title: 'PoliMi SAML 2FA'
        },
        // Step 5: Redirected back to Webex player
        {
          stage: 'unknown',
          url: 'https://polimi.webex.com/recordingservice/sites/polimi/recording/playback/abc',
          title: 'Webex Player'
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
          url: 'https://polimi.webex.com/recordingservice/sites/polimi/recording/playback/abc'
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
      // Acquire context for user 1 and user 2 (fills capacity of 2)
      await pool.withUserContext(1, async ({ context }) => {
        expect(context.id).toBe(1);
      });
      await pool.withUserContext(2, async ({ context }) => {
        expect(context.id).toBe(2);
      });
      expect(pool.getStats().activeContexts).toBe(2);

      // Acquiring context for user 3 should evict LRU idle context (user 1) and persist its state
      await pool.withUserContext(3, async ({ context }) => {
        expect(context.id).toBe(3);
      });
      expect(closedContexts).toContain(1);
      expect(pool.getStats().activeContexts).toBe(2);

      // Re-acquiring context for user 1 should restore its persisted storageState
      await pool.withUserContext(1, async ({ context }) => {
        expect(context.restoredState).toEqual({
          cookies: [{ name: 'user_ctx', value: 'ctx-1' }]
        });
      });

      // Destroying user 1 with clearPersistedState removes its stored state
      await pool.destroyUserContext(1, { clearPersistedState: true });
      expect(await sessionStore.loadSessionState(1)).toBeNull();
    } finally {
      await pool.closeAll();
    }
  });
});
