import { describe, expect, it } from 'vitest';
import { JSDOM } from 'jsdom';
import { PoliAuth } from '../src/index.js';
import { PoliAuthOrchestrator } from '../application/login-orchestrator.js';
import { OtpChallengeCoordinator } from '../application/otp-challenge.js';
import { CredentialSetupWizard } from '../application/credential-wizard.js';
import { TotpService } from '../domain/totp.js';
import { redactSecrets } from '../domain/redaction.js';
import {
  inspectPolimiPageStage,
  isPolimiAuthenticatedSessionPage
} from '../adapters/polimi-dom-adapter.js';
import {
  inspectFederatedSsoPageBySpec,
  isFederatedIdentifierPromptPage
} from '../adapters/federated-sso-dom-adapter.js';
import {
  InMemoryUserIdentityRepository,
  InMemoryVaultStorage
} from '../storage/memory-storage.js';
import type {
  FederatedSsoInspectionResult,
  PolimiStageInspectionResult
} from '../domain/entities.js';
import type {
  AuthPageDriverPort,
  FederatedAuthPageDriverPort,
  FederatedSsoProviderSpec,
  PageActionResult,
  PolimiCredentialSubmission,
  PolimiOtpSubmission,
  SessionRecoveryResult
} from '../interfaces/index.js';

function createSequenceDriver(options: {
  polimiStages?: PolimiStageInspectionResult[];
  federatedPages?: FederatedSsoInspectionResult[];
  recoverResult?: SessionRecoveryResult;
  onSubmitCredentials?: (params: PolimiCredentialSubmission) => void;
  onSubmitOtp?: (params: PolimiOtpSubmission) => void;
  onSubmitIdentifier?: (identifier: string) => void;
  onTriggerLogin?: () => void;
}): FederatedAuthPageDriverPort {
  const polimiQueue = [...(options.polimiStages ?? [])];
  const fedQueue = [...(options.federatedPages ?? [])];

  const driver: AuthPageDriverPort & FederatedAuthPageDriverPort = {
    federatedProviderId: 'test-sp',
    async goto() {},
    async waitForNavigation() {},
    async inspectPolimiStage(): Promise<PolimiStageInspectionResult> {
      return (
        polimiQueue.shift() ?? {
          stage: 'authenticated',
          url: 'https://servizionline.polimi.it/portaleservizi/',
          title: 'Portale servizi'
        }
      );
    },
    async recoverSessionPage(): Promise<SessionRecoveryResult> {
      return (
        options.recoverResult ?? {
          ok: true,
          navigatedTo: 'https://aunicalogin.polimi.it/aunicalogin/'
        }
      );
    },
    async submitCredentials(params: PolimiCredentialSubmission): Promise<PageActionResult> {
      options.onSubmitCredentials?.(params);
      return { ok: true };
    },
    async submitOtp(params: PolimiOtpSubmission): Promise<PageActionResult> {
      options.onSubmitOtp?.(params);
      return { ok: true };
    },
    async inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult> {
      return (
        fedQueue.shift() ?? {
          providerId: 'test-sp',
          status: 'authenticated',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: false,
          url: 'https://sp.example.com/app'
        }
      );
    },
    async submitFederatedIdentifier(identifier: string): Promise<PageActionResult> {
      options.onSubmitIdentifier?.(identifier);
      return { ok: true };
    },
    async triggerFederatedLogin(): Promise<PageActionResult> {
      options.onTriggerLogin?.();
      return { ok: true };
    }
  };

  return driver;
}

describe('Phase 5B Remediation Edge Cases (@polisdk/poliauth)', () => {
  it('waits out lingering prompt/trigger pages during async SAML transitions instead of aborting prematurely', async () => {
    const totp = new TotpService();
    const otpCoord = new OtpChallengeCoordinator({ totpGenerator: totp });
    const orch = new PoliAuthOrchestrator(otpCoord);

    let submitIdCalls = 0;
    const modeADriver = createSequenceDriver({
      onSubmitIdentifier: () => {
        submitIdCalls += 1;
      },
      federatedPages: [
        {
          providerId: 'webex',
          status: 'login_required',
          isIdentifierPrompt: true,
          isLoginTrigger: false,
          isSamlTransitPage: true,
          url: 'https://idbroker-eu.webex.com/'
        },
        // Slow SP still shows identifier prompt on the very next poll after submission
        {
          providerId: 'webex',
          status: 'login_required',
          isIdentifierPrompt: true,
          isLoginTrigger: false,
          isSamlTransitPage: true,
          url: 'https://idbroker-eu.webex.com/'
        },
        {
          providerId: 'webex',
          status: 'sso_in_transit',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: true,
          url: 'https://aunicalogin.polimi.it/idp/SAML2'
        },
        {
          providerId: 'webex',
          status: 'authenticated',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: false,
          url: 'https://web.webex.com/home'
        }
      ],
      polimiStages: [
        {
          stage: 'authenticated',
          url: 'https://web.webex.com/home',
          title: 'Webex'
        }
      ]
    });

    const outcomeA = await orch.authenticateFederatedSaml({
      userId: 'saml-a',
      driver: modeADriver,
      credentials: {
        personCode: '10123456',
        password: 'Secret!',
        polimiEmail: 'mario.rossi@mail.polimi.it'
      },
      pollIntervalMs: 1,
      ssoTransitWindowMs: 2_000
    });

    expect(outcomeA.ok).toBe(true);
    expect(outcomeA.status).toBe('authenticated');
    expect(submitIdCalls).toBe(1);

    let triggerCalls = 0;
    const modeBDriver = createSequenceDriver({
      onTriggerLogin: () => {
        triggerCalls += 1;
      },
      federatedPages: [
        {
          providerId: 'moodle',
          status: 'login_required',
          isIdentifierPrompt: false,
          isLoginTrigger: true,
          isSamlTransitPage: false,
          url: 'https://beep.metid.polimi.it/login/index.php'
        },
        // Slow click navigation still reports login trigger on next poll
        {
          providerId: 'moodle',
          status: 'login_required',
          isIdentifierPrompt: false,
          isLoginTrigger: true,
          isSamlTransitPage: false,
          url: 'https://beep.metid.polimi.it/login/index.php'
        },
        {
          providerId: 'moodle',
          status: 'authenticated',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: false,
          url: 'https://beep.metid.polimi.it/my/'
        }
      ]
    });

    const outcomeB = await orch.authenticateFederatedSaml({
      userId: 'saml-b',
      driver: modeBDriver,
      credentials: { personCode: '10123456', password: 'Secret!' },
      pollIntervalMs: 1,
      ssoTransitWindowMs: 2_000
    });

    expect(outcomeB.ok).toBe(true);
    expect(triggerCalls).toBe(1);

    // Mode C starts on blank/interstitial sso_in_transit (isSamlTransitPage: false)
    const modeCDriver = createSequenceDriver({
      federatedPages: [
        {
          providerId: 'direct-sp',
          status: 'sso_in_transit',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: false,
          url: 'about:blank'
        },
        {
          providerId: 'direct-sp',
          status: 'sso_in_transit',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: true,
          url: 'https://aunicalogin.polimi.it/idp/SAML2'
        },
        {
          providerId: 'direct-sp',
          status: 'authenticated',
          isIdentifierPrompt: false,
          isLoginTrigger: false,
          isSamlTransitPage: false,
          url: 'https://sp.polimi.it/home'
        }
      ]
    });

    const outcomeC = await orch.authenticateFederatedSaml({
      userId: 'saml-c',
      driver: modeCDriver,
      credentials: { personCode: '10123456', password: 'Secret!' },
      pollIntervalMs: 1,
      ssoTransitWindowMs: 2_000
    });

    expect(outcomeC.ok).toBe(true);

    // Expired ssoTransitWindowMs while still waiting_for_login fails deterministically
    const stalledModeBDriver = createSequenceDriver({
      federatedPages: Array.from({ length: 10 }, () => ({
        providerId: 'moodle',
        status: 'login_required' as const,
        isIdentifierPrompt: false,
        isLoginTrigger: true,
        isSamlTransitPage: false,
        url: 'https://beep.metid.polimi.it/login/index.php'
      }))
    });
    const stalledOutcome = await orch.authenticateFederatedSaml({
      userId: 'saml-timeout',
      driver: stalledModeBDriver,
      credentials: { personCode: '10123456', password: 'Secret!' },
      pollIntervalMs: 5,
      maxPollSteps: 10,
      ssoTransitWindowMs: 1
    });
    expect(stalledOutcome.ok).toBe(false);
    expect(stalledOutcome.status).toBe('waiting_for_login');
  });

  it('debounces post-submit transitions, short-circuits on explicit DOM error, and enforces manual OTP retry cap', async () => {
    const otpCoord = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });
    const orch = new PoliAuthOrchestrator(otpCoord);

    // 1. Debounce prevents duplicate submitCredentials while navigation is in progress
    let credSubmits = 0;
    const debounceDriver = createSequenceDriver({
      onSubmitCredentials: () => {
        credSubmits += 1;
      },
      polimiStages: [
        // Pre-goto initial stage check
        {
          stage: 'unknown',
          url: 'about:blank',
          title: ''
        },
        {
          stage: 'credentials',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp',
          title: 'Autenticazione'
        },
        {
          stage: 'credentials',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp',
          title: 'Autenticazione'
        },
        {
          stage: 'credentials',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp',
          title: 'Autenticazione'
        },
        {
          stage: 'authenticated',
          url: 'https://servizionline.polimi.it/portaleservizi/',
          title: 'Portale servizi'
        }
      ]
    });

    const debounceOutcome = await orch.authenticate({
      userId: 'debounce-user',
      driver: debounceDriver,
      credentials: { personCode: '10123456', password: 'Secret!' },
      pollDelayMs: 5,
      postSubmitDebounceMs: 2_000
    });
    expect(debounceOutcome.ok).toBe(true);
    expect(credSubmits).toBe(1);

    // 2. Explicit DOM error banner short-circuits debounce immediately
    const errDriver = createSequenceDriver({
      polimiStages: [
        // Pre-goto initial stage check
        {
          stage: 'unknown',
          url: 'about:blank',
          title: ''
        },
        {
          stage: 'credentials',
          url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp',
          title: 'Autenticazione'
        },
        {
          stage: 'credentials',
          url: 'https://aunicalogin.polimi.it/aunicalogin/IdentificazioneUnica.do',
          title: 'Autenticazione',
          errorMessage: 'Credenziali non valide'
        }
      ]
    });

    const startErr = Date.now();
    const errOutcome = await orch.authenticate({
      userId: 'err-user',
      driver: errDriver,
      credentials: { personCode: '10123456', password: 'WrongPassword!' },
      pollDelayMs: 5,
      postSubmitDebounceMs: 5_000
    });
    expect(errOutcome.ok).toBe(false);
    expect(errOutcome.error).toContain('Credenziali non valide');
    expect(Date.now() - startErr).toBeLessThan(1_000);

    // 3. Manual OTP retry cap fails deterministically instead of looping up to maxSteps
    let otpPrompts = 0;
    const manualOtpLoopDriver = createSequenceDriver({
      polimiStages: [
        {
          stage: 'unknown',
          url: 'about:blank',
          title: ''
        },
        ...Array.from({ length: 15 }, () => ({
          stage: 'otp' as const,
          url: 'https://aunicalogin.polimi.it/aunicalogin/IdentificazioneDFA.do',
          title: 'Autenticazione 2FA'
        }))
      ]
    });

    const otpOutcome = await orch.authenticate({
      userId: 'otp-cap-user',
      driver: manualOtpLoopDriver,
      credentials: { personCode: '10123456', password: 'Secret!' },
      pollDelayMs: 0,
      maxSteps: 30,
      maxManualOtpAttempts: 2,
      callbacks: {
        onOtpRequired: () => {
          otpPrompts += 1;
          setTimeout(() => {
            otpCoord.submitManualOtpForUser('otp-cap-user', '000000');
          }, 5);
        }
      }
    });

    expect(otpOutcome.ok).toBe(false);
    expect(otpPrompts).toBe(2);
    expect(otpOutcome.error).toMatch(/2/i);
  });

  it('prevents Moodle .usermenu false-positive auth, enforces && in identifierPrompt, and scopes PoliMi DOM checks', () => {
    const moodleSpec: FederatedSsoProviderSpec = {
      providerId: 'moodle',
      displayName: 'Moodle',
      loginTrigger: {
        hostnames: ['beep.metid.polimi.it'],
        pathnameSubstrings: ['/login/index.php'],
        triggerSelector: '.btn-shibboleth'
      },
      transitHostnames: ['shibidp.polimi.it', 'aunicalogin.polimi.it'],
      transitUrlSubstrings: ['/Shibboleth.sso/'],
      authenticatedHostnames: ['beep.metid.polimi.it'],
      authenticatedSelectors: ['.usermenu']
    };

    const loginDom = new JSDOM(
      `<html><body>
        <div class="usermenu">You are not logged in</div>
        <a class="btn-shibboleth" href="/Shibboleth.sso/Login">PoliMi Login</a>
      </body></html>`
    );
    const loginInspection = inspectFederatedSsoPageBySpec(moodleSpec, loginDom.window.document, {
      href: 'https://beep.metid.polimi.it/login/index.php',
      hostname: 'beep.metid.polimi.it',
      pathname: '/login/index.php'
    });
    expect(loginInspection.status).toBe('login_required');
    expect(loginInspection.isLoginTrigger).toBe(true);

    const dashboardDom = new JSDOM(`<html><body><div class="usermenu">Mario Rossi</div></body></html>`);
    const authInspection = inspectFederatedSsoPageBySpec(moodleSpec, dashboardDom.window.document, {
      href: 'https://beep.metid.polimi.it/my/',
      hostname: 'beep.metid.polimi.it',
      pathname: '/my/'
    });
    expect(authInspection.status).toBe('authenticated');

    // Identifier prompt && check
    const promptSpec: FederatedSsoProviderSpec = {
      providerId: 'sp-prompt',
      displayName: 'SP Prompt',
      identifierPrompt: {
        hostnames: ['login.sp.example.com'],
        pathnameSubstrings: ['/sso/start'],
        identifierInputSelector: 'input#email',
        submitButtonSelector: 'button[type="submit"]'
      },
      transitHostnames: [],
      transitUrlSubstrings: [],
      authenticatedHostnames: ['app.sp.example.com']
    };
    const emptyDoc = new JSDOM('<html><body></body></html>').window.document;
    expect(
      isFederatedIdentifierPromptPage(promptSpec, emptyDoc, {
        href: 'https://login.sp.example.com/other',
        hostname: 'login.sp.example.com',
        pathname: '/other'
      })
    ).toBe(false);
    expect(
      isFederatedIdentifierPromptPage(promptSpec, emptyDoc, {
        href: 'https://login.sp.example.com/sso/start',
        hostname: 'login.sp.example.com',
        pathname: '/sso/start'
      })
    ).toBe(true);

    // PoliMi domain scoping blocks non-PoliMi lookalikes
    const lookalikeDom = new JSDOM(
      `<html><body><div class="jaf-user-info">Fake</div><p>Sessione di lavoro terminata</p></body></html>`
    );
    expect(
      isPolimiAuthenticatedSessionPage(lookalikeDom.window.document, {
        href: 'https://evil.example.com/portaleservizi/',
        hostname: 'evil.example.com',
        pathname: '/portaleservizi/'
      })
    ).toBe(false);
    const nonPolimiStage = inspectPolimiPageStage(lookalikeDom.window.document, {
      href: 'https://evil.example.com/article',
      hostname: 'evil.example.com',
      pathname: '/article'
    });
    expect(nonPolimiStage.stage).toBe('unknown');
  });

  it('validates wizard inputs, preserves password whitespace, guards shared storage on logout, and redacts deep/circular objects', async () => {
    const wizard = new CredentialSetupWizard();
    wizard.startSession('wiz-1');

    // Early skip rejected without clearing session
    expect(wizard.skipTotpStep('wiz-1')?.status).toBe('validation_error');
    expect(wizard.hasActiveSession('wiz-1')).toBe(true);

    // Invalid person code rejected
    expect(wizard.submitStepInput('wiz-1', 'not-digits')?.status).toBe('validation_error');
    expect(wizard.submitStepInput('wiz-1', '10987654')?.status).toBe('next_step');

    // Leading/trailing whitespace preserved in password
    expect(wizard.submitStepInput('wiz-1', '  p@ss with spaces  ')?.status).toBe('next_step');

    // Invalid email rejected
    expect(wizard.submitStepInput('wiz-1', 'user@gmail.com')?.status).toBe('validation_error');
    expect(wizard.submitStepInput('wiz-1', 'mario.rossi@mail.polimi.it')?.status).toBe('next_step');

    const done = wizard.skipTotpStep('wiz-1');
    expect(done?.status).toBe('completed');
    if (done?.status === 'completed') {
      expect(done.credentials.password).toBe('  p@ss with spaces  ');
    }

    // Multi-user PoliAuth with shared singleStorage + explicit userRepository does NOT wipe shared storage on logout(userId)
    const sharedStorage = new InMemoryVaultStorage('shared-dev-secret');
    const userRepo = new InMemoryUserIdentityRepository();
    userRepo.ensureUser('u1', { username: 'alice' });
    userRepo.updateLoginStatus('u1', 'authenticated');

    const auth = new PoliAuth({
      storage: sharedStorage,
      userRepository: userRepo
    });
    await auth.saveCredentials({ personCode: '10111111', password: 'SharedPassword!' });

    await auth.logout('u1');
    expect(userRepo.getUser('u1')?.loginStatus).toBe('idle');
    expect((await auth.loadCredentials())?.password).toBe('SharedPassword!');

    // Deep object, Error, Map, Set, and circular reference redaction
    const circular: Record<string, unknown> = {
      password: 'MyUltraSecretPassword',
      nested: {
        totpSecret: 'JBSWY3DPEHPK3PXP',
        notes:
          'Authorization: Bearer header-token-123456 & https://sp.example.com/cb?ticket=ST-999 & {"secret":"json-secret-value"}'
      },
      items: new Set(['MyUltraSecretPassword']),
      bag: new Map([
        ['password', 'map-password-value'],
        ['key', 'MyUltraSecretPassword']
      ])
    };
    circular.self = circular;
    const err = new Error('Login failed for MyUltraSecretPassword');
    circular.err = err;

    const sanitized = redactSecrets(circular, ['MyUltraSecretPassword']) as Record<string, unknown>;
    expect(JSON.stringify(sanitized)).not.toContain('MyUltraSecretPassword');
    expect(JSON.stringify(sanitized)).not.toContain('JBSWY3DPEHPK3PXP');
    expect(JSON.stringify(sanitized)).not.toContain('header-token-123456');
    expect(JSON.stringify(sanitized)).not.toContain('ST-999');
    expect(JSON.stringify(sanitized)).not.toContain('json-secret-value');
    expect(JSON.stringify(sanitized)).not.toContain('map-password-value');
    expect(sanitized.items).toEqual(['[REDACTED]']);
    expect(sanitized.bag).toEqual({ password: '[REDACTED]', key: '[REDACTED]' });
    expect((sanitized.err as Error).message).toBe('Login failed for [REDACTED]');
    expect(sanitized.self).toBe('[Circular]');
  });
});
