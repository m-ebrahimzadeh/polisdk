/**
 * @module @polisdk/poliauth/application/login-orchestrator
 * Unified, Driver-Agnostic Politecnico di Milano SSO & Federated SAML SSO Orchestrator (Application Layer).
 *
 * Authentication concludes once an authenticated PoliMi session is established,
 * completely decoupled from downstream service navigation.
 */

import type {
  IdentityId,
  LoginCredentials,
  LoginFlowStatus
} from '../domain/entities.js';
import { POLIMI_LOGIN_FLOW_SPEC } from '../domain/login-flow-spec.js';
import type { AuthPageDriverPort } from '../interfaces/browser-driver-port.js';
import type {
  LoginProgressCallbacks,
  OtpChallengeProviderPort
} from '../interfaces/otp-provider-port.js';

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface PolimiSessionAuthRequest {
  userId: IdentityId;
  driver: AuthPageDriverPort;
  credentials: Pick<LoginCredentials, 'personCode' | 'password'> &
    Partial<Pick<LoginCredentials, 'otp' | 'totpSecret' | 'polimiEmail'>>;
  /**
   * Optional custom SSO entry URL. Defaults to `POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl`.
   */
  entryUrl?: string;
  /** Maximum state-machine iterations before timing out. Default: 40. */
  maxSteps?: number;
  /** Poll delay in milliseconds between intermediate steps. Default: 400. */
  pollDelayMs?: number;
  /** Optional callbacks for live status updates. */
  callbacks?: LoginProgressCallbacks;
  /** Optional hook invoked once an authenticated PoliMi session is established. */
  onAuthenticated?: () => void | Promise<void>;
}

export interface PolimiSessionAuthOutcome {
  ok: boolean;
  status: LoginFlowStatus;
  url?: string;
  error?: string;
}

export interface FederatedSamlAuthRequest {
  userId: IdentityId;
  driver: AuthPageDriverPort;
  credentials: Partial<LoginCredentials>;
  /** Poll interval in milliseconds. Default: 250. */
  pollIntervalMs?: number;
  /** Maximum poll iterations. Default: 180. */
  maxPollSteps?: number;
  /** SAML transit window duration in ms after submitting email on federated SP. Default: 25_000. */
  ssoTransitWindowMs?: number;
  callbacks?: LoginProgressCallbacks;
  onAuthenticated?: () => void | Promise<void>;
}

export interface FederatedSamlAuthOutcome {
  ok: boolean;
  status: 'authenticated' | 'waiting_for_login' | 'failed';
  error?: string;
}

export class PoliAuthOrchestrator {
  constructor(private readonly otpCoordinator: OtpChallengeProviderPort) {}

  /**
   * Executes the Politecnico di Milano SSO + 2FA authentication state machine
   * until an authenticated PoliMi session (`stage === 'authenticated'`) is established.
   */
  public async authenticate(
    req: PolimiSessionAuthRequest
  ): Promise<PolimiSessionAuthOutcome> {
    const {
      userId,
      driver,
      credentials,
      entryUrl = POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl,
      maxSteps = 40,
      pollDelayMs = 400,
      callbacks,
      onAuthenticated
    } = req;

    const notify = async (status: LoginFlowStatus, msg: string) => {
      await callbacks?.onStatusChange?.(status, msg);
    };

    try {
      const initialStage = await driver
        .inspectPolimiStage()
        .catch(() => ({ stage: 'unknown' as const, url: '', title: '' }));

      if (initialStage.stage === 'authenticated') {
        await onAuthenticated?.();
        await notify('authenticated', 'Authenticated on PoliMi SSO session.');
        return {
          ok: true,
          status: 'authenticated',
          url: initialStage.url
        };
      }

      await notify('opening_login', 'Opening PoliMi SSO login...');
      await driver.goto(entryUrl);

      let submittedCredentialsCount = 0;
      let submittedAutoTotpCount = 0;
      let submittedManualOtpCount = 0;
      let explicitOtpToConsume = credentials.otp?.trim() || '';

      for (let step = 0; step < maxSteps; step++) {
        const stageInfo = await driver.inspectPolimiStage().catch(() => null);

        if (!stageInfo) {
          await sleep(pollDelayMs);
          continue;
        }

        // 1. Authenticated PoliMi session reached
        if (stageInfo.stage === 'authenticated') {
          await onAuthenticated?.();
          await notify('authenticated', 'Authenticated on PoliMi SSO session.');
          return {
            ok: true,
            status: 'authenticated',
            url: stageInfo.url
          };
        }

        // 2. Session expired or bare /aunicalogin/ security violation recovery
        if (stageInfo.stage === 'session_expired') {
          await notify('recovering_session', 'Recovering expired PoliMi session...');
          await driver.recoverSessionPage();
          await sleep(pollDelayMs);
          continue;
        }

        // 3. Credentials form (`IdentificazioneUnica.do`)
        if (stageInfo.stage === 'credentials') {
          if (submittedCredentialsCount > 0 && stageInfo.errorMessage) {
            const errMsg = `PoliMi login rejected: ${stageInfo.errorMessage}`;
            await notify('failed', errMsg);
            return { ok: false, status: 'failed', error: errMsg };
          }

          if (submittedCredentialsCount >= 2) {
            const errMsg =
              stageInfo.errorMessage ||
              'PoliMi login remained on credentials page after submission.';
            await notify('failed', errMsg);
            return { ok: false, status: 'failed', error: errMsg };
          }

          const personCode = credentials.personCode?.trim() || '';
          const password = credentials.password || '';
          if (!personCode || !password) {
            const errMsg =
              'Person Code and Password are required to sign in on aunicalogin.polimi.it.';
            await notify('failed', errMsg);
            return { ok: false, status: 'failed', error: errMsg };
          }

          submittedCredentialsCount += 1;
          await notify(
            'submitting_credentials',
            'Submitting PoliMi credentials...'
          );

          const credResult = await driver.submitCredentials({
            personCode,
            password,
            stayConnected: true
          });

          if (!credResult.ok) {
            const errMsg =
              credResult.error || 'Failed to submit PoliMi credentials.';
            await notify('failed', errMsg);
            return { ok: false, status: 'failed', error: errMsg };
          }

          if (pollDelayMs > 0) await sleep(Math.min(350, pollDelayMs));
          continue;
        }

        // 4. 2FA OTP verification (`form#form_scelta2fa`)
        if (stageInfo.stage === 'otp') {
          if (submittedManualOtpCount > 0 && stageInfo.errorMessage) {
            const errMsg = `PoliMi 2FA OTP rejected: ${stageInfo.errorMessage}`;
            await notify('failed', errMsg);
            return { ok: false, status: 'failed', error: errMsg };
          }

          let otpToSubmit = '';
          if (explicitOtpToConsume) {
            otpToSubmit = explicitOtpToConsume;
            explicitOtpToConsume = '';
            submittedManualOtpCount += 1;
          } else {
            const otpChoice = await this.otpCoordinator.obtainOtpCodeForUser(
              userId,
              credentials.totpSecret,
              submittedAutoTotpCount === 0,
              callbacks
            );
            otpToSubmit = otpChoice.otp;
            if (otpChoice.usedAutoTotp) {
              submittedAutoTotpCount += 1;
            } else {
              submittedManualOtpCount += 1;
            }
          }

          await notify('submitting_otp', 'Submitting 6-digit 2FA code...');
          const otpResult = await driver.submitOtp({ otp: otpToSubmit });
          if (!otpResult.ok) {
            const errMsg = otpResult.error || 'Failed to submit 2FA OTP.';
            await notify('failed', errMsg);
            return { ok: false, status: 'failed', error: errMsg };
          }

          if (pollDelayMs > 0) await sleep(Math.min(450, pollDelayMs));
          continue;
        }

        // 5. Intermediate SSO handoff (`AunicaLogin.do?evn_checkCookieSSO=evento`) or loading
        await sleep(pollDelayMs);
      }

      const timeoutMsg =
        'Timed out navigating through PoliMi authentication pipeline.';
      await notify('failed', timeoutMsg);
      return { ok: false, status: 'failed', error: timeoutMsg };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      await notify('failed', msg);
      return { ok: false, status: 'failed', error: msg };
    }
  }

  /**
   * Handles a single step of Federated SAML SSO across an SP and PoliMi IdP.
   */
  public async handleFederatedSamlStep(params: {
    userId: IdentityId;
    driver: AuthPageDriverPort;
    credentials: Partial<LoginCredentials>;
    state: {
      submittedEmail: boolean;
      ssoTransitDeadline: number;
      seenSamlCredentialsStep: boolean;
      submittedSamlCredentialsCount: number;
      submittedSamlAutoTotpCount: number;
    };
    ssoTransitWindowMs?: number;
    callbacks?: LoginProgressCallbacks;
  }): Promise<
    | { action: 'continue_polling' }
    | { action: 'authenticated_or_ready' }
    | { action: 'login_required'; reason: string }
  > {
    const {
      userId,
      driver,
      credentials,
      state,
      ssoTransitWindowMs = 25_000,
      callbacks
    } = params;

    const polimiStage = await driver.inspectPolimiStage().catch(() => null);

    // 1. Intermediate PoliMi SSO handoff (`AunicaLogin.do?evn_checkCookieSSO=evento`)
    if (polimiStage && polimiStage.stage === 'sso_handoff') {
      return { action: 'continue_polling' };
    }

    // 2. PoliMi credentials form encountered during SAML SSO
    if (polimiStage && polimiStage.stage === 'credentials') {
      if (!state.seenSamlCredentialsStep) {
        state.seenSamlCredentialsStep = true;
        return { action: 'continue_polling' };
      }

      if (
        credentials.personCode &&
        credentials.password &&
        state.submittedSamlCredentialsCount < 2
      ) {
        state.submittedSamlCredentialsCount += 1;
        const credRes = await driver.submitCredentials({
          personCode: credentials.personCode,
          password: credentials.password,
          stayConnected: true
        });
        if (!credRes.ok) {
          return {
            action: 'login_required',
            reason:
              credRes.error ||
              'Failed to submit PoliMi credentials during SAML SSO.'
          };
        }
        return { action: 'continue_polling' };
      }
    }

    // 3. PoliMi 2FA OTP prompt encountered during SAML SSO
    if (polimiStage && polimiStage.stage === 'otp') {
      const otpChoice = await this.otpCoordinator.obtainOtpCodeForUser(
        userId,
        credentials.totpSecret,
        state.submittedSamlAutoTotpCount === 0,
        callbacks
      );
      if (otpChoice.usedAutoTotp) {
        state.submittedSamlAutoTotpCount += 1;
      }
      const otpRes = await driver.submitOtp({ otp: otpChoice.otp });
      if (!otpRes.ok) {
        return {
          action: 'login_required',
          reason:
            otpRes.error || 'Failed to submit 2FA OTP during SAML SSO.'
        };
      }
      return { action: 'continue_polling' };
    }

    // 4. Check Federated SSO state
    if (!driver.inspectFederatedSsoPage) {
      return {
        action: 'login_required',
        reason: 'Driver does not support federated SSO page inspection.'
      };
    }

    const ssoInspection = await driver.inspectFederatedSsoPage().catch(() => null);
    if (!ssoInspection) {
      return { action: 'continue_polling' };
    }

    if (ssoInspection.status === 'authenticated') {
      return { action: 'authenticated_or_ready' };
    }

    if (ssoInspection.isEmailSsoPage && !state.submittedEmail) {
      const email = (credentials.polimiEmail || '').trim();
      if (!email) {
        return {
          action: 'login_required',
          reason:
            'Federated SAML SSO requires your PoliMi email (@mail.polimi.it).'
        };
      }

      if (!driver.submitFederatedEmailLogin) {
        return {
          action: 'login_required',
          reason: 'Driver does not support federated SSO email submission.'
        };
      }

      state.submittedEmail = true;
      state.ssoTransitDeadline = Date.now() + ssoTransitWindowMs;
      const submitRes = await driver.submitFederatedEmailLogin(email);
      if (!submitRes.ok) {
        return {
          action: 'login_required',
          reason: submitRes.error || 'Failed to submit federated SSO email.'
        };
      }
      return { action: 'continue_polling' };
    }

    if (state.submittedEmail && Date.now() < state.ssoTransitDeadline) {
      return { action: 'continue_polling' };
    }

    return {
      action: 'login_required',
      reason:
        ssoInspection.reason ||
        'Federated SSO authentication required.'
    };
  }

  /**
   * Loops `handleFederatedSamlStep` across multi-hop SAML redirects until authenticated or failed.
   */
  public async authenticateFederatedSaml(
    req: FederatedSamlAuthRequest
  ): Promise<FederatedSamlAuthOutcome> {
    const {
      userId,
      driver,
      credentials,
      pollIntervalMs = 250,
      maxPollSteps = 180,
      ssoTransitWindowMs = 25_000,
      callbacks,
      onAuthenticated
    } = req;

    const state = {
      submittedEmail: false,
      ssoTransitDeadline: 0,
      seenSamlCredentialsStep: false,
      submittedSamlCredentialsCount: 0,
      submittedSamlAutoTotpCount: 0
    };

    for (let step = 0; step < maxPollSteps; step++) {
      const res = await this.handleFederatedSamlStep({
        userId,
        driver,
        credentials,
        state,
        ssoTransitWindowMs,
        callbacks
      });

      if (res.action === 'authenticated_or_ready') {
        await onAuthenticated?.();
        return { ok: true, status: 'authenticated' };
      }

      if (res.action === 'login_required') {
        return {
          ok: false,
          status: 'waiting_for_login',
          error: res.reason
        };
      }

      if (pollIntervalMs > 0) {
        await sleep(pollIntervalMs);
      }
    }

    return {
      ok: false,
      status: 'failed',
      error: 'Timed out waiting for federated SAML SSO completion.'
    };
  }
}
