/**
 * @module @polisdk/poliauth/domain/login-orchestrator
 * Unified, Driver-Agnostic Politecnico di Milano & Federated SAML SSO Orchestrator.
 *
 * Consolidates the multi-stage login state machines that were previously duplicated across:
 * - `polirecord/src/background/index.ts` (`executeAutomatedPolimiLogin` & Webex SSO poll loop)
 * - `polirecord/src/bot/browser/polimi-session.ts` (`ensureAuthenticatedArchivePage`)
 * - `polirecord/src/bot/browser/webex-downloader.ts` (Webex SAML SSO & mid-SAML credentials/OTP loop)
 */

import type {
  IdentityId,
  LoginCredentials,
  LoginFlowStatus
} from './entities';
import { POLIMI_LOGIN_FLOW_SPEC } from './login-flow-spec';
import {
  RECORDINGS_ARCHIVE_SERVICE,
  type PolimiPortalServiceDescriptor
} from './service-registry';
import type { AuthPageDriverPort } from '../interfaces/browser-driver-port';
import type {
  LoginProgressCallbacks,
  OtpChallengeProviderPort
} from '../interfaces/otp-provider-port';

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export interface PolimiServiceAuthRequest {
  userId: IdentityId;
  driver: AuthPageDriverPort;
  credentials: Pick<LoginCredentials, 'personCode' | 'password'> &
    Partial<Pick<LoginCredentials, 'otp' | 'totpSecret' | 'polimiEmail'>>;
  /**
   * Target portal service to open once authenticated on `Portale.do`.
   * Defaults to `RECORDINGS_ARCHIVE_SERVICE` (`idServizio=2314`).
   * Pass `null` if you only want to authenticate as far as `Portale.do`.
   */
  targetService?: PolimiPortalServiceDescriptor | null;
  /** Maximum state-machine iterations before timing out. Default: 40. */
  maxSteps?: number;
  /** Poll delay in milliseconds between intermediate steps. Default: 400. */
  pollDelayMs?: number;
  /** Optional callbacks for live UI/Telegram status updates. */
  callbacks?: LoginProgressCallbacks;
  /** Optional hook invoked whenever an authenticated target page is reached (e.g. to persist cookies). */
  onAuthenticated?: () => void | Promise<void>;
}

export interface PolimiServiceAuthOutcome {
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
  /** SAML transit window duration in ms after submitting email on `doSSO.jsp`. Default: 25_000. */
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
   * Executes the full Politecnico di Milano SSO + 2FA + Online Services Portal
   * + Target Service handoff state machine against any `AuthPageDriverPort`.
   */
  public async authenticateToService(
    req: PolimiServiceAuthRequest
  ): Promise<PolimiServiceAuthOutcome> {
    const {
      userId,
      driver,
      credentials,
      targetService = RECORDINGS_ARCHIVE_SERVICE,
      maxSteps = 40,
      pollDelayMs = 400,
      callbacks,
      onAuthenticated
    } = req;

    const notify = async (status: LoginFlowStatus, msg: string) => {
      await callbacks?.onStatusChange?.(status, msg);
    };

    try {
      // Check if already on the target service page
      const initialStage = await driver
        .inspectPolimiStage(targetService ?? undefined)
        .catch(() => ({ stage: 'unknown' as const, url: '', title: '' }));

      if (
        initialStage.stage === 'archive' ||
        initialStage.stage === 'target_service' ||
        (targetService === null && initialStage.stage === 'portal')
      ) {
        await onAuthenticated?.();
        await notify(
          'authenticated',
          `Authenticated on ${targetService?.name || 'PoliMi Online Services Portal'}.`
        );
        return {
          ok: true,
          status: 'authenticated',
          url: initialStage.url
        };
      }

      await notify('opening_login', 'Opening PoliMi SSO login...');
      await driver.goto(POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl);

      let submittedCredentialsCount = 0;
      let submittedAutoTotpCount = 0;
      let submittedManualOtpCount = 0;
      let clickedPortalServiceCount = 0;
      let explicitOtpToConsume = credentials.otp?.trim() || '';

      for (let step = 0; step < maxSteps; step++) {
        const stageInfo = await driver
          .inspectPolimiStage(targetService ?? undefined)
          .catch(() => null);

        if (!stageInfo) {
          await sleep(pollDelayMs);
          continue;
        }

        // 1. Target service reached
        if (
          stageInfo.stage === 'archive' ||
          stageInfo.stage === 'target_service' ||
          (targetService === null && stageInfo.stage === 'portal')
        ) {
          await onAuthenticated?.();
          await notify(
            'authenticated',
            `Authenticated on ${targetService?.name || 'PoliMi Online Services Portal'}.`
          );
          return {
            ok: true,
            status: 'authenticated',
            url: stageInfo.url
          };
        }

        // 2. Session expired or bare /aunicalogin/ security violation recovery
        if (stageInfo.stage === 'session_expired') {
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

        // 5. Online Services Portal (`Portale.do`) -> Click target service
        if (stageInfo.stage === 'portal' && targetService !== null) {
          if (clickedPortalServiceCount >= 3) {
            const errMsg = `Failed to open ${targetService.name} from PoliMi Online Services Portal after multiple attempts.`;
            await notify('failed', errMsg);
            return { ok: false, status: 'failed', error: errMsg };
          }
          clickedPortalServiceCount += 1;

          const statusKind: LoginFlowStatus =
            targetService.serviceId ===
            POLIMI_LOGIN_FLOW_SPEC.entry.recordingsArchiveServiceId
              ? 'opening_recording_archives'
              : 'opening_target_service';

          await notify(
            statusKind,
            `Opening ${targetService.name} (idServizio=${targetService.serviceId})...`
          );

          const portalResult = await driver.openPortalService(targetService);
          if (!portalResult.ok) {
            const errMsg =
              portalResult.error ||
              `Could not find ${targetService.name} link on PoliMi Portal.`;
            await notify('failed', errMsg);
            return { ok: false, status: 'failed', error: errMsg };
          }

          if (pollDelayMs > 0) await sleep(Math.min(500, pollDelayMs));
          continue;
        }

        // 6. Intermediate SSO handoff (`AunicaLogin.do?evn_checkCookieSSO=evento`) or loading
        await sleep(pollDelayMs);
      }

      const timeoutMsg = `Timed out navigating through PoliMi authentication pipeline to ${targetService?.name || 'Portal'}.`;
      await notify('failed', timeoutMsg);
      return { ok: false, status: 'failed', error: timeoutMsg };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      await notify('failed', msg);
      return { ok: false, status: 'failed', error: msg };
    }
  }

  /**
   * Handles a single step or full resolution of Federated SAML SSO (e.g. Webex `doSSO.jsp`
   * -> `shibidp.polimi.it` -> `aunicalogin.polimi.it` -> target SP).
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

    // 2. PoliMi credentials form encountered during SAML SSO (`id_servizio=2070`)
    if (polimiStage && polimiStage.stage === 'credentials') {
      // Give auto-SSO onload script 1 poll cycle to submit evn_checkCookieSSO if present
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

    // 4. Check Federated SSO state (e.g. Webex `doSSO.jsp` `#IDToken1` / `#IDButton2`)
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
