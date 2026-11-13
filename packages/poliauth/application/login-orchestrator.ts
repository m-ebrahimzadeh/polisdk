/**
 * @module @polisdk/poliauth/application/login-orchestrator
 * Unified, Driver-Agnostic Politecnico di Milano SSO & Federated SAML SSO Orchestrator (Application Layer).
 *
 * Authentication concludes once an authenticated PoliMi session is established,
 * completely decoupled from downstream service navigation.
 */

import {
  classifyPolimiFailure,
  classifyPolimiSemanticError,
  normalizeIdentityId,
  PoliAuthDiagnosticError,
  type IdentityId,
  type LoginCredentials,
  type LoginFlowStatus,
  type PoliAuthDiagnosticErrorPayload,
  type PoliAuthFailureClassification,
  type PolimiPageStage,
  type PolimiSemanticErrorCode,
  type PolimiStageInspectionResult
} from '../domain/entities.js';
import { redactSecrets, redactSensitiveErrorText } from '../domain/redaction.js';
import { getTotpRemainingSeconds } from '../domain/totp.js';
import { POLIMI_LOGIN_FLOW_SPEC } from '../domain/login-flow-spec.js';
import type {
  AuthPageDriverPort,
  FederatedAuthPageDriverPort,
  FederatedSsoPageDriverPort
} from '../interfaces/browser-driver-port.js';
import type { AuthLoggerPort } from '../interfaces/logger-port.js';
import type {
  LoginProgressCallbacks,
  OtpChallengeProviderPort
} from '../interfaces/otp-provider-port.js';
import type {
  UserIdentityReaderPort,
  UserIdentityWriterPort
} from '../interfaces/storage-port.js';
import { createRedactingLogger } from './redacting-logger.js';

export type PoliAuthIdentityRepository = Partial<
  UserIdentityReaderPort & UserIdentityWriterPort
>;

export const DEFAULT_POLIMI_SESSION_PROBE_URL =
  `https://${POLIMI_LOGIN_FLOW_SPEC.authenticatedSession.portalHostname}${POLIMI_LOGIN_FLOW_SPEC.authenticatedSession.portalPathnameSubstring}`;

export interface PoliAuthExecutionOptions {
  /**
   * Deduplicate concurrent requests for the same user/target via an in-memory
   * singleflight registry. Default: `true`.
   */
  enableSingleflight?: boolean;
  /**
   * Probe an existing/restored session via `sessionProbeUrl` before initiating a
   * full multi-stage login at `serviceEntryUrl`.
   */
  enablePreHydrationSessionProbe?: boolean;
  /**
   * Optional override URL used during Tier 1 pre-hydration session probing.
   * Defaults to `DEFAULT_POLIMI_SESSION_PROBE_URL`.
   */
  sessionProbeUrl?: string;
}

export interface PoliAuthOrchestratorDependencies {
  otpCoordinator: OtpChallengeProviderPort;
  logger?: AuthLoggerPort;
  identityRepository?: PoliAuthIdentityRepository;
  /** Enable per-user singleflight deduplication across concurrent calls. Default: `true`. */
  enableSingleflight?: boolean;
  /** Enable Tier 1 pre-hydration session probing by default across calls. Default: `false`. */
  enablePreHydrationSessionProbe?: boolean;
  /** Custom Tier 1 session probe URL. Defaults to `DEFAULT_POLIMI_SESSION_PROBE_URL`. */
  sessionProbeUrl?: string;
}

export type PoliAuthOrchestratorOptions = Omit<
  PoliAuthOrchestratorDependencies,
  'otpCoordinator'
>;

export function resolveUserSingleflightKey(
  userId: IdentityId | undefined,
  personCode?: string
): string | null {
  if (userId !== undefined && userId !== null) {
    const normalized = normalizeIdentityId(userId);
    if (normalized.length > 0) {
      return `user:${normalized}`;
    }
  }
  const normalizedPersonCode = personCode?.trim() || '';
  if (normalizedPersonCode.length > 0) {
    return `personCode:${normalizedPersonCode}`;
  }
  return null;
}

export function resolveFederatedSingleflightKey(
  userId: IdentityId | undefined,
  personCode: string | undefined,
  entryUrl?: string,
  providerId?: string
): string | null {
  const userKey = resolveUserSingleflightKey(userId, personCode);
  if (!userKey) {
    return null;
  }
  const providerKeyOrEntryUrl =
    entryUrl?.trim() || providerId?.trim() || 'default';
  return `${userKey}::federated::${providerKeyOrEntryUrl}`;
}

export async function executeWithSingleflight<T>(params: {
  registry: Map<string, Promise<T>>;
  key: string | null;
  enabled: boolean;
  execute: () => Promise<T>;
  onJoin?: () => void;
}): Promise<T> {
  const { registry, key, enabled, execute, onJoin } = params;
  if (!enabled || !key) {
    return execute();
  }

  const existing = registry.get(key);
  if (existing) {
    onJoin?.();
    return existing;
  }

  let settled = false;
  let inFlight!: Promise<T>;
  inFlight = (async () => {
    try {
      return await execute();
    } finally {
      settled = true;
      if (registry.get(key) === inFlight) {
        registry.delete(key);
      }
    }
  })();

  if (!settled) {
    registry.set(key, inFlight);
  }
  return inFlight;
}

export async function checkPreBrowserCircuitBreakerForIdentity(
  identityRepository: PoliAuthIdentityRepository | undefined,
  userId: IdentityId | undefined,
  logger?: AuthLoggerPort
): Promise<string | null> {
  if (
    userId === undefined ||
    userId === null ||
    normalizeIdentityId(userId).length === 0 ||
    !identityRepository?.getUser
  ) {
    return null;
  }
  const existingUser = await identityRepository.getUser(userId);
  if (existingUser?.loginStatus !== 'reauth_required') {
    return null;
  }
  const reason = existingUser.loginError
    ? `PoliMi login blocked by reauth_required circuit breaker: ${existingUser.loginError}. Update credentials to reset account status.`
    : 'PoliMi login blocked by reauth_required circuit breaker. Update credentials to reset account status.';
  const safeReason = redactSensitiveErrorText(reason);
  logger?.warn(
    `Pre-browser circuit breaker fast-fail for user ${normalizeIdentityId(userId)}: ${safeReason}`
  );
  return safeReason;
}

function isAuthLoggerPort(value: unknown): value is AuthLoggerPort {
  return (
    typeof value === 'object' &&
    value !== null &&
    ('debug' in value || 'info' in value || 'warn' in value || 'error' in value)
  );
}

function isStage1TerminalSemanticError(
  code: PolimiSemanticErrorCode | undefined
): code is 'INVALID_CREDENTIALS' | 'PASSWORD_EXPIRED' | 'ACCOUNT_LOCKED' {
  return (
    code === 'INVALID_CREDENTIALS' ||
    code === 'PASSWORD_EXPIRED' ||
    code === 'ACCOUNT_LOCKED'
  );
}

function resolveStageSemanticError(
  stageInfo: PolimiStageInspectionResult,
  operation: string
): PolimiSemanticErrorCode | undefined {
  if (stageInfo.semanticErrorCode) {
    return stageInfo.semanticErrorCode;
  }
  if (stageInfo.diagnosticError?.semanticErrorCode) {
    return stageInfo.diagnosticError.semanticErrorCode;
  }
  if (
    stageInfo.errorMessage ||
    stageInfo.diagnosticSnapshot ||
    (stageInfo.httpStatus !== undefined && stageInfo.httpStatus >= 500)
  ) {
    return classifyPolimiSemanticError({
      operation,
      stage: stageInfo.stage,
      url: stageInfo.url,
      httpStatus: stageInfo.httpStatus,
      errorMessage: stageInfo.errorMessage,
      diagnosticSnapshot: stageInfo.diagnosticSnapshot
    });
  }
  return undefined;
}

async function waitForNextTotpWindowBoundary(options: {
  pollIntervalMs: number;
  nextTotpWindowWaitMs?: number;
  waitForNextTotpWindow?: (waitMs: number) => Promise<void>;
  logger?: AuthLoggerPort;
}): Promise<void> {
  const computedWaitMs = getTotpRemainingSeconds(Date.now(), 30) * 1000 + 250;
  const requestedWaitMs =
    options.nextTotpWindowWaitMs !== undefined
      ? Math.max(0, options.nextTotpWindowWaitMs)
      : computedWaitMs;
  options.logger?.warn(
    `PoliMi 2FA auto-TOTP rejected; waiting ${requestedWaitMs}ms for next 30s RFC 6238 window before single retry.`
  );
  if (options.waitForNextTotpWindow) {
    await options.waitForNextTotpWindow(requestedWaitMs);
    return;
  }
  if (options.nextTotpWindowWaitMs !== undefined) {
    await sleep(requestedWaitMs);
    return;
  }
  if (options.pollIntervalMs > 0) {
    await sleep(computedWaitMs);
    return;
  }
  await sleep(0);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function extractDiagnosticFromError(
  err: unknown,
  operation: string,
  url?: string
): PoliAuthDiagnosticErrorPayload {
  if (err instanceof PoliAuthDiagnosticError) {
    return err.payload;
  }
  return classifyPolimiFailure({
    component: '@polisdk/poliauth/application/login-orchestrator',
    operation,
    stage: 'error',
    url,
    error: err
  });
}

function isTransientNavigationError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  if (
    /target closed|page has been closed|browser has been closed|context has been closed|has been closed|tab was closed|no tab with id/i.test(
      msg
    )
  ) {
    return false;
  }
  return /execution context was destroyed|most likely because of a navigation|cannot find context|frame was detached|receiving end does not exist|message port closed|receiving end returned empty response|navigating to|navigation in progress|interrupted by.*navigation/i.test(
    msg
  );
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
  /**
   * When `true`, probes an existing/hydrated PoliMi session on `sessionProbeUrl` before
   * navigating to `entryUrl` (`getservizio.xml?id_servizio=376`).
   */
  probeExistingSession?: boolean;
  /**
   * Optional override URL for Tier 1 pre-hydration session probing.
   * Defaults to `DEFAULT_POLIMI_SESSION_PROBE_URL`.
   */
  sessionProbeUrl?: string;
  /** Maximum state-machine iterations before timing out. Default: 40. */
  maxSteps?: number;
  /** Poll delay in milliseconds between intermediate steps. Default: 400. */
  pollDelayMs?: number;
  /** Maximum manual OTP submission retries before failing deterministically. Default: 3. */
  maxManualOtpAttempts?: number;
  /**
   * Minimum milliseconds to wait for transition or DOM error banner after submitting
   * credentials or OTP before retrying/falling back. Defaults to `1500` when `pollDelayMs > 0` (`0` otherwise).
   */
  postSubmitDebounceMs?: number;
  /** Optional explicit override for next-window wait duration after 1st `OTP_REJECTED` (ms). */
  nextTotpWindowWaitMs?: number;
  /** Optional hook overriding the wait for the next 30s TOTP window on `OTP_REJECTED` retry. */
  waitForNextTotpWindow?: (waitMs: number) => Promise<void>;
  /** Optional callbacks for live status updates. */
  callbacks?: LoginProgressCallbacks;
  /** Optional hook invoked once an authenticated PoliMi session is established. */
  onAuthenticated?: () => void | Promise<void>;
}

export interface PolimiSessionAuthOutcome {
  ok: boolean;
  status: LoginFlowStatus;
  stage?: PolimiPageStage;
  url?: string;
  sessionReused?: boolean;
  preHydrationProbeHit?: boolean;
  error?: string;
  classification?: PoliAuthFailureClassification;
  semanticErrorCode?: PolimiSemanticErrorCode;
  reauthRequired?: boolean;
  diagnostic?: PoliAuthDiagnosticErrorPayload;
}

export interface FederatedSamlAuthRequest {
  userId: IdentityId;
  driver:
    | FederatedAuthPageDriverPort
    | (AuthPageDriverPort & Partial<FederatedSsoPageDriverPort>);
  credentials: Partial<LoginCredentials>;
  /**
   * Optional institutional identifier (e.g. `student@mail.polimi.it`) submitted on
   * Mode A (`identifierPrompt`) SPs. Falls back to `credentials.polimiEmail`.
   */
  federatedIdentifier?: string;
  /**
   * Optional Service Provider entry URL to navigate to before polling
   * (useful for Mode B landing pages and Mode C direct-redirect SPs).
   */
  entryUrl?: string;
  /** Poll interval in milliseconds. Default: 250. */
  pollIntervalMs?: number;
  /** Maximum poll iterations. Default: 180. */
  maxPollSteps?: number;
  /** SAML transit window duration in ms after initiating SSO or entering transit. Default: 25_000. */
  ssoTransitWindowMs?: number;
  /** Maximum manual OTP submission retries before failing deterministically. Default: 3. */
  maxManualOtpAttempts?: number;
  /**
   * Minimum milliseconds to wait for PoliMi IdP transition or error banner after submitting
   * credentials or OTP during SAML SSO. Defaults to `1500` when `pollIntervalMs > 0` (`0` otherwise).
   */
  postSubmitDebounceMs?: number;
  /** Optional explicit override for next-window wait duration after 1st `OTP_REJECTED` (ms). */
  nextTotpWindowWaitMs?: number;
  /** Optional hook overriding the wait for the next 30s TOTP window on `OTP_REJECTED` retry. */
  waitForNextTotpWindow?: (waitMs: number) => Promise<void>;
  callbacks?: LoginProgressCallbacks;
  onAuthenticated?: () => void | Promise<void>;
}

export interface FederatedSamlAuthOutcome {
  ok: boolean;
  status: 'authenticated' | 'waiting_for_login' | 'failed' | 'reauth_required';
  error?: string;
  classification?: PoliAuthFailureClassification;
  semanticErrorCode?: PolimiSemanticErrorCode;
  reauthRequired?: boolean;
  diagnostic?: PoliAuthDiagnosticErrorPayload;
}

export interface FederatedSamlFlowState {
  submittedIdentifier: boolean;
  triggeredLogin: boolean;
  ssoTransitDeadline: number;
  seenSamlCredentialsStep: boolean;
  submittedSamlCredentialsCount: number;
  submittedSamlAutoTotpCount: number;
  submittedSamlManualOtpCount: number;
  retriedSamlAutoTotpNextWindow?: boolean;
  explicitOtpToConsume?: string;
  credentialsDebounceUntil?: number;
  otpDebounceUntil?: number;
}

export class PoliAuthOrchestrator {
  private readonly otpCoordinator: OtpChallengeProviderPort;
  private readonly logger?: AuthLoggerPort;
  private readonly identityRepository?: PoliAuthIdentityRepository;
  private readonly enableSingleflight: boolean;
  private readonly enablePreHydrationSessionProbe: boolean;
  private readonly sessionProbeUrl: string;
  private readonly inFlightAuth = new Map<string, Promise<PolimiSessionAuthOutcome>>();
  private readonly inFlightFederatedAuth = new Map<
    string,
    Promise<FederatedSamlAuthOutcome>
  >();

  constructor(dependencies: PoliAuthOrchestratorDependencies);
  constructor(
    otpCoordinator: OtpChallengeProviderPort,
    loggerOrOptions?: AuthLoggerPort | PoliAuthOrchestratorOptions
  );
  constructor(
    otpCoordinatorOrDeps: OtpChallengeProviderPort | PoliAuthOrchestratorDependencies,
    loggerOrOptions?: AuthLoggerPort | PoliAuthOrchestratorOptions
  ) {
    if ('otpCoordinator' in otpCoordinatorOrDeps) {
      this.otpCoordinator = otpCoordinatorOrDeps.otpCoordinator;
      this.logger = otpCoordinatorOrDeps.logger
        ? createRedactingLogger(otpCoordinatorOrDeps.logger)
        : undefined;
      this.identityRepository = otpCoordinatorOrDeps.identityRepository;
      this.enableSingleflight = otpCoordinatorOrDeps.enableSingleflight ?? true;
      this.enablePreHydrationSessionProbe =
        otpCoordinatorOrDeps.enablePreHydrationSessionProbe ?? false;
      this.sessionProbeUrl =
        otpCoordinatorOrDeps.sessionProbeUrl ?? DEFAULT_POLIMI_SESSION_PROBE_URL;
    } else {
      this.otpCoordinator = otpCoordinatorOrDeps;
      if (isAuthLoggerPort(loggerOrOptions)) {
        this.logger = createRedactingLogger(loggerOrOptions);
        this.identityRepository = undefined;
        this.enableSingleflight = true;
        this.enablePreHydrationSessionProbe = false;
        this.sessionProbeUrl = DEFAULT_POLIMI_SESSION_PROBE_URL;
      } else {
        this.logger = loggerOrOptions?.logger
          ? createRedactingLogger(loggerOrOptions.logger)
          : undefined;
        this.identityRepository = loggerOrOptions?.identityRepository;
        this.enableSingleflight = loggerOrOptions?.enableSingleflight ?? true;
        this.enablePreHydrationSessionProbe =
          loggerOrOptions?.enablePreHydrationSessionProbe ?? false;
        this.sessionProbeUrl =
          loggerOrOptions?.sessionProbeUrl ?? DEFAULT_POLIMI_SESSION_PROBE_URL;
      }
    }
  }

  /**
   * Returns the total count of active singleflight authentication flows
   * across both standard PoliMi SSO and federated SAML SSO.
   */
  public getInFlightCount(): number {
    return this.inFlightAuth.size + this.inFlightFederatedAuth.size;
  }

  /**
   * Returns `true` if `userId` currently has an active in-flight singleflight
   * execution in either standard or federated SSO authentication.
   */
  public isUserAuthenticationInFlight(userId: IdentityId): boolean {
    const userKey = resolveUserSingleflightKey(userId);
    if (!userKey) {
      return false;
    }
    if (this.inFlightAuth.has(userKey)) {
      return true;
    }
    const federatedPrefix = `${userKey}::federated::`;
    for (const key of this.inFlightFederatedAuth.keys()) {
      if (key.startsWith(federatedPrefix)) {
        return true;
      }
    }
    return false;
  }

  private async checkPreBrowserCircuitBreaker(userId: IdentityId): Promise<string | null> {
    return checkPreBrowserCircuitBreakerForIdentity(
      this.identityRepository,
      userId,
      this.logger
    );
  }

  private async tripCircuitBreaker(
    userId: IdentityId,
    semanticErrorCode: PolimiSemanticErrorCode | undefined,
    errorMessage: string
  ): Promise<boolean> {
    if (
      semanticErrorCode === 'IDP_MAINTENANCE' ||
      semanticErrorCode === 'DOM_SELECTOR_DRIFT' ||
      !semanticErrorCode
    ) {
      return false;
    }
    const safeError = redactSensitiveErrorText(errorMessage);
    this.logger?.warn(
      `Tripping reauth_required circuit breaker (${semanticErrorCode}) for user ${String(userId)}: ${safeError}`
    );
    if (userId && this.identityRepository?.updateLoginStatus) {
      await this.identityRepository.updateLoginStatus(userId, 'reauth_required', safeError);
    }
    return true;
  }

  /**
   * Executes the Politecnico di Milano SSO + 2FA authentication state machine
   * until an authenticated PoliMi session (`stage === 'authenticated'`) is established.
   *
   * Concurrent invocations for the same user identity join a single in-flight Promise
   * unless `enableSingleflight` is explicitly disabled.
   */
  public authenticate(
    req: PolimiSessionAuthRequest,
    options?: PoliAuthExecutionOptions
  ): Promise<PolimiSessionAuthOutcome> {
    const useSingleflight = options?.enableSingleflight ?? this.enableSingleflight;
    const key = resolveUserSingleflightKey(req.userId, req.credentials?.personCode);

    return executeWithSingleflight({
      registry: this.inFlightAuth,
      key,
      enabled: useSingleflight,
      onJoin: () => {
        const normalizedUser =
          req.userId !== undefined && req.userId !== null
            ? normalizeIdentityId(req.userId)
            : '';
        this.logger?.info('Joining existing in-flight PoliMi authentication flow.', {
          scope: 'orchestrator',
          flow: 'polimi',
          ...(normalizedUser ? { userId: normalizedUser } : { keyType: 'personCode' })
        });
      },
      execute: () => this.executeAuthenticate(req, options)
    });
  }

  private async tryPreHydrationSessionProbe(params: {
    driver: AuthPageDriverPort;
    probeUrl: string;
    pollDelayMs: number;
  }): Promise<{ authenticated: true; url: string } | { authenticated: false }> {
    const { driver, probeUrl, pollDelayMs } = params;
    try {
      await driver.goto(probeUrl);
      if (pollDelayMs > 0) {
        await driver
          .waitForNavigation(Math.min(Math.max(pollDelayMs * 3, 1_000), 2_500))
          .catch((err) => {
            this.logger?.debug(
              'Pre-hydration session probe waitForNavigation did not settle.',
              redactSensitiveErrorText(err)
            );
          });
      }
    } catch (err) {
      const probeFailure = classifyPolimiFailure({
        component: '@polisdk/poliauth/application/login-orchestrator',
        operation: 'probeExistingSession',
        stage: 'entry',
        url: probeUrl,
        selectorOrEndpoint: probeUrl,
        error: err
      });
      if (probeFailure.classification === 'TARGET_CLOSED') {
        throw err;
      }
      this.logger?.warn(
        `Pre-hydration session probe navigation failed; continuing to full PoliMi login: ${probeFailure.message}`,
        probeFailure
      );
      return { authenticated: false };
    }

    const inspectProbeStage = async (): Promise<PolimiStageInspectionResult> => {
      try {
        return await driver.inspectPolimiStage();
      } catch (err) {
        if (isTransientNavigationError(err)) {
          this.logger?.debug(
            'Transient navigation error inspecting pre-hydration probe stage; retrying once.',
            redactSensitiveErrorText(err)
          );
          if (pollDelayMs > 0) {
            await driver
              .waitForNavigation(Math.min(Math.max(pollDelayMs * 3, 1_000), 2_000))
              .catch((waitErr) => {
                this.logger?.debug(
                  'Pre-hydration retry waitForNavigation did not settle.',
                  redactSensitiveErrorText(waitErr)
                );
              });
          }
          try {
            return await driver.inspectPolimiStage();
          } catch (retryErr) {
            const retryFailure = classifyPolimiFailure({
              component: '@polisdk/poliauth/application/login-orchestrator',
              operation: 'probeExistingSession',
              url: probeUrl,
              error: retryErr
            });
            if (retryFailure.classification === 'TARGET_CLOSED') {
              throw retryErr;
            }
            this.logger?.debug(
              'Pre-hydration probe retry inspection interrupted; continuing to full login.',
              redactSensitiveErrorText(retryErr)
            );
            return { stage: 'unknown', url: probeUrl, title: '' };
          }
        }
        const inspectFailure = classifyPolimiFailure({
          component: '@polisdk/poliauth/application/login-orchestrator',
          operation: 'probeExistingSession',
          url: probeUrl,
          error: err
        });
        if (inspectFailure.classification === 'TARGET_CLOSED') {
          throw err;
        }
        this.logger?.debug(
          'Pre-hydration probe inspection failed; continuing to full login.',
          redactSensitiveErrorText(err)
        );
        return { stage: 'unknown', url: probeUrl, title: '' };
      }
    };

    const probeStage = await inspectProbeStage();
    if (probeStage.stage === 'authenticated') {
      return { authenticated: true, url: probeStage.url };
    }

    this.logger?.debug(
      'Pre-hydration session probe did not find an active session; falling back to standard PoliMi login.',
      {
        probeStage: probeStage.stage,
        probeUrl: redactSecrets(probeUrl)
      }
    );
    return { authenticated: false };
  }

  private async executeAuthenticate(
    req: PolimiSessionAuthRequest,
    options?: PoliAuthExecutionOptions
  ): Promise<PolimiSessionAuthOutcome> {
    const {
      userId,
      driver,
      credentials,
      entryUrl = POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl,
      maxSteps = 40,
      pollDelayMs = 400,
      maxManualOtpAttempts = 3,
      postSubmitDebounceMs = pollDelayMs > 0 ? Math.max(1_500, pollDelayMs * 3) : 0,
      nextTotpWindowWaitMs,
      waitForNextTotpWindow,
      callbacks,
      onAuthenticated
    } = req;

    const enablePreHydrationProbe =
      req.probeExistingSession ??
      options?.enablePreHydrationSessionProbe ??
      this.enablePreHydrationSessionProbe;
    const resolvedProbeUrl =
      req.sessionProbeUrl ??
      options?.sessionProbeUrl ??
      this.sessionProbeUrl ??
      DEFAULT_POLIMI_SESSION_PROBE_URL;

    const effectiveMaxManualOtpAttempts = Math.max(1, maxManualOtpAttempts);

    const notify = async (status: LoginFlowStatus, msg: string) => {
      await callbacks?.onStatusChange?.(status, msg);
    };

    try {
      const breakerReason = await this.checkPreBrowserCircuitBreaker(userId);
      if (breakerReason) {
        await notify('reauth_required', breakerReason);
        return {
          ok: false,
          status: 'reauth_required',
          error: breakerReason,
          classification: 'AUTHENTICATION_REJECTED',
          reauthRequired: true
        };
      }

      const initialStage = await driver
        .inspectPolimiStage()
        .catch((err) => {
          const initFailure = classifyPolimiFailure({
            component: '@polisdk/poliauth/application/login-orchestrator',
            operation: 'inspectPolimiStage',
            error: err
          });
          if (initFailure.classification === 'TARGET_CLOSED') {
            throw err;
          }
          this.logger?.debug(
            'Initial PoliMi stage inspection interrupted; proceeding to login entry URL.',
            redactSensitiveErrorText(err)
          );
          return { stage: 'unknown' as const, url: '', title: '' };
        });

      if (initialStage.stage === 'authenticated') {
        await onAuthenticated?.();
        await notify('authenticated', 'Authenticated on PoliMi SSO session.');
        return {
          ok: true,
          status: 'authenticated',
          stage: 'authenticated',
          url: initialStage.url,
          sessionReused: true,
          preHydrationProbeHit: true
        };
      }

      if (enablePreHydrationProbe) {
        await notify('opening_login', 'Checking existing PoliMi session...');
        const probeResult = await this.tryPreHydrationSessionProbe({
          driver,
          probeUrl: resolvedProbeUrl,
          pollDelayMs
        });
        if (probeResult.authenticated) {
          await onAuthenticated?.();
          await notify('authenticated', 'Authenticated via existing PoliMi session.');
          return {
            ok: true,
            status: 'authenticated',
            stage: 'authenticated',
            url: probeResult.url,
            sessionReused: true,
            preHydrationProbeHit: true
          };
        }
      }

      await notify('opening_login', 'Opening PoliMi SSO login...');
      await driver.goto(entryUrl);

      let submittedCredentialsCount = 0;
      let submittedAutoTotpCount = 0;
      let submittedManualOtpCount = 0;
      let autoTotpNextWindowRetried = false;
      let retryAutoTotpPending = false;
      let credentialsDebounceUntil = 0;
      let otpDebounceUntil = 0;
      let explicitOtpToConsume = credentials.otp?.trim() || '';

      for (let step = 0; step < maxSteps; step++) {
        const stageInfo = await driver.inspectPolimiStage().catch((err) => {
          if (isTransientNavigationError(err)) {
            this.logger?.debug(
              'Transient error inspecting PoliMi stage; retrying.',
              redactSensitiveErrorText(err)
            );
            return null;
          }
          throw err;
        });

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
            stage: 'authenticated',
            url: stageInfo.url,
            sessionReused: false,
            preHydrationProbeHit: false
          };
        }

        // 1.5 Global Semantic Outage / Account Lockout / Expired Password Gate (any stage)
        const stageSemantic = resolveStageSemanticError(stageInfo, 'inspectPolimiPageStage');
        if (stageSemantic === 'ACCOUNT_LOCKED' || stageSemantic === 'PASSWORD_EXPIRED') {
          const errMsg =
            stageInfo.errorMessage ||
            stageInfo.diagnosticError?.message ||
            (stageSemantic === 'ACCOUNT_LOCKED'
              ? 'PoliMi account is locked or suspended.'
              : 'PoliMi password has expired and must be changed.');
          const diagnostic = classifyPolimiFailure({
            component: '@polisdk/poliauth/application/login-orchestrator',
            operation: 'inspectPolimiPageStage',
            stage: stageInfo.stage,
            url: stageInfo.url,
            httpStatus: stageInfo.httpStatus,
            errorMessage: stageInfo.errorMessage ?? errMsg,
            diagnosticSnapshot: stageInfo.diagnosticSnapshot,
            error: errMsg
          });
          await this.tripCircuitBreaker(userId, stageSemantic, errMsg);
          await notify('failed', errMsg);
          return {
            ok: false,
            status: 'failed',
            url: stageInfo.url,
            error: errMsg,
            classification: diagnostic.classification,
            semanticErrorCode: stageSemantic,
            reauthRequired: true,
            diagnostic
          };
        }

        if (stageSemantic === 'IDP_MAINTENANCE') {
          const diag =
            stageInfo.diagnosticError ??
            classifyPolimiFailure({
              component: '@polisdk/poliauth/application/login-orchestrator',
              operation: 'inspectPolimiPageStage',
              stage: stageInfo.stage,
              url: stageInfo.url,
              httpStatus: stageInfo.httpStatus,
              errorMessage: stageInfo.errorMessage,
              diagnosticSnapshot: stageInfo.diagnosticSnapshot,
              error: stageInfo.errorMessage || 'PoliMi Identity Provider maintenance detected.'
            });
          this.logger?.warn(`PoliMi outage detected: ${diag.message}`, diag);
          await notify('failed', diag.message);
          return {
            ok: false,
            status: 'failed',
            url: stageInfo.url,
            error: diag.message,
            classification: diag.classification,
            semanticErrorCode: 'IDP_MAINTENANCE',
            reauthRequired: false,
            diagnostic: diag
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
          otpDebounceUntil = 0;
          if (submittedCredentialsCount > 0 && stageInfo.errorMessage) {
            const errMsg = `PoliMi login rejected: ${stageInfo.errorMessage}`;
            const diagnostic = classifyPolimiFailure({
              component: '@polisdk/poliauth/application/login-orchestrator',
              operation: 'submitCredentials',
              stage: 'credentials',
              url: stageInfo.url,
              httpStatus: stageInfo.httpStatus,
              errorMessage: stageInfo.errorMessage,
              diagnosticSnapshot: stageInfo.diagnosticSnapshot,
              error: errMsg
            });
            const semanticErrorCode =
              diagnostic.semanticErrorCode ?? stageSemantic ?? 'INVALID_CREDENTIALS';
            const tripped = isStage1TerminalSemanticError(semanticErrorCode)
              ? await this.tripCircuitBreaker(userId, semanticErrorCode, errMsg)
              : false;
            await notify('failed', errMsg);
            return {
              ok: false,
              status: 'failed',
              url: stageInfo.url,
              error: errMsg,
              classification: diagnostic.classification,
              semanticErrorCode,
              reauthRequired: tripped,
              diagnostic
            };
          }

          if (
            submittedCredentialsCount > 0 &&
            postSubmitDebounceMs > 0 &&
            Date.now() < credentialsDebounceUntil
          ) {
            await sleep(pollDelayMs);
            continue;
          }

          if (submittedCredentialsCount >= 2) {
            const errMsg =
              stageInfo.errorMessage ||
              'PoliMi login remained on credentials page after submission.';
            const diagnostic = classifyPolimiFailure({
              component: '@polisdk/poliauth/application/login-orchestrator',
              operation: 'submitCredentials',
              stage: 'credentials',
              url: stageInfo.url,
              httpStatus: stageInfo.httpStatus,
              errorMessage: stageInfo.errorMessage,
              diagnosticSnapshot: stageInfo.diagnosticSnapshot,
              error: errMsg
            });
            const semanticErrorCode = diagnostic.semanticErrorCode;
            const tripped = isStage1TerminalSemanticError(semanticErrorCode)
              ? await this.tripCircuitBreaker(userId, semanticErrorCode, errMsg)
              : false;
            await notify('failed', errMsg);
            return {
              ok: false,
              status: 'failed',
              url: stageInfo.url,
              error: errMsg,
              classification: diagnostic.classification,
              ...(semanticErrorCode ? { semanticErrorCode } : {}),
              reauthRequired: tripped,
              diagnostic
            };
          }

          const personCode = credentials.personCode?.trim() || '';
          const password = credentials.password || '';
          if (!personCode || !password) {
            const errMsg =
              'Person Code and Password are required to sign in on aunicalogin.polimi.it.';
            const diagnostic = classifyPolimiFailure({
              component: '@polisdk/poliauth/application/login-orchestrator',
              operation: 'submitCredentials',
              stage: 'credentials',
              url: stageInfo.url,
              error: errMsg
            });
            await notify('failed', errMsg);
            return {
              ok: false,
              status: 'failed',
              url: stageInfo.url,
              error: errMsg,
              classification: diagnostic.classification,
              ...(diagnostic.semanticErrorCode
                ? { semanticErrorCode: diagnostic.semanticErrorCode }
                : {}),
              diagnostic
            };
          }

          submittedCredentialsCount += 1;
          await notify(
            'submitting_credentials',
            'Submitting PoliMi credentials...'
          );

          const credResult = (await driver.submitCredentials({
            personCode,
            password,
            stayConnected: true
          })) as { ok: boolean; error?: string; diagnostic?: PoliAuthDiagnosticErrorPayload };

          if (!credResult.ok) {
            const diagnostic =
              credResult.diagnostic ??
              classifyPolimiFailure({
                component: '@polisdk/poliauth/application/login-orchestrator',
                operation: 'submitCredentials',
                stage: 'credentials',
                url: stageInfo.url,
                error: credResult.error || 'Failed to submit PoliMi credentials.'
              });
            const errMsg = credResult.error || diagnostic.message;
            const semanticErrorCode = diagnostic.semanticErrorCode;
            const tripped = isStage1TerminalSemanticError(semanticErrorCode)
              ? await this.tripCircuitBreaker(userId, semanticErrorCode, errMsg)
              : false;
            await notify('failed', errMsg);
            return {
              ok: false,
              status: 'failed',
              url: stageInfo.url,
              error: errMsg,
              classification: diagnostic.classification,
              ...(semanticErrorCode ? { semanticErrorCode } : {}),
              reauthRequired: tripped,
              diagnostic
            };
          }

          credentialsDebounceUntil = Date.now() + postSubmitDebounceMs;
          if (postSubmitDebounceMs > 0) {
            await driver.waitForNavigation(Math.min(postSubmitDebounceMs, 1_500)).catch(() => undefined);
          }
          if (pollDelayMs > 0) await sleep(Math.min(350, pollDelayMs));
          continue;
        }

        // 4. 2FA OTP verification (`form#form_scelta2fa`)
        if (stageInfo.stage === 'otp') {
          credentialsDebounceUntil = 0;
          if (submittedManualOtpCount > 0 && stageInfo.errorMessage) {
            const errMsg = `PoliMi 2FA OTP rejected: ${stageInfo.errorMessage}`;
            const diagnostic = classifyPolimiFailure({
              component: '@polisdk/poliauth/application/login-orchestrator',
              operation: 'submitOtp',
              stage: 'otp',
              url: stageInfo.url,
              httpStatus: stageInfo.httpStatus,
              errorMessage: stageInfo.errorMessage,
              diagnosticSnapshot: stageInfo.diagnosticSnapshot,
              error: errMsg
            });
            const semanticErrorCode = diagnostic.semanticErrorCode ?? 'OTP_REJECTED';
            const tripped = await this.tripCircuitBreaker(userId, semanticErrorCode, errMsg);
            await notify('failed', errMsg);
            return {
              ok: false,
              status: 'failed',
              url: stageInfo.url,
              error: errMsg,
              classification: diagnostic.classification,
              semanticErrorCode,
              reauthRequired: tripped,
              diagnostic
            };
          }

          if (submittedAutoTotpCount > 0 && stageInfo.errorMessage) {
            const errMsg = `PoliMi 2FA OTP rejected: ${stageInfo.errorMessage}`;
            const diagnostic = classifyPolimiFailure({
              component: '@polisdk/poliauth/application/login-orchestrator',
              operation: 'submitOtp',
              stage: 'otp',
              url: stageInfo.url,
              httpStatus: stageInfo.httpStatus,
              errorMessage: stageInfo.errorMessage,
              diagnosticSnapshot: stageInfo.diagnosticSnapshot,
              error: errMsg
            });
            const semanticErrorCode = diagnostic.semanticErrorCode ?? 'OTP_REJECTED';
            if (
              submittedAutoTotpCount === 1 &&
              !autoTotpNextWindowRetried &&
              semanticErrorCode === 'OTP_REJECTED'
            ) {
              autoTotpNextWindowRetried = true;
              retryAutoTotpPending = true;
              await waitForNextTotpWindowBoundary({
                pollIntervalMs: pollDelayMs,
                nextTotpWindowWaitMs,
                waitForNextTotpWindow,
                logger: this.logger
              });
            } else {
              const tripped = await this.tripCircuitBreaker(userId, semanticErrorCode, errMsg);
              await notify('failed', errMsg);
              return {
                ok: false,
                status: 'failed',
                url: stageInfo.url,
                error: errMsg,
                classification: diagnostic.classification,
                semanticErrorCode,
                reauthRequired: tripped,
                diagnostic
              };
            }
          }

          if (
            (submittedAutoTotpCount > 0 || submittedManualOtpCount > 0) &&
            !stageInfo.errorMessage &&
            postSubmitDebounceMs > 0 &&
            Date.now() < otpDebounceUntil
          ) {
            await sleep(pollDelayMs);
            continue;
          }

          if (submittedManualOtpCount >= effectiveMaxManualOtpAttempts) {
            const errMsg =
              stageInfo.errorMessage ||
              `PoliMi 2FA manual OTP exceeded maximum retry attempts (${effectiveMaxManualOtpAttempts}).`;
            const diagnostic = classifyPolimiFailure({
              component: '@polisdk/poliauth/application/login-orchestrator',
              operation: 'submitOtp',
              stage: 'otp',
              url: stageInfo.url,
              httpStatus: stageInfo.httpStatus,
              errorMessage: stageInfo.errorMessage,
              diagnosticSnapshot: stageInfo.diagnosticSnapshot,
              error: errMsg
            });
            const semanticErrorCode = diagnostic.semanticErrorCode ?? 'OTP_REJECTED';
            const tripped = await this.tripCircuitBreaker(userId, semanticErrorCode, errMsg);
            await notify('failed', errMsg);
            return {
              ok: false,
              status: 'failed',
              url: stageInfo.url,
              error: errMsg,
              classification: diagnostic.classification,
              semanticErrorCode,
              reauthRequired: tripped,
              diagnostic
            };
          }

          let otpToSubmit = '';
          if (explicitOtpToConsume) {
            otpToSubmit = explicitOtpToConsume;
            explicitOtpToConsume = '';
            submittedManualOtpCount += 1;
          } else {
            const allowAutoTotp = submittedAutoTotpCount === 0 || retryAutoTotpPending;
            retryAutoTotpPending = false;
            const otpChoice = await this.otpCoordinator.obtainOtpCodeForUser(
              userId,
              credentials.totpSecret,
              allowAutoTotp,
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
          const otpResult = (await driver.submitOtp({ otp: otpToSubmit })) as {
            ok: boolean;
            error?: string;
            diagnostic?: PoliAuthDiagnosticErrorPayload;
          };
          if (!otpResult.ok) {
            const diagnostic =
              otpResult.diagnostic ??
              classifyPolimiFailure({
                component: '@polisdk/poliauth/application/login-orchestrator',
                operation: 'submitOtp',
                stage: 'otp',
                url: stageInfo.url,
                error: otpResult.error || 'Failed to submit 2FA OTP.'
              });
            const errMsg = otpResult.error || diagnostic.message;
            const semanticErrorCode = diagnostic.semanticErrorCode;
            const shouldTripOtpFailure =
              isStage1TerminalSemanticError(semanticErrorCode) ||
              (semanticErrorCode === 'OTP_REJECTED' &&
                (submittedManualOtpCount > 0 || submittedAutoTotpCount >= 2));
            const tripped = shouldTripOtpFailure
              ? await this.tripCircuitBreaker(userId, semanticErrorCode, errMsg)
              : false;
            await notify('failed', errMsg);
            return {
              ok: false,
              status: 'failed',
              url: stageInfo.url,
              error: errMsg,
              classification: diagnostic.classification,
              ...(semanticErrorCode ? { semanticErrorCode } : {}),
              reauthRequired: tripped,
              diagnostic
            };
          }

          otpDebounceUntil = Date.now() + postSubmitDebounceMs;
          if (postSubmitDebounceMs > 0) {
            await driver.waitForNavigation(Math.min(postSubmitDebounceMs, 1_500)).catch(() => undefined);
          }
          if (pollDelayMs > 0) await sleep(Math.min(450, pollDelayMs));
          continue;
        }

        // 4.5 Deterministic Outage vs. Selector Drift short-circuit on unknown stage
        if (
          stageInfo.stage === 'unknown' &&
          stageInfo.diagnosticError &&
          (stageInfo.diagnosticError.classification === 'PORTAL_OUTAGE_OR_NETWORK_ERROR' ||
            stageInfo.diagnosticError.classification === 'DOM_SELECTOR_DRIFT')
        ) {
          const diag = stageInfo.diagnosticError;
          if (diag.classification === 'PORTAL_OUTAGE_OR_NETWORK_ERROR') {
            this.logger?.warn(`PoliMi outage detected: ${diag.message}`, diag);
          } else {
            this.logger?.error(`PoliMi DOM selector drift detected: ${diag.message}`, diag);
          }
          await notify('failed', diag.message);
          return {
            ok: false,
            status: 'failed',
            url: stageInfo.url,
            error: diag.message,
            classification: diag.classification,
            ...(diag.semanticErrorCode ? { semanticErrorCode: diag.semanticErrorCode } : {}),
            reauthRequired: false,
            diagnostic: diag
          };
        }

        credentialsDebounceUntil = 0;
        otpDebounceUntil = 0;

        // 5. Intermediate SSO handoff (`AunicaLogin.do?evn_checkCookieSSO=evento`) or loading
        await sleep(pollDelayMs);
      }

      const timeoutMsg =
        'Timed out navigating through PoliMi authentication pipeline.';
      await notify('failed', timeoutMsg);
      return { ok: false, status: 'failed', error: timeoutMsg };
    } catch (err) {
      const diagnostic = extractDiagnosticFromError(err, 'authenticate', entryUrl);
      const msg = diagnostic.message || redactSensitiveErrorText(err);
      const semanticErrorCode = diagnostic.semanticErrorCode;
      const tripped = isStage1TerminalSemanticError(semanticErrorCode)
        ? await this.tripCircuitBreaker(userId, semanticErrorCode, msg)
        : false;
      this.logger?.error(`PoliMi authentication failed: ${msg}`, diagnostic);
      await notify('failed', msg);
      return {
        ok: false,
        status: 'failed',
        error: msg,
        classification: diagnostic.classification,
        ...(semanticErrorCode ? { semanticErrorCode } : {}),
        reauthRequired: tripped,
        diagnostic
      };
    }
  }

  /**
   * Handles a single step of Federated SAML/Shibboleth SSO across an SP (Mode A identifier prompt,
   * Mode B click-through login trigger, or Mode C direct redirect) and the PoliMi IdP.
   */
  public async handleFederatedSamlStep(params: {
    userId: IdentityId;
    driver:
      | FederatedAuthPageDriverPort
      | (AuthPageDriverPort & Partial<FederatedSsoPageDriverPort>);
    credentials: Partial<LoginCredentials>;
    federatedIdentifier?: string;
    state: FederatedSamlFlowState;
    ssoTransitWindowMs?: number;
    maxManualOtpAttempts?: number;
    postSubmitDebounceMs?: number;
    pollIntervalMs?: number;
    nextTotpWindowWaitMs?: number;
    waitForNextTotpWindow?: (waitMs: number) => Promise<void>;
    callbacks?: LoginProgressCallbacks;
  }): Promise<
    | { action: 'continue_polling' }
    | { action: 'authenticated_or_ready' }
    | {
        action: 'login_required';
        reason: string;
        classification?: PoliAuthFailureClassification;
        semanticErrorCode?: PolimiSemanticErrorCode;
        reauthRequired?: boolean;
        diagnostic?: PoliAuthDiagnosticErrorPayload;
      }
    | {
        action: 'failed';
        reason: string;
        classification?: PoliAuthFailureClassification;
        semanticErrorCode?: PolimiSemanticErrorCode;
        reauthRequired?: boolean;
        diagnostic?: PoliAuthDiagnosticErrorPayload;
      }
  > {
    const {
      userId,
      driver,
      credentials,
      federatedIdentifier,
      state,
      ssoTransitWindowMs = 25_000,
      maxManualOtpAttempts = 3,
      postSubmitDebounceMs = 1_500,
      pollIntervalMs = 250,
      nextTotpWindowWaitMs,
      waitForNextTotpWindow,
      callbacks
    } = params;

    const effectiveMaxManualOtpAttempts = Math.max(1, maxManualOtpAttempts);

    let polimiStage = null;
    try {
      polimiStage = await driver.inspectPolimiStage();
    } catch (err) {
      if (isTransientNavigationError(err)) {
        this.logger?.debug(
          'Transient error inspecting PoliMi stage during SAML SSO; retrying.',
          redactSensitiveErrorText(err)
        );
        return { action: 'continue_polling' };
      }
      const diagnostic = extractDiagnosticFromError(err, 'handleFederatedSamlStep');
      const reason = diagnostic.message || redactSensitiveErrorText(err);
      this.logger?.error(`PoliMi stage inspection failed during SAML SSO: ${reason}`, diagnostic);
      return {
        action: 'failed',
        reason,
        classification: diagnostic.classification,
        ...(diagnostic.semanticErrorCode
          ? { semanticErrorCode: diagnostic.semanticErrorCode }
          : {}),
        diagnostic
      };
    }

    if (polimiStage) {
      const stageSemantic = resolveStageSemanticError(
        polimiStage,
        'handleFederatedSamlStep'
      );
      if (stageSemantic === 'ACCOUNT_LOCKED' || stageSemantic === 'PASSWORD_EXPIRED') {
        const reason =
          polimiStage.errorMessage ||
          polimiStage.diagnosticError?.message ||
          (stageSemantic === 'ACCOUNT_LOCKED'
            ? 'PoliMi account is locked or suspended.'
            : 'PoliMi password has expired and must be changed.');
        const diagnostic = classifyPolimiFailure({
          component: '@polisdk/poliauth/application/login-orchestrator',
          operation: 'handleFederatedSamlStep',
          stage: polimiStage.stage,
          url: polimiStage.url,
          httpStatus: polimiStage.httpStatus,
          errorMessage: polimiStage.errorMessage ?? reason,
          diagnosticSnapshot: polimiStage.diagnosticSnapshot,
          error: reason
        });
        await this.tripCircuitBreaker(userId, stageSemantic, reason);
        return {
          action: 'failed',
          reason,
          classification: diagnostic.classification,
          semanticErrorCode: stageSemantic,
          reauthRequired: true,
          diagnostic
        };
      }

      if (
        stageSemantic === 'IDP_MAINTENANCE' ||
        (polimiStage.stage === 'unknown' &&
          polimiStage.diagnosticError &&
          (polimiStage.diagnosticError.classification === 'PORTAL_OUTAGE_OR_NETWORK_ERROR' ||
            polimiStage.diagnosticError.classification === 'DOM_SELECTOR_DRIFT'))
      ) {
        const diag =
          polimiStage.diagnosticError ??
          classifyPolimiFailure({
            component: '@polisdk/poliauth/application/login-orchestrator',
            operation: 'handleFederatedSamlStep',
            stage: polimiStage.stage,
            url: polimiStage.url,
            httpStatus: polimiStage.httpStatus,
            errorMessage: polimiStage.errorMessage,
            diagnosticSnapshot: polimiStage.diagnosticSnapshot,
            error: polimiStage.errorMessage || 'PoliMi Identity Provider maintenance detected.'
          });
        return {
          action: 'failed',
          reason: diag.message,
          classification: diag.classification,
          semanticErrorCode: diag.semanticErrorCode ?? stageSemantic,
          reauthRequired: false,
          diagnostic: diag
        };
      }
    }

    // 1. PoliMi expired session / security violation recovery during SAML SSO
    if (polimiStage && polimiStage.stage === 'session_expired') {
      state.credentialsDebounceUntil = 0;
      state.otpDebounceUntil = 0;
      state.ssoTransitDeadline = Math.max(
        state.ssoTransitDeadline,
        Date.now() + ssoTransitWindowMs
      );
      await callbacks?.onStatusChange?.(
        'recovering_session',
        'Recovering expired PoliMi session...'
      );
      await driver.recoverSessionPage();
      return { action: 'continue_polling' };
    }

    // 2. Intermediate PoliMi SSO handoff (`AunicaLogin.do?evn_checkCookieSSO=evento`)
    if (polimiStage && polimiStage.stage === 'sso_handoff') {
      state.credentialsDebounceUntil = 0;
      state.otpDebounceUntil = 0;
      state.ssoTransitDeadline = Math.max(
        state.ssoTransitDeadline,
        Date.now() + ssoTransitWindowMs
      );
      return { action: 'continue_polling' };
    }

    // 3. PoliMi credentials form encountered during SAML SSO
    if (polimiStage && polimiStage.stage === 'credentials') {
      state.otpDebounceUntil = 0;
      state.ssoTransitDeadline = Math.max(
        state.ssoTransitDeadline,
        Date.now() + ssoTransitWindowMs
      );

      if (!state.seenSamlCredentialsStep) {
        state.seenSamlCredentialsStep = true;
        return { action: 'continue_polling' };
      }

      if (state.submittedSamlCredentialsCount > 0 && polimiStage.errorMessage) {
        const reason = `PoliMi login rejected: ${polimiStage.errorMessage}`;
        const diagnostic = classifyPolimiFailure({
          component: '@polisdk/poliauth/application/login-orchestrator',
          operation: 'submitCredentials',
          stage: 'credentials',
          url: polimiStage.url,
          httpStatus: polimiStage.httpStatus,
          errorMessage: polimiStage.errorMessage,
          diagnosticSnapshot: polimiStage.diagnosticSnapshot,
          error: reason
        });
        const semanticErrorCode = diagnostic.semanticErrorCode ?? 'INVALID_CREDENTIALS';
        const tripped = isStage1TerminalSemanticError(semanticErrorCode)
          ? await this.tripCircuitBreaker(userId, semanticErrorCode, reason)
          : false;
        return {
          action: 'login_required',
          reason,
          classification: diagnostic.classification,
          semanticErrorCode,
          reauthRequired: tripped,
          diagnostic
        };
      }

      if (
        state.submittedSamlCredentialsCount > 0 &&
        postSubmitDebounceMs > 0 &&
        Date.now() < (state.credentialsDebounceUntil ?? 0)
      ) {
        return { action: 'continue_polling' };
      }

      if (state.submittedSamlCredentialsCount >= 2) {
        return {
          action: 'login_required',
          reason:
            polimiStage.errorMessage ||
            'PoliMi login remained on credentials page after submission.'
        };
      }

      const personCode = credentials.personCode?.trim() || '';
      const password = credentials.password || '';
      if (!personCode || !password) {
        return {
          action: 'login_required',
          reason:
            'Person Code and Password are required to sign in on aunicalogin.polimi.it.'
        };
      }

      state.submittedSamlCredentialsCount += 1;
      await callbacks?.onStatusChange?.(
        'submitting_credentials',
        'Submitting PoliMi credentials...'
      );
      const credRes = (await driver.submitCredentials({
        personCode,
        password,
        stayConnected: true
      })) as { ok: boolean; error?: string; diagnostic?: PoliAuthDiagnosticErrorPayload };
      if (!credRes.ok) {
        const reason =
          credRes.error || 'Failed to submit PoliMi credentials during SAML SSO.';
        const diagnostic =
          credRes.diagnostic ??
          classifyPolimiFailure({
            component: '@polisdk/poliauth/application/login-orchestrator',
            operation: 'submitCredentials',
            stage: 'credentials',
            url: polimiStage.url,
            error: reason
          });
        const semanticErrorCode = diagnostic.semanticErrorCode;
        const tripped = isStage1TerminalSemanticError(semanticErrorCode)
          ? await this.tripCircuitBreaker(userId, semanticErrorCode, reason)
          : false;
        return {
          action: 'login_required',
          reason,
          classification: diagnostic.classification,
          ...(semanticErrorCode ? { semanticErrorCode } : {}),
          reauthRequired: tripped,
          diagnostic
        };
      }
      state.credentialsDebounceUntil = Date.now() + postSubmitDebounceMs;
      return { action: 'continue_polling' };
    }

    // 4. PoliMi 2FA OTP prompt encountered during SAML SSO
    if (polimiStage && polimiStage.stage === 'otp') {
      state.credentialsDebounceUntil = 0;
      state.ssoTransitDeadline = Math.max(
        state.ssoTransitDeadline,
        Date.now() + ssoTransitWindowMs
      );

      if (state.submittedSamlManualOtpCount > 0 && polimiStage.errorMessage) {
        const reason = `PoliMi 2FA OTP rejected: ${polimiStage.errorMessage}`;
        const diagnostic = classifyPolimiFailure({
          component: '@polisdk/poliauth/application/login-orchestrator',
          operation: 'submitOtp',
          stage: 'otp',
          url: polimiStage.url,
          httpStatus: polimiStage.httpStatus,
          errorMessage: polimiStage.errorMessage,
          diagnosticSnapshot: polimiStage.diagnosticSnapshot,
          error: reason
        });
        const semanticErrorCode = diagnostic.semanticErrorCode ?? 'OTP_REJECTED';
        const tripped = await this.tripCircuitBreaker(userId, semanticErrorCode, reason);
        return {
          action: 'login_required',
          reason,
          classification: diagnostic.classification,
          semanticErrorCode,
          reauthRequired: tripped,
          diagnostic
        };
      }

      let retrySamlAutoTotp = false;
      if (state.submittedSamlAutoTotpCount > 0 && polimiStage.errorMessage) {
        const reason = `PoliMi 2FA OTP rejected: ${polimiStage.errorMessage}`;
        const diagnostic = classifyPolimiFailure({
          component: '@polisdk/poliauth/application/login-orchestrator',
          operation: 'submitOtp',
          stage: 'otp',
          url: polimiStage.url,
          httpStatus: polimiStage.httpStatus,
          errorMessage: polimiStage.errorMessage,
          diagnosticSnapshot: polimiStage.diagnosticSnapshot,
          error: reason
        });
        const semanticErrorCode = diagnostic.semanticErrorCode ?? 'OTP_REJECTED';
        if (
          state.submittedSamlAutoTotpCount === 1 &&
          !state.retriedSamlAutoTotpNextWindow &&
          semanticErrorCode === 'OTP_REJECTED'
        ) {
          state.retriedSamlAutoTotpNextWindow = true;
          retrySamlAutoTotp = true;
          await waitForNextTotpWindowBoundary({
            pollIntervalMs,
            nextTotpWindowWaitMs,
            waitForNextTotpWindow,
            logger: this.logger
          });
        } else {
          const tripped = await this.tripCircuitBreaker(userId, semanticErrorCode, reason);
          return {
            action: 'login_required',
            reason,
            classification: diagnostic.classification,
            semanticErrorCode,
            reauthRequired: tripped,
            diagnostic
          };
        }
      }

      if (
        (state.submittedSamlAutoTotpCount > 0 || state.submittedSamlManualOtpCount > 0) &&
        !polimiStage.errorMessage &&
        postSubmitDebounceMs > 0 &&
        Date.now() < (state.otpDebounceUntil ?? 0)
      ) {
        return { action: 'continue_polling' };
      }

      if (state.submittedSamlManualOtpCount >= effectiveMaxManualOtpAttempts) {
        const reason =
          polimiStage.errorMessage ||
          `PoliMi 2FA manual OTP exceeded maximum retry attempts (${effectiveMaxManualOtpAttempts}).`;
        const diagnostic = classifyPolimiFailure({
          component: '@polisdk/poliauth/application/login-orchestrator',
          operation: 'submitOtp',
          stage: 'otp',
          url: polimiStage.url,
          httpStatus: polimiStage.httpStatus,
          errorMessage: polimiStage.errorMessage,
          diagnosticSnapshot: polimiStage.diagnosticSnapshot,
          error: reason
        });
        const semanticErrorCode = diagnostic.semanticErrorCode ?? 'OTP_REJECTED';
        const tripped = await this.tripCircuitBreaker(userId, semanticErrorCode, reason);
        return {
          action: 'login_required',
          reason,
          classification: diagnostic.classification,
          semanticErrorCode,
          reauthRequired: tripped,
          diagnostic
        };
      }

      let otpToSubmit = '';
      const pendingExplicitOtp = state.explicitOtpToConsume?.trim() || '';
      if (pendingExplicitOtp) {
        otpToSubmit = pendingExplicitOtp;
        state.explicitOtpToConsume = '';
        state.submittedSamlManualOtpCount += 1;
      } else {
        const allowAutoTotp =
          state.submittedSamlAutoTotpCount === 0 || retrySamlAutoTotp;
        const otpChoice = await this.otpCoordinator.obtainOtpCodeForUser(
          userId,
          credentials.totpSecret,
          allowAutoTotp,
          callbacks
        );
        otpToSubmit = otpChoice.otp;
        if (otpChoice.usedAutoTotp) {
          state.submittedSamlAutoTotpCount += 1;
        } else {
          state.submittedSamlManualOtpCount += 1;
        }
      }

      await callbacks?.onStatusChange?.('submitting_otp', 'Submitting 6-digit 2FA code...');
      const otpRes = (await driver.submitOtp({ otp: otpToSubmit })) as {
        ok: boolean;
        error?: string;
        diagnostic?: PoliAuthDiagnosticErrorPayload;
      };
      if (!otpRes.ok) {
        const reason = otpRes.error || 'Failed to submit 2FA OTP during SAML SSO.';
        const diagnostic =
          otpRes.diagnostic ??
          classifyPolimiFailure({
            component: '@polisdk/poliauth/application/login-orchestrator',
            operation: 'submitOtp',
            stage: 'otp',
            url: polimiStage.url,
            error: reason
          });
        const semanticErrorCode = diagnostic.semanticErrorCode;
        const shouldTripOtpFailure =
          isStage1TerminalSemanticError(semanticErrorCode) ||
          (semanticErrorCode === 'OTP_REJECTED' &&
            (state.submittedSamlManualOtpCount > 0 || state.submittedSamlAutoTotpCount >= 2));
        const tripped = shouldTripOtpFailure
          ? await this.tripCircuitBreaker(userId, semanticErrorCode, reason)
          : false;
        return {
          action: 'login_required',
          reason,
          classification: diagnostic.classification,
          ...(semanticErrorCode ? { semanticErrorCode } : {}),
          reauthRequired: tripped,
          diagnostic
        };
      }
      state.otpDebounceUntil = Date.now() + postSubmitDebounceMs;
      return { action: 'continue_polling' };
    }

    state.credentialsDebounceUntil = 0;
    state.otpDebounceUntil = 0;

    // 5. Check Federated SP SSO state
    const fedDriver = driver as Partial<FederatedSsoPageDriverPort>;
    if (!fedDriver.inspectFederatedSsoPage) {
      return {
        action: 'failed',
        reason: 'Driver does not support federated SSO page inspection.'
      };
    }

    let ssoInspection = null;
    try {
      ssoInspection = await fedDriver.inspectFederatedSsoPage();
    } catch (err) {
      if (isTransientNavigationError(err)) {
        this.logger?.debug(
          'Transient error inspecting federated SSO page; retrying.',
          redactSensitiveErrorText(err)
        );
        return { action: 'continue_polling' };
      }
      const reason = redactSensitiveErrorText(err);
      this.logger?.error(`Federated SSO inspection failed: ${reason}`);
      return { action: 'failed', reason };
    }

    if (!ssoInspection) {
      return { action: 'continue_polling' };
    }

    if (ssoInspection.status === 'authenticated') {
      return { action: 'authenticated_or_ready' };
    }

    if (ssoInspection.status === 'error') {
      return {
        action: 'login_required',
        reason: ssoInspection.reason || 'Federated SSO reported an error.'
      };
    }

    // Mode A: SP presents an identifier-discovery (email / username) prompt
    if (ssoInspection.isIdentifierPrompt) {
      if (!state.submittedIdentifier) {
        const identifier = (federatedIdentifier ?? credentials.polimiEmail ?? '').trim();
        if (!identifier) {
          return {
            action: 'login_required',
            reason: `Federated SAML SSO (${ssoInspection.providerId}) requires a federatedIdentifier (or credentials.polimiEmail), but none was provided.`
          };
        }

        if (!fedDriver.submitFederatedIdentifier) {
          return {
            action: 'failed',
            reason: 'Driver does not support federated SSO identifier submission.'
          };
        }

        state.submittedIdentifier = true;
        state.ssoTransitDeadline = Date.now() + ssoTransitWindowMs;
        const submitRes = await fedDriver.submitFederatedIdentifier(identifier);
        if (!submitRes.ok) {
          return {
            action: 'login_required',
            reason: submitRes.error || 'Failed to submit federated SSO identifier.'
          };
        }
        return { action: 'continue_polling' };
      }

      if (Date.now() < state.ssoTransitDeadline) {
        return { action: 'continue_polling' };
      }

      return {
        action: 'login_required',
        reason:
          ssoInspection.reason ||
          'Timed out waiting for federated SP navigation after submitting identifier.'
      };
    }

    // Mode B: SP presents a click-through SSO login trigger (no email prompt required)
    if (ssoInspection.isLoginTrigger) {
      if (!state.triggeredLogin) {
        if (!fedDriver.triggerFederatedLogin) {
          return {
            action: 'failed',
            reason: 'Driver does not support federated SSO login trigger.'
          };
        }

        state.triggeredLogin = true;
        state.ssoTransitDeadline = Date.now() + ssoTransitWindowMs;
        const triggerRes = await fedDriver.triggerFederatedLogin();
        if (!triggerRes.ok) {
          return {
            action: 'login_required',
            reason: triggerRes.error || 'Failed to trigger federated SSO login.'
          };
        }
        return { action: 'continue_polling' };
      }

      if (Date.now() < state.ssoTransitDeadline) {
        return { action: 'continue_polling' };
      }

      return {
        action: 'login_required',
        reason:
          ssoInspection.reason ||
          'Timed out waiting for federated SP navigation after triggering SSO login.'
      };
    }

    // Mode C / SAML transit polling window (includes initial interstitial/blank pages)
    if (ssoInspection.status === 'sso_in_transit') {
      if (state.ssoTransitDeadline === 0) {
        state.ssoTransitDeadline = Date.now() + ssoTransitWindowMs;
      }
      if (Date.now() < state.ssoTransitDeadline) {
        return { action: 'continue_polling' };
      }
    }

    return {
      action: 'login_required',
      reason: ssoInspection.reason || 'Federated SSO authentication required.'
    };
  }

  /**
   * Loops `handleFederatedSamlStep` across multi-hop SAML/Shibboleth redirects until authenticated or failed.
   *
   * Concurrent invocations for the same user identity and federated target join a single
   * in-flight Promise unless `enableSingleflight` is explicitly disabled.
   */
  public authenticateFederatedSaml(
    req: FederatedSamlAuthRequest,
    options?: PoliAuthExecutionOptions
  ): Promise<FederatedSamlAuthOutcome> {
    const useSingleflight = options?.enableSingleflight ?? this.enableSingleflight;
    const providerId = (
      req.driver as Partial<FederatedSsoPageDriverPort> | undefined
    )?.federatedProviderId;
    const key = resolveFederatedSingleflightKey(
      req.userId,
      req.credentials?.personCode,
      req.entryUrl,
      providerId
    );

    return executeWithSingleflight({
      registry: this.inFlightFederatedAuth,
      key,
      enabled: useSingleflight,
      onJoin: () => {
        const normalizedUser =
          req.userId !== undefined && req.userId !== null
            ? normalizeIdentityId(req.userId)
            : '';
        const target = req.entryUrl?.trim() || providerId?.trim() || 'default';
        this.logger?.info('Joining existing in-flight federated SAML authentication flow.', {
          scope: 'orchestrator',
          flow: 'federated_saml',
          ...(normalizedUser ? { userId: normalizedUser } : { keyType: 'personCode' }),
          target: redactSecrets(target)
        });
      },
      execute: () => this.executeAuthenticateFederatedSaml(req)
    });
  }

  private async executeAuthenticateFederatedSaml(
    req: FederatedSamlAuthRequest
  ): Promise<FederatedSamlAuthOutcome> {
    const {
      userId,
      driver,
      credentials,
      federatedIdentifier,
      entryUrl,
      pollIntervalMs = 250,
      maxPollSteps = 180,
      ssoTransitWindowMs = 25_000,
      maxManualOtpAttempts = 3,
      postSubmitDebounceMs = pollIntervalMs > 0 ? Math.max(1_500, pollIntervalMs * 4) : 0,
      nextTotpWindowWaitMs,
      waitForNextTotpWindow,
      callbacks,
      onAuthenticated
    } = req;

    try {
      const breakerReason = await this.checkPreBrowserCircuitBreaker(userId);
      if (breakerReason) {
        await callbacks?.onStatusChange?.('reauth_required', breakerReason);
        return {
          ok: false,
          status: 'reauth_required',
          error: breakerReason,
          classification: 'AUTHENTICATION_REJECTED',
          reauthRequired: true
        };
      }

      if (entryUrl) {
        const fedDriver = driver as Partial<FederatedSsoPageDriverPort>;
        if (fedDriver.inspectFederatedSsoPage) {
          const initialSso = await fedDriver.inspectFederatedSsoPage().catch((err) => {
            if (isTransientNavigationError(err)) {
              this.logger?.debug(
                'Transient error on initial federated SSO check; navigating to entry URL.',
                redactSensitiveErrorText(err)
              );
              return null;
            }
            throw err;
          });
          if (initialSso?.status === 'authenticated') {
            await onAuthenticated?.();
            await callbacks?.onStatusChange?.(
              'authenticated',
              'Authenticated on federated SP session.'
            );
            return { ok: true, status: 'authenticated' };
          }
        }

        await callbacks?.onStatusChange?.('opening_login', 'Opening federated SSO login...');
        await driver.goto(entryUrl);
      }

      const state: FederatedSamlFlowState = {
        submittedIdentifier: false,
        triggeredLogin: false,
        ssoTransitDeadline: 0,
        seenSamlCredentialsStep: false,
        submittedSamlCredentialsCount: 0,
        submittedSamlAutoTotpCount: 0,
        submittedSamlManualOtpCount: 0,
        explicitOtpToConsume: credentials.otp?.trim() || ''
      };

      for (let step = 0; step < maxPollSteps; step++) {
        const res = await this.handleFederatedSamlStep({
          userId,
          driver,
          credentials,
          federatedIdentifier,
          state,
          ssoTransitWindowMs,
          maxManualOtpAttempts,
          postSubmitDebounceMs,
          pollIntervalMs,
          nextTotpWindowWaitMs,
          waitForNextTotpWindow,
          callbacks
        });

        if (res.action === 'authenticated_or_ready') {
          await onAuthenticated?.();
          await callbacks?.onStatusChange?.(
            'authenticated',
            'Authenticated on federated SP session.'
          );
          return { ok: true, status: 'authenticated' };
        }

        if (res.action === 'failed') {
          await callbacks?.onStatusChange?.('failed', res.reason);
          return {
            ok: false,
            status: 'failed',
            error: res.reason,
            ...(res.classification ? { classification: res.classification } : {}),
            ...(res.semanticErrorCode ? { semanticErrorCode: res.semanticErrorCode } : {}),
            ...(res.reauthRequired !== undefined ? { reauthRequired: res.reauthRequired } : {}),
            ...(res.diagnostic ? { diagnostic: res.diagnostic } : {})
          };
        }

        if (res.action === 'login_required') {
          return {
            ok: false,
            status: 'waiting_for_login',
            error: res.reason,
            ...(res.classification ? { classification: res.classification } : {}),
            ...(res.semanticErrorCode ? { semanticErrorCode: res.semanticErrorCode } : {}),
            ...(res.reauthRequired !== undefined ? { reauthRequired: res.reauthRequired } : {}),
            ...(res.diagnostic ? { diagnostic: res.diagnostic } : {})
          };
        }

        if (pollIntervalMs > 0) {
          await sleep(pollIntervalMs);
        }
      }

      const timeoutMsg = 'Timed out waiting for federated SAML SSO completion.';
      await callbacks?.onStatusChange?.('failed', timeoutMsg);
      return {
        ok: false,
        status: 'failed',
        error: timeoutMsg
      };
    } catch (err) {
      const diagnostic = extractDiagnosticFromError(err, 'authenticateFederatedSaml', entryUrl);
      const msg = diagnostic.message || redactSensitiveErrorText(err);
      const semanticErrorCode = diagnostic.semanticErrorCode;
      const tripped = isStage1TerminalSemanticError(semanticErrorCode)
        ? await this.tripCircuitBreaker(userId, semanticErrorCode, msg)
        : false;
      this.logger?.error(`Federated SAML authentication failed: ${msg}`, diagnostic);
      await callbacks?.onStatusChange?.('failed', msg);
      return {
        ok: false,
        status: 'failed',
        error: msg,
        classification: diagnostic.classification,
        ...(semanticErrorCode ? { semanticErrorCode } : {}),
        reauthRequired: tripped,
        diagnostic
      };
    }
  }
}
