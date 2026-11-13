/**
 * @module @polisdk/poliauth/domain/entities
 * Core Domain Entities, Value Objects, Diagnostic Error Models, and Authentication State Models.
 */

import { POLIMI_LOGIN_FLOW_SPEC } from './login-flow-spec.js';
import {
  redactSecrets,
  redactSensitiveErrorText,
  type RedactionRule
} from './redaction.js';

/**
 * Unique identifier for a user or tenant across any host platform
 * (e.g., UUID string, numeric ID, or profile key).
 */
export type IdentityId = string | number;

/**
 * Normalizes an `IdentityId` into a trimmed canonical string key.
 */
export function normalizeIdentityId(userId: IdentityId): string {
  return String(userId).trim();
}

/**
 * User credentials required for Politecnico di Milano SSO, 2FA, and federated SAML SSO.
 */
export interface LoginCredentials {
  personCode: string;
  password: string;
  otp: string;
  totpSecret?: string;
  polimiEmail: string;
}

/**
 * Persisted credentials stored inside the AES-256-GCM encrypted vault.
 */
export interface SavedVaultCredentials {
  personCode: string;
  password: string;
  totpSecret: string;
  polimiEmail: string;
  updatedAt: number;
}

/**
 * Stage of the Politecnico di Milano authentication pipeline.
 * Authentication concludes as soon as the session reaches `'authenticated'`.
 */
export type PolimiPageStage =
  | 'authenticated'
  | 'otp'
  | 'credentials'
  | 'sso_handoff'
  | 'session_expired'
  | 'unknown';

/**
 * Canonical authentication stage covering IdP DOM states plus `'entry'` and `'error'` diagnostics.
 */
export type PoliAuthStage = PolimiPageStage | 'entry' | 'error';

/**
 * Deterministic failure taxonomy separating portal/network outages from HTML selector drift.
 */
export type PoliAuthFailureClassification =
  | 'PORTAL_OUTAGE_OR_NETWORK_ERROR'
  | 'DOM_SELECTOR_DRIFT'
  | 'AUTHENTICATION_REJECTED'
  | 'OTP_CHALLENGE_FAILED'
  | 'TARGET_CLOSED'
  | 'UNKNOWN_FAILURE';

/**
 * Sanitized structural DOM snapshot captured at failure/unknown stage boundaries.
 */
export interface PoliAuthDomDiagnosticSnapshot {
  url: string;
  pathname: string;
  httpStatus?: number;
  hasEmptyBody: boolean;
  hasLoginInput: boolean;
  hasPasswordInput: boolean;
  hasOtpInput: boolean;
  hasSsoHandoffForm: boolean;
  hasExpiredSessionMarker: boolean;
  hasAuthenticatedMarker: boolean;
  hasErrorBanner: boolean;
  hasMaintenanceBanner: boolean;
  errorMessage?: string;
}

/**
 * Closed taxonomy of semantic Politecnico di Milano Identity Provider failure codes.
 */
export type PolimiSemanticErrorCode =
  | 'INVALID_CREDENTIALS'
  | 'PASSWORD_EXPIRED'
  | 'ACCOUNT_LOCKED'
  | 'OTP_REJECTED'
  | 'IDP_MAINTENANCE'
  | 'DOM_SELECTOR_DRIFT';

/**
 * Structured diagnostic error payload attached to `PoliAuthDiagnosticError` and outcomes.
 */
export interface PoliAuthDiagnosticErrorPayload {
  component: string;
  operation: string;
  stage: PoliAuthStage;
  classification: PoliAuthFailureClassification;
  semanticErrorCode?: PolimiSemanticErrorCode;
  selectorOrEndpoint: string;
  message: string;
  diagnosticSnapshot?: PoliAuthDomDiagnosticSnapshot;
  causeMessage?: string;
}

export interface PolimiFailureClassificationInput {
  component?: string;
  operation: string;
  stage?: PoliAuthStage;
  url?: string;
  title?: string;
  pathname?: string;
  httpStatus?: number;
  selectorOrEndpoint?: string;
  error?: unknown;
  errorMessage?: string;
  diagnosticSnapshot?: PoliAuthDomDiagnosticSnapshot;
  extraSecrets?: string[];
  customRules?: RedactionRule[];
}

function extractHostnameSafe(rawUrl: string | undefined): string {
  if (!rawUrl) return '';
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    const match = /^[a-z]+:\/\/([^/?#:]+)/i.exec(rawUrl);
    return (match?.[1] ?? '').toLowerCase();
  }
}

export function isExpectedPolimiIdpHostname(hostname: string): boolean {
  const normalized = (hostname || '').trim().toLowerCase();
  if (!normalized) return false;
  if (normalized === POLIMI_LOGIN_FLOW_SPEC.entry.idpHostname.toLowerCase()) {
    return true;
  }
  return POLIMI_LOGIN_FLOW_SPEC.samlIdentityProvider.transitHostnames.some(
    (expected) => expected.toLowerCase() === normalized
  );
}

/**
 * Scrubs all fields of a `PoliAuthDiagnosticErrorPayload` through `redactSecrets`.
 */
export function sanitizeDiagnosticErrorPayload(
  payload: PoliAuthDiagnosticErrorPayload,
  extraSecrets: string[] = [],
  customRules: RedactionRule[] = []
): PoliAuthDiagnosticErrorPayload {
  const sanitizedSnapshot = payload.diagnosticSnapshot
    ? redactSecrets(payload.diagnosticSnapshot, extraSecrets, customRules)
    : undefined;
  return {
    component: redactSecrets(payload.component, extraSecrets, customRules),
    operation: redactSecrets(payload.operation, extraSecrets, customRules),
    stage: payload.stage,
    classification: payload.classification,
    ...(payload.semanticErrorCode !== undefined
      ? { semanticErrorCode: payload.semanticErrorCode }
      : {}),
    selectorOrEndpoint: redactSecrets(payload.selectorOrEndpoint, extraSecrets, customRules),
    message: redactSecrets(payload.message, extraSecrets, customRules),
    ...(sanitizedSnapshot ? { diagnosticSnapshot: sanitizedSnapshot } : {}),
    ...(payload.causeMessage !== undefined
      ? { causeMessage: redactSecrets(payload.causeMessage, extraSecrets, customRules) }
      : {})
  };
}

/**
 * Deterministically disambiguates portal/network outages from PoliMi IdP DOM selector drift,
 * credential/OTP rejections, and closed browser targets.
 */
export function classifyPolimiFailure(
  input: PolimiFailureClassificationInput
): PoliAuthDiagnosticErrorPayload {
  const extraSecrets = input.extraSecrets ?? [];
  const customRules = input.customRules ?? [];
  const component = input.component ?? '@polisdk/poliauth/domain/entities';
  const stage: PoliAuthStage = input.stage ?? 'unknown';
  const snapshot = input.diagnosticSnapshot
    ? redactSecrets(input.diagnosticSnapshot, extraSecrets, customRules)
    : undefined;

  const rawCause =
    input.error !== undefined
      ? redactSensitiveErrorText(input.error, extraSecrets, customRules)
      : undefined;
  const effectiveUrl = redactSecrets(
    snapshot?.url || input.url || '',
    extraSecrets,
    customRules
  );
  const selectorOrEndpoint = redactSecrets(
    input.selectorOrEndpoint || effectiveUrl || POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl,
    extraSecrets,
    customRules
  );
  const effectiveHttpStatus = input.httpStatus ?? snapshot?.httpStatus;
  const lowerCause = (rawCause ?? '').toLowerCase();
  const lowerUrl = effectiveUrl.toLowerCase();

  let classification: PoliAuthFailureClassification = 'UNKNOWN_FAILURE';
  let message = rawCause || `PoliMi authentication failed during ${input.operation}.`;

  // 1. Browser / Page Target Closed
  if (
    /target closed|page has been closed|browser has been closed|context has been closed|has been closed|tab was closed|no tab with id/i.test(
      lowerCause
    )
  ) {
    classification = 'TARGET_CLOSED';
    message = rawCause || 'Target browser page or context was closed.';
  } else {
    // 2. Network / Infrastructure Outage / Maintenance
    const hasNetworkSignature =
      POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators.networkErrorPatterns.some((pattern) =>
        lowerCause.includes(pattern.toLowerCase())
      ) ||
      /timeout\s+\d+ms\s+exceeded|navigation timeout|timed out waiting for/i.test(lowerCause) ||
      lowerUrl.startsWith('chrome-error://') ||
      lowerUrl.startsWith('about:neterror');

    const hasOutageStatus =
      effectiveHttpStatus !== undefined &&
      ((
        POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators.httpStatusCodes as readonly number[]
      ).includes(effectiveHttpStatus) ||
        effectiveHttpStatus >= 500);

    const hasMaintenanceText =
      Boolean(snapshot?.hasMaintenanceBanner) ||
      POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators.textPatterns.some(
        (pattern) =>
          lowerCause.includes(pattern.toLowerCase()) ||
          (snapshot?.errorMessage ?? '').toLowerCase().includes(pattern.toLowerCase())
      );

    const hasEmptyBody = snapshot?.hasEmptyBody === true;

    if (hasNetworkSignature || hasOutageStatus || hasMaintenanceText || hasEmptyBody) {
      classification = 'PORTAL_OUTAGE_OR_NETWORK_ERROR';
      if (hasOutageStatus) {
        message = `PoliMi portal outage detected (HTTP ${String(effectiveHttpStatus)}) during ${input.operation}${rawCause ? `: ${rawCause}` : '.'}`;
      } else if (hasMaintenanceText) {
        message = `PoliMi portal maintenance banner detected during ${input.operation}${snapshot?.errorMessage ? `: ${snapshot.errorMessage}` : '.'}`;
      } else if (hasEmptyBody) {
        message = `PoliMi portal returned an empty response body during ${input.operation}.`;
      } else {
        message = `PoliMi network or transport error during ${input.operation}${rawCause ? `: ${rawCause}` : '.'}`;
      }
    } else {
      const semanticFromContext = classifyPolimiSemanticError({
        ...input,
        stage,
        diagnosticSnapshot: snapshot
      });

      if (semanticFromContext === 'IDP_MAINTENANCE') {
        classification = 'PORTAL_OUTAGE_OR_NETWORK_ERROR';
        message =
          snapshot?.errorMessage ||
          input.errorMessage ||
          rawCause ||
          'PoliMi Identity Provider maintenance or outage detected.';
      } else if (semanticFromContext === 'ACCOUNT_LOCKED') {
        classification = 'AUTHENTICATION_REJECTED';
        message =
          snapshot?.errorMessage ||
          input.errorMessage ||
          rawCause ||
          'PoliMi account is locked or suspended.';
      } else if (semanticFromContext === 'PASSWORD_EXPIRED') {
        classification = 'AUTHENTICATION_REJECTED';
        message =
          snapshot?.errorMessage ||
          input.errorMessage ||
          rawCause ||
          'PoliMi password has expired and must be changed.';
      } else if (semanticFromContext === 'OTP_REJECTED') {
        classification = 'OTP_CHALLENGE_FAILED';
        message =
          snapshot?.errorMessage ||
          input.errorMessage ||
          rawCause ||
          'PoliMi 2FA OTP challenge was rejected.';
      } else if (semanticFromContext === 'INVALID_CREDENTIALS') {
        classification = 'AUTHENTICATION_REJECTED';
        message =
          snapshot?.errorMessage ||
          input.errorMessage ||
          rawCause ||
          'PoliMi credentials were rejected by Identity Provider.';
      } else if (semanticFromContext === 'DOM_SELECTOR_DRIFT') {
        const hostname = extractHostnameSafe(snapshot?.url || input.url);
        classification = 'DOM_SELECTOR_DRIFT';
        message = `PoliMi DOM selector drift detected on ${hostname} during ${input.operation} (expected ${selectorOrEndpoint} on populated HTTP ${String(effectiveHttpStatus ?? 200)} page).`;
      } else if (stage === 'otp' && input.operation === 'submitOtp') {
        classification = 'OTP_CHALLENGE_FAILED';
        message = rawCause || 'Failed to submit 2FA OTP.';
      } else if (stage === 'credentials' && input.operation === 'submitCredentials') {
        classification = 'AUTHENTICATION_REJECTED';
        message = rawCause || 'Failed to submit PoliMi credentials.';
      }
    }
  }

  let semanticErrorCode: PolimiSemanticErrorCode | undefined;
  if (classification === 'PORTAL_OUTAGE_OR_NETWORK_ERROR') {
    semanticErrorCode = 'IDP_MAINTENANCE';
  } else if (classification === 'DOM_SELECTOR_DRIFT') {
    semanticErrorCode = 'DOM_SELECTOR_DRIFT';
  } else if (classification !== 'TARGET_CLOSED') {
    semanticErrorCode = classifyPolimiSemanticError({
      ...input,
      stage,
      diagnosticSnapshot: snapshot
    });
  }

  return sanitizeDiagnosticErrorPayload(
    {
      component,
      operation: input.operation,
      stage,
      classification,
      ...(semanticErrorCode ? { semanticErrorCode } : {}),
      selectorOrEndpoint,
      message,
      ...(snapshot ? { diagnosticSnapshot: snapshot } : {}),
      ...(rawCause ? { causeMessage: rawCause } : {})
    },
    extraSecrets,
    customRules
  );
}

/**
 * Classifies an IdP failure or diagnostic snapshot into a closed semantic error code.
 */
export function classifyPolimiSemanticError(
  input: Omit<PolimiFailureClassificationInput, 'operation'> & {
    operation?: string;
    stage?: PoliAuthStage;
  }
): PolimiSemanticErrorCode | undefined {
  const snapshot = input.diagnosticSnapshot;
  const stage: PoliAuthStage = input.stage ?? 'unknown';
  const operation = input.operation ?? '';
  const rawCause =
    input.error instanceof Error
      ? input.error.message
      : typeof input.error === 'string'
        ? input.error
        : input.error !== undefined && input.error !== null
          ? String(input.error)
          : '';
  const lowerCause = rawCause.toLowerCase();
  const effectiveHttpStatus = input.httpStatus ?? snapshot?.httpStatus;

  if (
    /target closed|target page, context or browser has been closed|browser has been closed|session closed|target_closed/i.test(
      lowerCause
    ) &&
    (effectiveHttpStatus === undefined || effectiveHttpStatus < 500)
  ) {
    return undefined;
  }

  const bannerErrorText = (snapshot?.errorMessage ?? input.errorMessage ?? '').trim();
  const combinedErrorText = `${bannerErrorText} ${rawCause}`.toLowerCase();
  const combinedAllText = `${bannerErrorText} ${input.title ?? ''} ${rawCause}`.toLowerCase();

  // 1. Portal Maintenance / Outage / Empty Body / Network Error
  const isMaintenanceHttp =
    effectiveHttpStatus !== undefined &&
    (POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators.httpStatusCodes as readonly number[]).includes(
      effectiveHttpStatus
    );
  const isMaintenanceNet = POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators.networkErrorPatterns.some(
    (pattern) => lowerCause.includes(pattern.toLowerCase())
  );
  const isMaintenanceText = POLIMI_LOGIN_FLOW_SPEC.maintenanceIndicators.textPatterns.some(
    (pattern) => combinedAllText.includes(pattern.toLowerCase())
  );
  if (
    isMaintenanceHttp ||
    isMaintenanceNet ||
    snapshot?.hasMaintenanceBanner === true ||
    snapshot?.hasEmptyBody === true ||
    isMaintenanceText
  ) {
    return 'IDP_MAINTENANCE';
  }

  // 2. Account Locked (detected at any stage)
  if (
    POLIMI_LOGIN_FLOW_SPEC.semanticErrorIndicators.accountLockedPatterns.some((pattern) =>
      combinedAllText.includes(pattern.toLowerCase())
    )
  ) {
    return 'ACCOUNT_LOCKED';
  }

  // 3. Password Expired
  if (
    POLIMI_LOGIN_FLOW_SPEC.semanticErrorIndicators.passwordExpiredPatterns.some((pattern) =>
      combinedAllText.includes(pattern.toLowerCase())
    )
  ) {
    return 'PASSWORD_EXPIRED';
  }

  const hasBannerError = snapshot?.hasErrorBanner === true || bannerErrorText.length > 0;

  // 4. OTP Rejected (Stage 2 or explicit OTP rejection pattern)
  if (
    POLIMI_LOGIN_FLOW_SPEC.semanticErrorIndicators.otpRejectedPatterns.some((pattern) =>
      combinedErrorText.includes(pattern.toLowerCase())
    ) ||
    /otp rejected|2fa otp rejected|2fa manual otp exceeded/i.test(lowerCause) ||
    (stage === 'otp' && hasBannerError)
  ) {
    return 'OTP_REJECTED';
  }

  // 5. Invalid Credentials (Stage 1 or explicit invalid-credentials pattern)
  if (
    POLIMI_LOGIN_FLOW_SPEC.semanticErrorIndicators.invalidCredentialsPatterns.some((pattern) =>
      combinedErrorText.includes(pattern.toLowerCase())
    ) ||
    /login rejected/i.test(lowerCause) ||
    (stage === 'credentials' && hasBannerError)
  ) {
    return 'INVALID_CREDENTIALS';
  }

  // 6. DOM Selector Drift (populated HTTP 200 DOM on expected *.polimi.it IdP hostname)
  const hostname = extractHostnameSafe(snapshot?.url || input.url);
  const isExpectedIdpHost = isExpectedPolimiIdpHostname(hostname);
  const hasRuntimeEvalFailure = /evalerror|typeerror|referenceerror|syntaxerror/i.test(lowerCause);
  const isOkOrNoTransportError =
    !hasRuntimeEvalFailure &&
    (effectiveHttpStatus === undefined || effectiveHttpStatus === 200);
  const isCleanPopulatedDom =
    snapshot !== undefined &&
    snapshot.hasEmptyBody === false &&
    snapshot.hasMaintenanceBanner === false &&
    !hasBannerError;
  const isMissingStageSelectorFailure =
    (operation === 'submitCredentials' ||
      operation === 'submitOtp' ||
      operation === 'recoverSessionPage') &&
    isOkOrNoTransportError &&
    isCleanPopulatedDom;

  if (
    isExpectedIdpHost &&
    isOkOrNoTransportError &&
    isCleanPopulatedDom &&
    (stage === 'unknown' || isMissingStageSelectorFailure)
  ) {
    return 'DOM_SELECTOR_DRIFT';
  }

  return undefined;
}

/**
 * Structured, secret-redacted Error subclass carrying `PoliAuthDiagnosticErrorPayload`.
 */
export class PoliAuthDiagnosticError extends Error {
  public readonly payload: PoliAuthDiagnosticErrorPayload;

  constructor(
    payload: PoliAuthDiagnosticErrorPayload,
    extraSecrets: string[] = [],
    customRules: RedactionRule[] = []
  ) {
    const sanitized = sanitizeDiagnosticErrorPayload(payload, extraSecrets, customRules);
    super(sanitized.message);
    this.name = 'PoliAuthDiagnosticError';
    this.payload = sanitized;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface PolimiStageInspectionResult {
  stage: PolimiPageStage;
  url: string;
  title: string;
  errorMessage?: string;
  httpStatus?: number;
  semanticErrorCode?: PolimiSemanticErrorCode;
  diagnosticSnapshot?: PoliAuthDomDiagnosticSnapshot;
  diagnosticError?: PoliAuthDiagnosticErrorPayload;
}

export type StageInspectionResult = PolimiStageInspectionResult;
export type PoliAuthStageInspectionResult = PolimiStageInspectionResult;

/**
 * High-level status of an authentication flow.
 */
export type LoginFlowStatus =
  | 'idle'
  | 'opening_login'
  | 'recovering_session'
  | 'submitting_credentials'
  | 'waiting_for_otp'
  | 'submitting_otp'
  | 'authenticated'
  | 'failed'
  | 'reauth_required';

export type UserLoginStatus = LoginFlowStatus;

export const LOGIN_STATUS_LABELS: Record<LoginFlowStatus, string> = {
  idle: 'Idle',
  opening_login: 'Opening Login',
  recovering_session: 'Recovering Session',
  submitting_credentials: 'Submitting Credentials',
  waiting_for_otp: 'Waiting for OTP',
  submitting_otp: 'Submitting OTP',
  authenticated: 'Authenticated',
  failed: 'Login Failed',
  reauth_required: 'Re-authentication Required'
};

/**
 * Status of a federated SAML SSO flow, as observed from the Service Provider (SP) side.
 */
export type FederatedSsoStatus =
  | 'authenticated'
  | 'login_required'
  | 'sso_in_transit'
  | 'error';

/**
 * Provider-neutral classification of the current page during a federated SAML SSO flow.
 */
export interface FederatedSsoInspectionResult {
  /** Identifier of the federated SSO provider adapter that produced this result (e.g. `'webex'`, `'webeep'`). */
  providerId: string;
  status: FederatedSsoStatus;
  /**
   * `true` when the SP renders an identifier-discovery prompt (institutional email /
   * username) that must be submitted before the SP redirects to the PoliMi IdP.
   */
  isIdentifierPrompt: boolean;
  /**
   * `true` when the SP renders a click-through SSO login trigger button or link
   * that initiates the SAML/Shibboleth redirect without requiring an email prompt.
   */
  isLoginTrigger: boolean;
  /** `true` while the browser is on SP/IdP SAML redirect or assertion endpoints. */
  isSamlTransitPage: boolean;
  url: string;
  reason?: string;
}

/**
 * Domain entity representing a persisted user identity in PoliAuth.
 */
export interface UserIdentity {
  userId: IdentityId;
  username: string | null;
  displayName: string | null;
  personCode: string;
  polimiEmail: string;
  loginStatus: LoginFlowStatus;
  loginError: string | null;
  roles: string[];
  metadata: Record<string, unknown>;
  createdAt: number;
  updatedAt: number;
}

export interface UserIdentityPatch {
  username?: string | null;
  displayName?: string | null;
  personCode?: string;
  polimiEmail?: string;
  loginStatus?: LoginFlowStatus;
  loginError?: string | null;
  roles?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * Value object representing the subject of an authorization check.
 */
export interface AuthSubject {
  userId: IdentityId;
  isAllowed: boolean;
  isAdmin: boolean;
  isPrivateChannel: boolean;
  identity?: UserIdentity | null;
}
