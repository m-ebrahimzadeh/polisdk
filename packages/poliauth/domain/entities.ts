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
 * Structured diagnostic error payload attached to `PoliAuthDiagnosticError` and outcomes.
 */
export interface PoliAuthDiagnosticErrorPayload {
  component: string;
  operation: string;
  stage: PoliAuthStage;
  classification: PoliAuthFailureClassification;
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
  pathname?: string;
  httpStatus?: number;
  selectorOrEndpoint?: string;
  error?: unknown;
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
    } else if (
      (stage === 'otp' && snapshot?.hasErrorBanner) ||
      /otp rejected|2fa otp rejected|2fa manual otp exceeded/i.test(lowerCause)
    ) {
      classification = 'OTP_CHALLENGE_FAILED';
      message =
        snapshot?.errorMessage ||
        rawCause ||
        'PoliMi 2FA OTP challenge was rejected.';
    } else if (
      (stage === 'credentials' && snapshot?.hasErrorBanner) ||
      /login rejected|invalid credentials|credenziali non valide/i.test(lowerCause)
    ) {
      classification = 'AUTHENTICATION_REJECTED';
      message =
        snapshot?.errorMessage ||
        rawCause ||
        'PoliMi credentials were rejected by Identity Provider.';
    } else {
      // 3. Deterministic DOM Selector Drift check
      const hostname = extractHostnameSafe(snapshot?.url || input.url);
      const isExpectedIdpHost = isExpectedPolimiIdpHostname(hostname);
      const hasRuntimeEvalFailure = /evalerror|typeerror|referenceerror|syntaxerror/i.test(
        lowerCause
      );
      const isOkOrNoTransportError =
        !hasRuntimeEvalFailure &&
        (effectiveHttpStatus === undefined || effectiveHttpStatus === 200);
      const isCleanPopulatedDom =
        snapshot !== undefined &&
        snapshot.hasEmptyBody === false &&
        snapshot.hasMaintenanceBanner === false &&
        snapshot.hasErrorBanner === false;
      const isMissingStageSelectorFailure =
        (input.operation === 'submitCredentials' ||
          input.operation === 'submitOtp' ||
          input.operation === 'recoverSessionPage') &&
        (effectiveHttpStatus === undefined || effectiveHttpStatus === 200) &&
        snapshot !== undefined &&
        snapshot.hasEmptyBody === false &&
        snapshot.hasMaintenanceBanner === false &&
        snapshot.hasErrorBanner === false;

      if (
        isExpectedIdpHost &&
        isOkOrNoTransportError &&
        isCleanPopulatedDom &&
        (stage === 'unknown' || isMissingStageSelectorFailure)
      ) {
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

  return sanitizeDiagnosticErrorPayload(
    {
      component,
      operation: input.operation,
      stage,
      classification,
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
  diagnosticSnapshot?: PoliAuthDomDiagnosticSnapshot;
  diagnosticError?: PoliAuthDiagnosticErrorPayload;
}

export type StageInspectionResult = PolimiStageInspectionResult;

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
  | 'failed';

export const LOGIN_STATUS_LABELS: Record<LoginFlowStatus, string> = {
  idle: 'Idle',
  opening_login: 'Opening Login',
  recovering_session: 'Recovering Session',
  submitting_credentials: 'Submitting Credentials',
  waiting_for_otp: 'Waiting for OTP',
  submitting_otp: 'Submitting OTP',
  authenticated: 'Authenticated',
  failed: 'Login Failed'
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
