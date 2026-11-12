/**
 * @module @polisdk/poliauth/domain/entities
 * Core Domain Entities, Value Objects, and Authentication State Models.
 */

/**
 * Unique identifier for a user or tenant across any host platform
 * (e.g., Telegram numeric user ID, UUID string, or browser profile ID).
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
 * 100% compatible with `LoginCredentials` in PoliRecord.
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
 * 100% compatible with `SavedVaultCredentials` in PoliRecord.
 */
export interface SavedVaultCredentials {
  personCode: string;
  password: string;
  totpSecret: string;
  polimiEmail: string;
  updatedAt: number;
}

/**
 * Stage of the Politecnico di Milano authentication and portal navigation pipeline.
 * Preserves `'archive'` for backward compatibility while supporting `'target_service'`
 * for arbitrary PoliMi portal services.
 */
export type PolimiPageStage =
  | 'archive'
  | 'target_service'
  | 'portal'
  | 'otp'
  | 'credentials'
  | 'sso_handoff'
  | 'session_expired'
  | 'unknown';

export interface PolimiStageInspectionResult {
  stage: PolimiPageStage;
  url: string;
  title: string;
  errorMessage?: string;
  hasRecordingArchivesLink?: boolean;
  hasTargetServiceLink?: boolean;
  detectedServiceId?: string;
}

/**
 * High-level status of an authentication flow.
 */
export type LoginFlowStatus =
  | 'idle'
  | 'opening_login'
  | 'submitting_credentials'
  | 'waiting_for_otp'
  | 'submitting_otp'
  | 'opening_recording_archives'
  | 'opening_target_service'
  | 'authenticated'
  | 'failed';

export const LOGIN_STATUS_LABELS: Record<LoginFlowStatus, string> = {
  idle: 'Idle',
  opening_login: 'Opening Login',
  submitting_credentials: 'Submitting Credentials',
  waiting_for_otp: 'Waiting for OTP',
  submitting_otp: 'Submitting OTP',
  opening_recording_archives: 'Opening Recording Archives',
  opening_target_service: 'Opening Target Service',
  authenticated: 'Authenticated',
  failed: 'Login Failed'
};

/**
 * Status of a federated SAML SSO flow (such as Cisco Webex IdB -> Shibboleth IdP -> PoliMi AunicaLogin).
 */
export type FederatedSsoStatus =
  | 'authenticated'
  | 'login_required'
  | 'sso_in_transit'
  | 'error';

export interface FederatedSsoInspectionResult {
  status: FederatedSsoStatus;
  isEmailSsoPage: boolean;
  isSamlTransitPage: boolean;
  url: string;
  reason?: string;
}

/**
 * Domain entity representing a persisted user identity in PoliAuth.
 * Application-specific fields (like download queues or course filters) do not belong here,
 * though arbitrary host metadata can be attached via `metadata`.
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
