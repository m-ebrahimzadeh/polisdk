/**
 * @module @polisdk/poliauth/interfaces/otp-provider-port
 * Two-Factor Authentication (2FA) OTP Challenge Coordination Port.
 */

import type { IdentityId, LoginFlowStatus } from '../domain/entities';

export interface LoginProgressCallbacks {
  onStatusChange?: (
    status: LoginFlowStatus,
    message: string
  ) => void | Promise<void>;
  onOtpRequired?: () => void | Promise<void>;
}

export interface OtpResolutionResult {
  otp: string;
  usedAutoTotp: boolean;
}

/**
 * Coordinates automatic TOTP derivation and interactive manual 6-digit OTP challenges.
 */
export interface OtpChallengeProviderPort {
  obtainOtpCodeForUser(
    userId: IdentityId,
    totpSecret: string | undefined,
    allowAutoTotp: boolean,
    callbacks?: LoginProgressCallbacks
  ): Promise<OtpResolutionResult>;

  hasPendingOtpWaiter(userId: IdentityId): boolean;

  submitManualOtpForUser(userId: IdentityId, otp: string): boolean;

  cancelPendingOtpWaiter(userId: IdentityId, reason?: string): void;
}
