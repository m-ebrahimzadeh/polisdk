/**
 * @module @polisdk/poliauth/interfaces/otp-provider-port
 * Segregated Two-Factor Authentication (2FA) OTP Challenge Ports.
 */

import type { IdentityId, LoginFlowStatus } from '../domain/entities.js';

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
 * Resolves a 6-digit OTP for a user (automatic TOTP or interactive manual entry).
 * This is the only OTP role required by `PoliAuthOrchestrator`.
 */
export interface OtpCodeProviderPort {
  obtainOtpCodeForUser(
    userId: IdentityId,
    totpSecret: string | undefined,
    allowAutoTotp: boolean,
    callbacks?: LoginProgressCallbacks
  ): Promise<OtpResolutionResult>;
}

/**
 * Delivery-side control of pending interactive OTP challenges
 * (used by bots/UIs that relay a user-typed code).
 */
export interface ManualOtpChallengePort {
  hasPendingOtpWaiter(userId: IdentityId): boolean;
  submitManualOtpForUser(userId: IdentityId, otp: string): boolean;
  cancelPendingOtpWaiter(userId: IdentityId, reason?: string): void;
}

/**
 * Full OTP challenge coordinator contract (implemented by `OtpChallengeCoordinator`).
 */
export interface OtpChallengeProviderPort extends OtpCodeProviderPort, ManualOtpChallengePort {}
