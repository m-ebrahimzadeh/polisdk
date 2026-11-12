/**
 * @module @polisdk/poliauth/application/otp-challenge
 * Two-Factor Authentication (2FA) Challenge Coordinator (Application Layer Use Case).
 *
 * Manages automatic TOTP derivation (with rollover guard) and asynchronous
 * manual 6-digit OTP waiters per user with bounded timeouts.
 */

import { normalizeIdentityId, type IdentityId } from '../domain/entities.js';
import { TotpService } from '../domain/totp.js';
import type { TotpGeneratorPort } from '../interfaces/crypto-port.js';
import type {
  LoginProgressCallbacks,
  OtpChallengeProviderPort,
  OtpResolutionResult
} from '../interfaces/otp-provider-port.js';

interface PendingOtpWaiter {
  resolve: (otp: string) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

function unrefTimerIfSupported(timer: unknown): void {
  if (
    typeof timer === 'object' &&
    timer !== null &&
    'unref' in timer &&
    typeof (timer as { unref?: unknown }).unref === 'function'
  ) {
    (timer as { unref: () => void }).unref();
  }
}

export interface OtpChallengeCoordinatorOptions {
  /** Timeout for manual OTP entry in milliseconds. Default: 120_000 (2 minutes). */
  manualOtpTimeoutMs?: number;
  /** Minimum remaining TOTP window seconds before waiting for next window. Default: 2. */
  minTotpRemainingSeconds?: number;
  /** Custom TOTP generator implementation. */
  totpGenerator?: TotpGeneratorPort;
  /** Optional default notifier invoked when a user must enter a manual OTP. */
  defaultOtpRequiredNotifier?: (userId: IdentityId) => void | Promise<void>;
}

export class OtpChallengeCoordinator implements OtpChallengeProviderPort {
  private readonly pendingWaiters = new Map<string, PendingOtpWaiter>();
  private readonly manualOtpTimeoutMs: number;
  private readonly minTotpRemainingSeconds: number;
  private readonly totpGenerator: TotpGeneratorPort;
  private defaultNotifier: ((userId: IdentityId) => void | Promise<void>) | null;

  constructor(options: OtpChallengeCoordinatorOptions = {}) {
    this.manualOtpTimeoutMs = options.manualOtpTimeoutMs ?? 120_000;
    this.minTotpRemainingSeconds = options.minTotpRemainingSeconds ?? 2;
    this.totpGenerator = options.totpGenerator ?? new TotpService();
    this.defaultNotifier = options.defaultOtpRequiredNotifier ?? null;
  }

  public setDefaultOtpRequiredNotifier(
    notifier: (userId: IdentityId) => void | Promise<void>
  ): void {
    this.defaultNotifier = notifier;
  }

  public async obtainOtpCodeForUser(
    userId: IdentityId,
    totpSecret: string | undefined,
    allowAutoTotp: boolean,
    callbacks?: LoginProgressCallbacks
  ): Promise<OtpResolutionResult> {
    const canUseAutoTotp =
      allowAutoTotp &&
      Boolean(totpSecret) &&
      this.totpGenerator.isValidSecret(totpSecret!);

    if (canUseAutoTotp) {
      const { code } = await this.totpGenerator.generateStable(totpSecret!, {
        minRemainingSeconds: this.minTotpRemainingSeconds
      });
      return { otp: code, usedAutoTotp: true };
    }

    await callbacks?.onStatusChange?.(
      'waiting_for_otp',
      'Waiting for 6-digit 2FA OTP...'
    );

    if (callbacks?.onOtpRequired) {
      await callbacks.onOtpRequired();
    } else if (this.defaultNotifier) {
      await this.defaultNotifier(userId);
    }

    const otp = await this.waitForManualOtp(userId, this.manualOtpTimeoutMs);
    return { otp, usedAutoTotp: false };
  }

  public hasPendingOtpWaiter(userId: IdentityId): boolean {
    return this.pendingWaiters.has(normalizeIdentityId(userId));
  }

  public submitManualOtpForUser(userId: IdentityId, otp: string): boolean {
    const key = normalizeIdentityId(userId);
    const waiter = this.pendingWaiters.get(key);
    if (!waiter) return false;

    const cleaned = otp.replace(/\s+/g, '');
    if (!/^\d{6}$/.test(cleaned)) {
      return false;
    }

    clearTimeout(waiter.timer);
    this.pendingWaiters.delete(key);
    waiter.resolve(cleaned);
    return true;
  }

  public cancelPendingOtpWaiter(
    userId: IdentityId,
    reason = 'OTP challenge cancelled.'
  ): void {
    const key = normalizeIdentityId(userId);
    const existing = this.pendingWaiters.get(key);
    if (!existing) return;
    clearTimeout(existing.timer);
    this.pendingWaiters.delete(key);
    existing.reject(new Error(reason));
  }

  public waitForManualOtp(
    userId: IdentityId,
    timeoutMs = this.manualOtpTimeoutMs
  ): Promise<string> {
    const key = normalizeIdentityId(userId);
    const existing = this.pendingWaiters.get(key);
    if (existing) {
      clearTimeout(existing.timer);
      existing.reject(new Error('Superseded by a new OTP request.'));
      this.pendingWaiters.delete(key);
    }

    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingWaiters.delete(key);
        reject(new Error('Timed out waiting for 6-digit 2FA OTP.'));
      }, timeoutMs);

      unrefTimerIfSupported(timer);

      this.pendingWaiters.set(key, { resolve, reject, timer });
    });
  }
}
