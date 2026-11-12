import { describe, expect, it } from 'vitest';
import { CredentialSetupWizard } from '../domain/credential-wizard.js';
import { OtpChallengeCoordinator } from '../domain/otp-challenge.js';
import { TotpService } from '../domain/totp.js';

describe('CredentialSetupWizard & OtpChallengeCoordinator', () => {
  it('guides a user through all 4 steps of the interactive credential setup wizard with input validation', () => {
    const wizard = new CredentialSetupWizard();
    const userId = 1001;

    const initial = wizard.startSession(userId, 999);
    expect(initial.step).toBe('person_code');
    expect(wizard.hasActiveSession(userId)).toBe(true);

    // Empty input rejected
    const emptyCode = wizard.submitStepInput(userId, '   ');
    expect(emptyCode?.status).toBe('validation_error');

    // Step 1: Person code advances to password
    const step1 = wizard.submitStepInput(userId, '10987654');
    expect(step1?.status).toBe('next_step');
    if (step1?.status === 'next_step') {
      expect(step1.step).toBe('password');
      expect(step1.maskedPersonCode).toBe('109***54');
    }

    // Step 2: Password advances to email
    const step2 = wizard.submitStepInput(userId, 'SuperSecretPoliPass!');
    expect(step2?.status).toBe('next_step');
    if (step2?.status === 'next_step') {
      expect(step2.step).toBe('email');
    }

    // Step 3: Email advances to totp_secret
    const step3 = wizard.submitStepInput(userId, 'mario.rossi@mail.polimi.it');
    expect(step3?.status).toBe('next_step');
    if (step3?.status === 'next_step') {
      expect(step3.step).toBe('totp_secret');
      expect(step3.maskedEmail).toBe('ma***i@mail.polimi.it');
    }

    // Invalid TOTP secret rejected
    const badTotp = wizard.submitStepInput(userId, 'NOT_BASE32_!!!');
    expect(badTotp?.status).toBe('validation_error');

    // Step 4: Valid TOTP secret completes wizard
    const done = wizard.submitStepInput(userId, 'jbsw y3dp ehpk 3pxp');
    expect(done?.status).toBe('completed');
    expect(wizard.hasActiveSession(userId)).toBe(false);
    if (done?.status === 'completed') {
      expect(done.credentials).toEqual({
        personCode: '10987654',
        password: 'SuperSecretPoliPass!',
        polimiEmail: 'mario.rossi@mail.polimi.it',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      });
    }
  });

  it('supports skipping TOTP secret in the wizard and cancelling mid-flow', () => {
    const wizard = new CredentialSetupWizard();
    wizard.startSession('user-skip');
    wizard.submitStepInput('user-skip', '10987654');
    wizard.submitStepInput('user-skip', 'Pass123!');
    wizard.submitStepInput('user-skip', 'mario.rossi@mail.polimi.it');

    const skipTotp = wizard.skipTotpStep('user-skip');
    expect(skipTotp?.status).toBe('completed');
    if (skipTotp?.status === 'completed') {
      expect(skipTotp.credentials.totpSecret).toBe('');
    }
    expect(wizard.hasActiveSession('user-skip')).toBe(false);

    wizard.startSession('user-cancel');
    expect(wizard.hasActiveSession('user-cancel')).toBe(true);
    wizard.cancelSession('user-cancel');
    expect(wizard.hasActiveSession('user-cancel')).toBe(false);
  });

  it('resolves manual OTP challenges, supersedes older waiters, and rejects on timeout', async () => {
    const coordinator = new OtpChallengeCoordinator({ totpGenerator: new TotpService() });

    // 1. Manual OTP resolution
    const waitPromise = coordinator.waitForManualOtp(501, 5_000);
    expect(coordinator.hasPendingOtpWaiter(501)).toBe(true);

    // Invalid OTP format ignored
    expect(coordinator.submitManualOtpForUser(501, 'abc')).toBe(false);

    // Valid 6-digit OTP resolves the promise
    expect(coordinator.submitManualOtpForUser(501, ' 123 456 ')).toBe(true);
    await expect(waitPromise).resolves.toBe('123456');
    expect(coordinator.hasPendingOtpWaiter(501)).toBe(false);

    // 2. Superseding an existing waiter
    const firstWaiter = coordinator.waitForManualOtp(502, 5_000);
    const secondWaiter = coordinator.waitForManualOtp(502, 5_000);
    await expect(firstWaiter).rejects.toThrow(/Superseded/i);
    coordinator.submitManualOtpForUser(502, '654321');
    await expect(secondWaiter).resolves.toBe('654321');

    // 3. Timeout expiration
    const timeoutWaiter = coordinator.waitForManualOtp(503, 30);
    await expect(timeoutWaiter).rejects.toThrow(/Timed out/i);
  });
});
