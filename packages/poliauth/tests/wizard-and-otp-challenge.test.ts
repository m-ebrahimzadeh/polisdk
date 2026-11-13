import { describe, expect, it } from 'vitest';
import { CredentialSetupWizard } from '../application/credential-wizard.js';
import { OtpChallengeCoordinator } from '../application/otp-challenge.js';
import { TotpService } from '../domain/totp.js';
import { InMemoryUserIdentityRepository } from '../storage/memory-storage.js';
import { PoliAuth } from '../src/poliauth-client.js';

describe('CredentialSetupWizard & OtpChallengeCoordinator', () => {
  it('guides a user through all 4 steps of the interactive credential setup wizard with input validation', () => {
    const wizard = new CredentialSetupWizard();
    const userId = 1001;

    const initial = wizard.startSession(userId);
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

  it('resets loginStatus from reauth_required back to idle and clears loginError upon wizard completion and PoliAuth.saveCredentials', async () => {
    const users = new InMemoryUserIdentityRepository();
    await users.ensureUser(8001, { username: 'mario.rossi' });
    await users.updateLoginStatus(
      8001,
      'reauth_required',
      'PoliMi login rejected: Credenziali non valide'
    );

    const wizard = new CredentialSetupWizard({ identityRepository: users });
    wizard.startSession(8001);
    wizard.submitStepInput(8001, '10987654');
    wizard.submitStepInput(8001, 'FreshPoliPass!');
    wizard.submitStepInput(8001, 'mario.rossi@mail.polimi.it');
    const doneTotp = wizard.submitStepInput(8001, 'JBSWY3DPEHPK3PXP');
    expect(doneTotp?.status).toBe('completed');

    const afterTotpWizard = await users.getUser(8001);
    expect(afterTotpWizard?.loginStatus).toBe('idle');
    expect(afterTotpWizard?.loginError).toBeNull();

    // Also test skipTotpStep path
    await users.updateLoginStatus(8001, 'reauth_required', 'Password expired');
    wizard.startSession(8001);
    wizard.submitStepInput(8001, '10987654');
    wizard.submitStepInput(8001, 'AnotherPass!');
    wizard.submitStepInput(8001, 'mario.rossi@mail.polimi.it');
    const doneSkip = wizard.skipTotpStep(8001);
    expect(doneSkip?.status).toBe('completed');

    const afterSkipWizard = await users.getUser(8001);
    expect(afterSkipWizard?.loginStatus).toBe('idle');
    expect(afterSkipWizard?.loginError).toBeNull();

    // Also test PoliAuth.saveCredentials resetting reauth_required
    const client = new PoliAuth({ identityRepository: users });
    await users.updateLoginStatus(8001, 'reauth_required', 'Invalid credentials');
    await client.saveCredentials(
      {
        personCode: '10987654',
        password: 'FixedPassword!',
        polimiEmail: 'mario.rossi@mail.polimi.it',
        totpSecret: 'JBSWY3DPEHPK3PXP'
      },
      8001
    );

    const afterSave = await users.getUser(8001);
    expect(afterSave?.loginStatus).toBe('idle');
    expect(afterSave?.loginError).toBeNull();
  });
});
