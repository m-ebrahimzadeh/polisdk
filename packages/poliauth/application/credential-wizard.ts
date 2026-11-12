/**
 * @module @polisdk/poliauth/application/credential-wizard
 * Platform-Agnostic Interactive Credential Onboarding Wizard State Machine (Application Layer).
 */

import {
  maskPersonCode,
  maskPolimiEmail
} from '../domain/credentials.js';
import {
  normalizeIdentityId,
  type IdentityId,
  type SavedVaultCredentials
} from '../domain/entities.js';
import { cleanTotpSecret, isValidTotpSecret } from '../domain/totp.js';

export type WizardStep = 'person_code' | 'password' | 'email' | 'totp_secret';

export interface WizardSessionState {
  userId: IdentityId;
  step: WizardStep;
  personCode: string;
  password: string;
  polimiEmail: string;
  startedAt: number;
}

export type WizardTransitionResult =
  | {
      status: 'next_step';
      step: WizardStep;
      session: WizardSessionState;
      maskedPersonCode: string;
      maskedEmail?: string;
    }
  | {
      status: 'validation_error';
      step: WizardStep;
      errorMessage: string;
      session: WizardSessionState;
    }
  | {
      status: 'completed';
      session: WizardSessionState;
      credentials: Omit<SavedVaultCredentials, 'updatedAt'>;
      maskedPersonCode: string;
      maskedEmail: string;
    };

export class CredentialSetupWizard {
  private readonly sessions = new Map<string, WizardSessionState>();

  public startSession(userId: IdentityId): WizardSessionState {
    const state: WizardSessionState = {
      userId,
      step: 'person_code',
      personCode: '',
      password: '',
      polimiEmail: '',
      startedAt: Date.now()
    };
    this.sessions.set(normalizeIdentityId(userId), state);
    return state;
  }

  public getSession(userId: IdentityId): WizardSessionState | null {
    return this.sessions.get(normalizeIdentityId(userId)) ?? null;
  }

  public hasActiveSession(userId: IdentityId): boolean {
    return this.sessions.has(normalizeIdentityId(userId));
  }

  public cancelSession(userId: IdentityId): void {
    this.sessions.delete(normalizeIdentityId(userId));
  }

  /**
   * Advances the wizard with the user's text input for the current step.
   */
  public submitStepInput(
    userId: IdentityId,
    rawInput: string
  ): WizardTransitionResult | null {
    const key = normalizeIdentityId(userId);
    const session = this.sessions.get(key);
    if (!session) return null;

    const text = rawInput.trim();
    if (!text) {
      return {
        status: 'validation_error',
        step: session.step,
        errorMessage: 'Input cannot be empty.',
        session
      };
    }

    if (session.step === 'person_code') {
      session.personCode = text;
      session.step = 'password';
      return {
        status: 'next_step',
        step: 'password',
        session,
        maskedPersonCode: maskPersonCode(session.personCode)
      };
    }

    if (session.step === 'password') {
      session.password = rawInput.trim();
      session.step = 'email';
      return {
        status: 'next_step',
        step: 'email',
        session,
        maskedPersonCode: maskPersonCode(session.personCode)
      };
    }

    if (session.step === 'email') {
      session.polimiEmail = text;
      session.step = 'totp_secret';
      return {
        status: 'next_step',
        step: 'totp_secret',
        session,
        maskedPersonCode: maskPersonCode(session.personCode),
        maskedEmail: maskPolimiEmail(session.polimiEmail)
      };
    }

    if (session.step === 'totp_secret') {
      if (text.toLowerCase() === 'skip') {
        return this.skipTotpStep(userId)!;
      }

      const cleaned = cleanTotpSecret(text);
      if (!isValidTotpSecret(cleaned)) {
        return {
          status: 'validation_error',
          step: 'totp_secret',
          errorMessage:
            'Invalid Base32 TOTP secret. Please provide a valid Base32 secret (at least 8 chars, A–Z / 2–7), an otpauth:// URI, or skip.',
          session
        };
      }

      this.sessions.delete(key);
      return {
        status: 'completed',
        session,
        credentials: {
          personCode: session.personCode,
          password: session.password,
          polimiEmail: session.polimiEmail,
          totpSecret: cleaned
        },
        maskedPersonCode: maskPersonCode(session.personCode),
        maskedEmail: maskPolimiEmail(session.polimiEmail)
      };
    }

    return null;
  }

  /**
   * Completes the wizard at Step 4 by skipping the optional TOTP secret.
   */
  public skipTotpStep(userId: IdentityId): WizardTransitionResult | null {
    const key = normalizeIdentityId(userId);
    const session = this.sessions.get(key);
    if (!session) return null;

    this.sessions.delete(key);
    return {
      status: 'completed',
      session,
      credentials: {
        personCode: session.personCode,
        password: session.password,
        polimiEmail: session.polimiEmail,
        totpSecret: ''
      },
      maskedPersonCode: maskPersonCode(session.personCode),
      maskedEmail: maskPolimiEmail(session.polimiEmail)
    };
  }
}
