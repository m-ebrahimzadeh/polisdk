/**
 * @module @polisdk/telegram-auth
 * Telegram-aware Credential Setup Wizard tracking per-user `promptMessageId`.
 */

import {
  CredentialSetupWizard,
  normalizeIdentityId,
  type IdentityId,
  type WizardSessionState,
  type WizardTransitionResult,
} from "@polisdk/poliauth";

export interface TelegramWizardSession extends WizardSessionState {
  promptMessageId?: number;
}

/**
 * Telegram wrapper around `CredentialSetupWizard` that adds per-user `promptMessageId`
 * tracking so bots can update or delete interactive wizard prompt messages.
 */
export class TelegramCredentialWizard {
  private readonly wizard: CredentialSetupWizard;
  private readonly promptIds = new Map<string, number>();

  constructor() {
    this.wizard = new CredentialSetupWizard();
  }

  startSession(
    userId: IdentityId,
    promptMessageId?: number,
  ): TelegramWizardSession {
    const session = this.wizard.startSession(userId);
    const key = normalizeIdentityId(userId);
    if (promptMessageId !== undefined) {
      this.promptIds.set(key, promptMessageId);
    } else {
      this.promptIds.delete(key);
    }
    return {
      ...session,
      promptMessageId,
    };
  }

  setPromptMessageId(userId: IdentityId, promptMessageId: number): void {
    const key = normalizeIdentityId(userId);
    if (this.wizard.hasActiveSession(userId)) {
      this.promptIds.set(key, promptMessageId);
    }
  }

  getSession(userId: IdentityId): TelegramWizardSession | null {
    const key = normalizeIdentityId(userId);
    const session = this.wizard.getSession(userId);
    if (!session) {
      this.promptIds.delete(key);
      return null;
    }
    return {
      ...session,
      promptMessageId: this.promptIds.get(key),
    };
  }

  hasActiveSession(userId: IdentityId): boolean {
    const active = this.wizard.hasActiveSession(userId);
    if (!active) {
      this.promptIds.delete(normalizeIdentityId(userId));
    }
    return active;
  }

  cancelSession(userId: IdentityId): void {
    this.promptIds.delete(normalizeIdentityId(userId));
    this.wizard.cancelSession(userId);
  }

  submitStepInput(
    userId: IdentityId,
    rawText: string,
  ): WizardTransitionResult | null {
    const result = this.wizard.submitStepInput(userId, rawText);
    if (!result || result.status === "completed") {
      this.promptIds.delete(normalizeIdentityId(userId));
    }
    return result;
  }

  skipTotpStep(userId: IdentityId): WizardTransitionResult | null {
    const result = this.wizard.skipTotpStep(userId);
    if (!result || result.status === "completed") {
      this.promptIds.delete(normalizeIdentityId(userId));
    }
    return result;
  }
}
