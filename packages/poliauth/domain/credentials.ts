/**
 * @module @polisdk/poliauth/domain/credentials
 * Credential Validation, Normalization, and Privacy Masking Utilities.
 */

import type { LoginCredentials, SavedVaultCredentials } from './entities';

/**
 * Masks a PoliMi Person Code (Codice Persona) for safe display in UI and logs.
 * Example: `"10812345"` -> `"108***45"`
 */
export function maskPersonCode(personCode: string): string {
  const trimmed = (personCode || '').trim();
  if (!trimmed) return 'Not set';
  if (trimmed.length <= 4) return '****';
  return `${trimmed.slice(0, 3)}${'*'.repeat(trimmed.length - 5)}${trimmed.slice(-2)}`;
}

/**
 * Masks a PoliMi email address for safe display in UI and logs.
 * Example: `"mario.rossi@mail.polimi.it"` -> `"ma***i@mail.polimi.it"`
 */
export function maskPolimiEmail(email: string): string {
  const trimmed = (email || '').trim();
  if (!trimmed) return 'Not set';
  const [localPart, domain] = trimmed.split('@');
  if (!domain) return '***';
  const maskedLocal =
    localPart.length <= 2
      ? `${localPart[0] || '*'}***`
      : `${localPart.slice(0, 2)}***${localPart.slice(-1)}`;
  return `${maskedLocal}@${domain}`;
}

/**
 * Masks an arbitrary password or secret string.
 */
export function maskSecret(secret: string | undefined | null): string {
  if (!secret || !secret.trim()) return 'Not set';
  return '●●●●●●●●';
}

/**
 * Validates whether a string is a plausible PoliMi Person Code (6 to 10 digits).
 */
export function isValidPersonCode(personCode: string): boolean {
  const trimmed = (personCode || '').trim();
  return /^\d{6,10}$/.test(trimmed);
}

/**
 * Validates whether a string is a valid PoliMi email address (`@mail.polimi.it` or `@polimi.it`).
 */
export function isValidPolimiEmail(email: string): boolean {
  const trimmed = (email || '').trim().toLowerCase();
  return /^[^\s@]+@(?:mail\.)?polimi\.it$/.test(trimmed);
}

/**
 * Validates whether a string is a 6-digit numeric 2FA OTP code.
 */
export function isValidOtpCode(otp: string): boolean {
  const cleaned = (otp || '').replace(/\s+/g, '');
  return /^\d{6}$/.test(cleaned);
}

/**
 * Merges partial credential updates into an existing `SavedVaultCredentials` snapshot.
 */
export function mergeVaultCredentials(
  existing: SavedVaultCredentials | null | undefined,
  patch: Partial<SavedVaultCredentials | LoginCredentials>,
  now = Date.now()
): SavedVaultCredentials {
  const base: SavedVaultCredentials = existing || {
    personCode: '',
    password: '',
    totpSecret: '',
    polimiEmail: '',
    updatedAt: 0
  };

  return {
    personCode:
      patch.personCode !== undefined ? patch.personCode.trim() : base.personCode,
    password: patch.password !== undefined ? patch.password : base.password,
    totpSecret:
      patch.totpSecret !== undefined ? patch.totpSecret.trim() : base.totpSecret,
    polimiEmail:
      patch.polimiEmail !== undefined ? patch.polimiEmail.trim() : base.polimiEmail,
    updatedAt: now
  };
}
