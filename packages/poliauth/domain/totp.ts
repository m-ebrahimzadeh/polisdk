/**
 * @module @polisdk/poliauth/domain/totp
 * TOTP (Time-based One-Time Password) implementation conforming to RFC 6238 and RFC 4226.
 * Zero-dependency implementation powered by standard Web Crypto API (`crypto.subtle`).
 */

export interface TotpOptions {
  /** Timestamp in milliseconds. Defaults to Date.now(). */
  timestampMs?: number;
  /** Time step in seconds. Default 30. */
  timeStepSeconds?: number;
  /** Number of OTP digits. Default 6. */
  digits?: number;
}

export interface StableTotpOptions extends TotpOptions {
  /**
   * Minimum remaining validity window in seconds before generating a code.
   * If the current window has `<= minRemainingSeconds` left, `generateStable`
   * waits for the next time step so the code never expires mid-request.
   * Default: 2 seconds.
   */
  minRemainingSeconds?: number;
}

export interface StableTotpResult {
  code: string;
  remainingSeconds: number;
  waitedMs: number;
}

/**
 * Port/contract for RFC 6238 / RFC 4226 TOTP generation and Base32 validation.
 */
export interface TotpGeneratorPort {
  cleanSecret(input: string): string;
  isValidSecret(input: string): boolean;
  decodeBase32(base32Str: string): Uint8Array;
  generate(secret: string, options?: TotpOptions): Promise<string>;
  generateStable(
    secret: string,
    options?: StableTotpOptions
  ): Promise<StableTotpResult>;
  getRemainingSeconds(timestampMs?: number, timeStepSeconds?: number): number;
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BASE32_LOOKUP: Record<string, number> = {};
for (let i = 0; i < BASE32_ALPHABET.length; i++) {
  BASE32_LOOKUP[BASE32_ALPHABET[i]] = i;
}

/**
 * Extracts and cleans a Base32 secret string.
 * Supports:
 * - Raw Base32 strings (e.g. `"JBSWY3DPEHPK3PXP"`)
 * - Strings with whitespace or hyphens (e.g. `"JBSW Y3DP-EHPK 3PXP"`)
 * - `otpauth://` URIs (e.g. `"otpauth://totp/PoliMi:11033850?secret=JBSWY3DPEHPK3PXP&issuer=PoliMi"`)
 */
export function cleanTotpSecret(input: string): string {
  if (!input) return '';
  let str = input.trim();

  if (str.toLowerCase().startsWith('otpauth://')) {
    try {
      const parsedUrl = new URL(str);
      const secretParam = parsedUrl.searchParams.get('secret');
      if (secretParam) {
        str = secretParam;
      }
    } catch {
      const match = /[?&]secret=([A-Za-z2-7=]+)/i.exec(str);
      if (match && match[1]) {
        str = match[1];
      }
    }
  }

  return str.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
}

/**
 * Checks whether a given string is a valid Base32 TOTP secret (at least 8 Base32 chars).
 */
export function isValidTotpSecret(input: string): boolean {
  const cleaned = cleanTotpSecret(input);
  if (cleaned.length < 8) return false;
  for (let i = 0; i < cleaned.length; i++) {
    if (BASE32_LOOKUP[cleaned[i]] === undefined) {
      return false;
    }
  }
  return true;
}

/**
 * Decodes an RFC 4648 Base32 string into raw bytes.
 */
export function decodeBase32(base32Str: string): Uint8Array {
  const cleaned = cleanTotpSecret(base32Str);
  if (cleaned.length === 0) {
    return new Uint8Array(0);
  }

  let buffer = 0;
  let bitsLeft = 0;
  const output: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const char = cleaned[i];
    const val = BASE32_LOOKUP[char];
    if (val === undefined) {
      throw new Error(`Invalid Base32 character '${char}' in TOTP secret.`);
    }
    buffer = (buffer << 5) | val;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      output.push((buffer >> bitsLeft) & 0xff);
    }
  }

  return new Uint8Array(output);
}

/**
 * Generates an RFC 6238 Time-based One-Time Password (TOTP) using HMAC-SHA1.
 */
export async function generateTotp(
  secret: string,
  options: TotpOptions = {}
): Promise<string> {
  const { timestampMs = Date.now(), timeStepSeconds = 30, digits = 6 } = options;
  const secretBytes = decodeBase32(secret);
  if (secretBytes.length === 0) {
    throw new Error('TOTP secret is empty.');
  }

  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('Web Crypto API (crypto.subtle) is not available.');
  }

  const counter = Math.floor(timestampMs / 1000 / timeStepSeconds);
  const counterBuffer = new Uint8Array(8);
  let tempCounter = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    counterBuffer[i] = Number(tempCounter & 0xffn);
    tempCounter >>= 8n;
  }

  const key = await subtle.importKey(
    'raw',
    secretBytes as unknown as BufferSource,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signature = await subtle.sign(
    'HMAC',
    key,
    counterBuffer as unknown as BufferSource
  );
  const hmac = new Uint8Array(signature);

  // RFC 4226 Dynamic Truncation
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const modulo = 10 ** digits;
  const otpNumber = binary % modulo;
  return otpNumber.toString().padStart(digits, '0');
}

/**
 * Returns the number of seconds remaining until the current TOTP time-step ends (`1..30`).
 */
export function getTotpRemainingSeconds(
  timestampMs = Date.now(),
  timeStepSeconds = 30
): number {
  const currentSeconds = Math.floor(timestampMs / 1000);
  const elapsed = currentSeconds % timeStepSeconds;
  return timeStepSeconds - elapsed;
}

/**
 * Generates a TOTP code while guarding against imminent window rollover.
 * If the current 30-second window has `<= minRemainingSeconds` (default 2s) left,
 * waits for the next window before computing the code so it never expires mid-POST.
 */
export async function generateStableTotp(
  secret: string,
  options: StableTotpOptions = {}
): Promise<{ code: string; remainingSeconds: number; waitedMs: number }> {
  const {
    minRemainingSeconds = 2,
    timeStepSeconds = 30,
    digits = 6,
    timestampMs
  } = options;

  let waitedMs = 0;
  let effectiveNow = timestampMs ?? Date.now();
  const remaining = getTotpRemainingSeconds(effectiveNow, timeStepSeconds);

  if (timestampMs === undefined && remaining <= minRemainingSeconds) {
    waitedMs = (remaining + 0.5) * 1000;
    await new Promise(resolve => setTimeout(resolve, waitedMs));
    effectiveNow = Date.now();
  }

  const code = await generateTotp(secret, {
    timestampMs: effectiveNow,
    timeStepSeconds,
    digits
  });

  return {
    code,
    remainingSeconds: getTotpRemainingSeconds(effectiveNow, timeStepSeconds),
    waitedMs
  };
}

/**
 * Injectable TOTP service implementing `TotpGeneratorPort`.
 */
export class TotpService implements TotpGeneratorPort {
  public cleanSecret(input: string): string {
    return cleanTotpSecret(input);
  }

  public isValidSecret(input: string): boolean {
    return isValidTotpSecret(input);
  }

  public decodeBase32(base32Str: string): Uint8Array {
    return decodeBase32(base32Str);
  }

  public generate(secret: string, options?: TotpOptions): Promise<string> {
    return generateTotp(secret, options);
  }

  public generateStable(
    secret: string,
    options?: StableTotpOptions
  ): Promise<{ code: string; remainingSeconds: number; waitedMs: number }> {
    return generateStableTotp(secret, options);
  }

  public getRemainingSeconds(
    timestampMs?: number,
    timeStepSeconds?: number
  ): number {
    return getTotpRemainingSeconds(timestampMs, timeStepSeconds);
  }
}
