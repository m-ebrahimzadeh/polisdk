import { describe, expect, it } from 'vitest';
import {
  cleanTotpSecret,
  isValidTotpSecret,
  decodeBase32,
  generateTotp,
  getTotpRemainingSeconds,
  TotpService
} from '../domain/totp.js';

describe('TOTP Domain Service & Utilities', () => {
  it('cleans raw Base32 secrets and extracts secret from otpauth:// URIs', () => {
    expect(cleanTotpSecret('jbsw y3dp ehpk 3pxp')).toBe('JBSWY3DPEHPK3PXP');
    expect(
      cleanTotpSecret(
        'otpauth://totp/PoliMi:10987654?secret=jbswy3dpehpk3pxp&issuer=PoliMi&digits=6'
      )
    ).toBe('JBSWY3DPEHPK3PXP');
  });

  it('validates Base32 TOTP secrets accurately', () => {
    expect(isValidTotpSecret('JBSWY3DPEHPK3PXP')).toBe(true);
    expect(isValidTotpSecret('jbsw y3dp ehpk 3pxp')).toBe(true);
    expect(isValidTotpSecret('SHORT')).toBe(false);
    expect(isValidTotpSecret('INVALID_CHARS_1890!')).toBe(false);
  });

  it('decodes Base32 strings into exact byte arrays', () => {
    // "Hello!" in Base32 is JBSWY3DPEE======
    const decoded = decodeBase32('JBSWY3DPEE');
    const text = new TextDecoder().decode(decoded);
    expect(text).toBe('Hello!');
  });

  it('generates deterministic 6-digit TOTP codes for fixed timestamps', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const fixedTimeMs = 1_700_000_000_000;
    const code1 = await generateTotp(secret, { timestampMs: fixedTimeMs });
    const code2 = await generateTotp('jbsw y3dp ehpk 3pxp', { timestampMs: fixedTimeMs });

    expect(code1).toMatch(/^\d{6}$/);
    expect(code1).toBe(code2);

    // Same 30s window produces identical code
    const codeSameWindow = await generateTotp(secret, { timestampMs: fixedTimeMs + 1000 });
    expect(codeSameWindow).toBe(code1);
  });

  it('computes remaining seconds in a 30-second TOTP window', () => {
    // 1_700_000_010_000 ms = 1,700,000,010 s -> 1700000010 % 30 = 0 -> 30s remaining
    expect(getTotpRemainingSeconds(1_700_000_010_000, 30)).toBe(30);
    // +28 seconds into the window -> 2s remaining
    expect(getTotpRemainingSeconds(1_700_000_038_000, 30)).toBe(2);
    // +29 seconds into the window -> 1s remaining
    expect(getTotpRemainingSeconds(1_700_000_039_000, 30)).toBe(1);
  });

  it('generates stable TOTP code with remainingSeconds metadata via TotpService', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const fixedTimeMs = 1_700_000_015_000;
    const service = new TotpService();
    const res = await service.generateStable(secret, {
      timestampMs: fixedTimeMs,
      minRemainingSeconds: 2
    });
    expect(res.code).toMatch(/^\d{6}$/);
    expect(res.remainingSeconds).toBe(25);
    expect(res.waitedMs).toBe(0);
  });
});
