import { describe, expect, it, vi } from 'vitest';
import {
  cleanTotpSecret,
  isValidTotpSecret,
  decodeBase32,
  generateTotp,
  generateStableTotp,
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

  it('matches official RFC 6238 SHA-1 test vectors (8 digits, 30s time step)', async () => {
    // ASCII "12345678901234567890" encoded as RFC 4648 Base32
    const rfc6238SecretBase32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    const vectors: Array<[number, string]> = [
      [59, '94287082'],
      [1_111_111_109, '07081804'],
      [1_111_111_111, '14050471'],
      [1_234_567_890, '89005924'],
      [2_000_000_000, '69279037'],
      [20_000_000_000, '65353130']
    ];

    for (const [epochSeconds, expectedCode] of vectors) {
      const code = await generateTotp(rfc6238SecretBase32, {
        timestampMs: epochSeconds * 1000,
        timeStepSeconds: 30,
        digits: 8
      });
      expect(code).toBe(expectedCode);
    }
  });

  it('waits for window rollover in generateStableTotp when <= 2s remain', async () => {
    vi.useFakeTimers();
    try {
      const secret = 'JBSWY3DPEHPK3PXP';
      // 29s into a 30s window -> 1s remaining (<= default minRemainingSeconds 2s)
      vi.setSystemTime(29_000);

      const expectedNextWindowCode = await generateTotp(secret, { timestampMs: 30_500 });
      const promise = generateStableTotp(secret, { minRemainingSeconds: 2 });

      await vi.advanceTimersByTimeAsync(1_500);
      const res = await promise;

      expect(res.waitedMs).toBe(1_500);
      expect(res.code).toBe(expectedNextWindowCode);
      expect(res.remainingSeconds).toBe(30);
    } finally {
      vi.useRealTimers();
    }
  });
});
