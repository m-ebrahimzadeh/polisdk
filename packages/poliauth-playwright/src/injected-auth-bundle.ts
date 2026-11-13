import type { AuthLoggerPort } from '@polisdk/poliauth/interfaces';
import { createRedactingLogger, redactSensitiveErrorText } from '@polisdk/poliauth/middleware';
import { INJECTED_AUTH_ADAPTER_BUNDLE_CODE } from './generated/injected-bundle-code.js';

/**
 * Minimal structural interface for a Playwright `Page` capable of evaluating scripts.
 */
export interface EvaluatablePageLike {
  evaluate<R, Arg = void>(
    pageFunction: ((arg: Arg) => R | Promise<R>) | string,
    arg?: Arg
  ): Promise<R>;
}

function isTransientInjectionError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /execution context was destroyed|most likely because of a navigation|cannot find context|frame was detached|target closed|navigation/i.test(
    msg
  );
}

/**
 * Returns the precompiled, self-contained IIFE JavaScript bundle that attaches
 * `window.__PoliAuthAdapters` inside a browser page context.
 */
export function getInjectedAuthAdapterBundleCode(): string {
  return INJECTED_AUTH_ADAPTER_BUNDLE_CODE;
}

/**
 * Ensures `window.__PoliAuthAdapters` is present on a Playwright `Page`.
 * Logs and safely returns `false` on transient execution-context destruction errors
 * while the page is mid-redirect so callers can retry once settled.
 */
export async function ensureAuthAdaptersInjected(
  page: EvaluatablePageLike,
  logger?: AuthLoggerPort
): Promise<boolean> {
  const safeLogger = logger ? createRedactingLogger(logger) : undefined;
  try {
    const hasAdapters = await page.evaluate(() => {
      return typeof window.__PoliAuthAdapters !== 'undefined';
    });

    if (!hasAdapters) {
      await page.evaluate(getInjectedAuthAdapterBundleCode());
    }
    return true;
  } catch (err) {
    const redacted = redactSensitiveErrorText(err);
    if (isTransientInjectionError(err)) {
      safeLogger?.warn(
        `Transient error injecting PoliAuth DOM adapters during page navigation; retrying once settled: ${redacted}`
      );
      return false;
    }
    safeLogger?.error(`Failed to inject PoliAuth DOM adapters: ${redacted}`);
    throw err;
  }
}
