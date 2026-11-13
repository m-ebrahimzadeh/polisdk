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
  addScriptTag?(options: { content?: string; url?: string; path?: string }): Promise<unknown>;
}

function isTransientInjectionError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  if (
    /target closed|page has been closed|browser has been closed|context has been closed|has been closed/i.test(
      msg
    )
  ) {
    return false;
  }
  return /execution context was destroyed|most likely because of a navigation|cannot find context|frame was detached|navigating to|navigation in progress|interrupted by.*navigation/i.test(
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
      const bundleCode = getInjectedAuthAdapterBundleCode();
      try {
        await page.evaluate(bundleCode);
      } catch (evalErr) {
        if (isTransientInjectionError(evalErr) || typeof page.addScriptTag !== 'function') {
          throw evalErr;
        }
        safeLogger?.warn(
          `page.evaluate adapter injection failed (${redactSensitiveErrorText(evalErr)}); falling back to page.addScriptTag.`
        );
        await page.addScriptTag({ content: bundleCode });
      }
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
