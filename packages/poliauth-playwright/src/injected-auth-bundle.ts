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

/**
 * Returns the precompiled, self-contained IIFE JavaScript bundle that attaches
 * `window.__PoliAuthAdapters` inside a browser page context.
 */
export function getInjectedAuthAdapterBundleCode(): string {
  return INJECTED_AUTH_ADAPTER_BUNDLE_CODE;
}

/**
 * Ensures `window.__PoliAuthAdapters` is present on a Playwright `Page`.
 * Safely catches transient execution-context destruction errors if the page is mid-redirect.
 */
export async function ensureAuthAdaptersInjected(page: EvaluatablePageLike): Promise<void> {
  try {
    const hasAdapters = await page.evaluate(() => {
      return typeof window.__PoliAuthAdapters !== 'undefined';
    });

    if (!hasAdapters) {
      await page.evaluate(getInjectedAuthAdapterBundleCode());
    }
  } catch {
    // Page may be mid-navigation / SAML redirect; caller's retry loop will re-inject once settled.
  }
}
