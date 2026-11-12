import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

let cachedBundleCode: string | null = null;

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
 * Returns the self-contained IIFE JavaScript bundle that attaches `window.__PoliAuthAdapters`
 * inside a browser page context.
 */
export function getInjectedAuthAdapterBundleCode(): string {
  if (cachedBundleCode) {
    return cachedBundleCode;
  }

  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const prebuiltCandidates = [
    path.resolve(currentDir, 'injected-auth-adapters.iife.js'),
    path.resolve(currentDir, '../dist/injected-auth-adapters.iife.js'),
    path.resolve(currentDir, '../../dist/injected-auth-adapters.iife.js')
  ];

  for (const candidate of prebuiltCandidates) {
    if (fs.existsSync(candidate)) {
      cachedBundleCode = fs.readFileSync(candidate, 'utf8');
      return cachedBundleCode;
    }
  }

  const sourceCandidates = [
    path.resolve(currentDir, 'injected-auth-entry.ts'),
    path.resolve(currentDir, '../adapters/injected-auth-entry.ts'),
    path.resolve(currentDir, '../../adapters/injected-auth-entry.ts')
  ];
  const entryPoint = sourceCandidates.find((p) => fs.existsSync(p));
  if (!entryPoint) {
    throw new Error(
      `Cannot locate injected-auth-entry.ts or prebuilt injected-auth-adapters.iife.js from ${currentDir}`
    );
  }

  const result = esbuild.buildSync({
    entryPoints: [entryPoint],
    bundle: true,
    write: false,
    format: 'iife',
    platform: 'browser',
    target: ['es2022']
  });

  cachedBundleCode = result.outputFiles[0].text;
  return cachedBundleCode;
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
