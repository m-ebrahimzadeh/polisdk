/**
 * @module @polisdk/poliauth-chrome
 * Chrome Extension (`chrome.storage.local`) implementation of `VaultStoragePort`.
 */

import type { VaultStoragePort } from "@polisdk/poliauth";

export interface ChromeStorageAreaLike {
  get(keys: string | string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

/**
 * Resolve `chrome.storage.local` or fail clearly if invoked outside a Chrome extension context.
 */
function resolveDefaultChromeLocalStorage(): ChromeStorageAreaLike {
  const chromeObj = (globalThis as { chrome?: typeof chrome }).chrome;
  if (!chromeObj?.storage?.local) {
    throw new Error(
      "chrome.storage.local is not available in the current environment. Provide a custom ChromeStorageAreaLike instance.",
    );
  }
  return chromeObj.storage.local;
}

/**
 * `VaultStoragePort` backed by `chrome.storage.local` (or an injected compatible storage area).
 */
export class ChromeLocalVaultStorage implements VaultStoragePort {
  private readonly storageArea: ChromeStorageAreaLike;
  private readonly secretMaterial?: string;

  constructor(storageArea?: ChromeStorageAreaLike, secretMaterial?: string) {
    this.storageArea = storageArea ?? resolveDefaultChromeLocalStorage();
    this.secretMaterial = secretMaterial;
  }

  async get(keys: string | string[]): Promise<Record<string, unknown>> {
    return this.storageArea.get(keys);
  }

  async set(items: Record<string, unknown>): Promise<void> {
    await this.storageArea.set(items);
  }

  async remove(keys: string | string[]): Promise<void> {
    await this.storageArea.remove(keys);
  }

  getSecretMaterial(): string | undefined {
    return this.secretMaterial;
  }
}
