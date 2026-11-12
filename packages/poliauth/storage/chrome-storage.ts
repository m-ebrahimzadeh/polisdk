import type { VaultStoragePort } from '../interfaces/storage-port.js';

export interface ChromeStorageAreaLike {
  get(keys: string | string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

/**
 * `VaultStoragePort` backed by `chrome.storage.local` (or an injected `ChromeStorageAreaLike`).
 */
export class ChromeLocalVaultStorage implements VaultStoragePort {
  private readonly area: ChromeStorageAreaLike;

  constructor(area?: ChromeStorageAreaLike) {
    const resolved =
      area ??
      (typeof chrome !== 'undefined' && chrome?.storage?.local ? chrome.storage.local : undefined);
    if (!resolved) {
      throw new Error(
        'ChromeLocalVaultStorage requires chrome.storage.local or an explicit ChromeStorageAreaLike instance.'
      );
    }
    this.area = resolved;
  }

  async get(keys: string | string[]): Promise<Record<string, unknown>> {
    return await this.area.get(Array.isArray(keys) ? keys : [keys]);
  }

  async set(items: Record<string, unknown>): Promise<void> {
    await this.area.set(items);
  }

  async remove(keys: string | string[]): Promise<void> {
    await this.area.remove(Array.isArray(keys) ? keys : [keys]);
  }
}
