/**
 * @module @polisdk/poliauth/adapters/federated-sso-provider-registry
 * Registry of pluggable federated SAML Service Provider adapters.
 */

import type {
  FederatedSsoProviderAdapterPort,
  FederatedSsoProviderResolverPort
} from '../interfaces/federated-sso-provider-port.js';
import { WebexSamlProviderAdapter } from './webex-sso-dom-adapter.js';

function normalizeProviderId(providerId: string): string {
  return providerId.trim().toLowerCase();
}

/**
 * In-memory registry mapping `providerId` -> `FederatedSsoProviderAdapterPort`.
 *
 * Registering a new provider never requires changes to core ports, drivers, or the
 * orchestrator (Open/Closed Principle).
 */
export class FederatedSsoProviderRegistry implements FederatedSsoProviderResolverPort {
  private readonly providers = new Map<string, FederatedSsoProviderAdapterPort>();

  constructor(providers: Iterable<FederatedSsoProviderAdapterPort> = []) {
    for (const provider of providers) {
      this.register(provider);
    }
  }

  /**
   * Registers a provider. Throws if another provider already uses the same `providerId`
   * unless `options.replace` is `true`.
   */
  register(provider: FederatedSsoProviderAdapterPort, options: { replace?: boolean } = {}): this {
    const key = normalizeProviderId(provider.providerId);
    if (!key) {
      throw new Error('Federated SSO provider must declare a non-empty providerId.');
    }
    if (this.providers.has(key) && !options.replace) {
      throw new Error(`Federated SSO provider "${key}" is already registered.`);
    }
    this.providers.set(key, provider);
    return this;
  }

  unregister(providerId: string): boolean {
    return this.providers.delete(normalizeProviderId(providerId));
  }

  has(providerId: string): boolean {
    return this.providers.has(normalizeProviderId(providerId));
  }

  resolve(providerId: string): FederatedSsoProviderAdapterPort | undefined {
    return this.providers.get(normalizeProviderId(providerId));
  }

  /**
   * Resolves a provider or throws a descriptive error listing the registered providers.
   */
  require(providerId: string): FederatedSsoProviderAdapterPort {
    const provider = this.resolve(providerId);
    if (!provider) {
      const known = this.providerIds().join(', ') || 'none';
      throw new Error(
        `Unknown federated SSO provider "${providerId}". Registered providers: ${known}.`
      );
    }
    return provider;
  }

  providerIds(): string[] {
    return Array.from(this.providers.keys());
  }

  list(): FederatedSsoProviderAdapterPort[] {
    return Array.from(this.providers.values());
  }
}

/**
 * Creates a registry pre-populated with the federated SAML providers bundled in
 * `@polisdk/poliauth` (currently `WebexSamlProviderAdapter`).
 */
export function createDefaultFederatedSsoProviderRegistry(): FederatedSsoProviderRegistry {
  return new FederatedSsoProviderRegistry([new WebexSamlProviderAdapter()]);
}
