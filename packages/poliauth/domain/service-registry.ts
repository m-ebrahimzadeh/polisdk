/**
 * @module @polisdk/poliauth/domain/service-registry
 * Extensible Registry of Politecnico di Milano Online Services (`idServizio`).
 *
 * Allows any PoliSDK module (PoliRecord, PoliCareer, PoliWeBeep, PoliExams, etc.)
 * to authenticate through `aunicalogin.polimi.it` -> `servizionline.polimi.it`
 * and launch its target service without hardcoding service IDs in the auth engine.
 */

import { POLIMI_LOGIN_FLOW_SPEC } from './login-flow-spec';
import type { PolimiPageStage } from './entities';

export interface PolimiPortalServiceDescriptor {
  /** Unique PoliMi service ID (`id_servizio` / `idServizio`), e.g. `'2314'`. */
  serviceId: string;
  /** Human-readable name of the service. */
  name: string;
  /** CSS selectors used to locate the service link on `Portale.do`. */
  portalLinkSelectors: readonly string[];
  /** Case-insensitive link text substrings used as fallback matchers on `Portale.do`. */
  portalTextMatchers: readonly string[];
  /** URL pathname or hostname substrings that identify when the browser has landed on the service. */
  targetUrlSubstrings: readonly string[];
  /** Optional DOM selector that must be present to confirm the service page is fully loaded. */
  requiredDomSelector?: string;
  /** Stage name reported when this service is reached (`'archive'` or `'target_service'`). */
  stageName?: Extract<PolimiPageStage, 'archive' | 'target_service'>;
}

/**
 * Built-in Descriptor: PoliMi Recordings Archive (`idServizio=2314`).
 */
export const RECORDINGS_ARCHIVE_SERVICE: PolimiPortalServiceDescriptor = {
  serviceId: POLIMI_LOGIN_FLOW_SPEC.entry.recordingsArchiveServiceId,
  name: 'PoliMi Recordings Archive',
  portalLinkSelectors: POLIMI_LOGIN_FLOW_SPEC.portalPage.recordingArchivesLinkSelectors,
  portalTextMatchers: POLIMI_LOGIN_FLOW_SPEC.portalPage.recordingArchivesTextMatchers,
  targetUrlSubstrings: ['ArchivioListActivity.do'],
  requiredDomSelector: 'select[name="aa"]',
  stageName: 'archive'
};

/**
 * Built-in Descriptor: Online Services Portal (`id_servizio=376`).
 */
export const SERVIZI_ONLINE_PORTAL_SERVICE: PolimiPortalServiceDescriptor = {
  serviceId: POLIMI_LOGIN_FLOW_SPEC.entry.serviziOnlineServiceId,
  name: 'PoliMi Online Services Portal',
  portalLinkSelectors: [],
  portalTextMatchers: [],
  targetUrlSubstrings: ['servizionline.polimi.it/portaleservizi/'],
  stageName: 'target_service'
};

/**
 * Built-in Descriptor: WeBeep Learning Platform.
 */
export const WEBEEP_SERVICE: PolimiPortalServiceDescriptor = {
  serviceId: '2166',
  name: 'WeBeep Learning Platform',
  portalLinkSelectors: [
    'a.srv_link[href*="idServizio=2166"]',
    'a[href*="idServizio=2166"]'
  ],
  portalTextMatchers: ['webeep', 'bee-p'],
  targetUrlSubstrings: ['webeep.polimi.it'],
  stageName: 'target_service'
};

/**
 * Registry for looking up and registering PoliMi services across the PoliSDK platform.
 */
export class PolimiServiceRegistry {
  private readonly services = new Map<string, PolimiPortalServiceDescriptor>();

  constructor(initialServices: PolimiPortalServiceDescriptor[] = [
    RECORDINGS_ARCHIVE_SERVICE,
    SERVIZI_ONLINE_PORTAL_SERVICE,
    WEBEEP_SERVICE
  ]) {
    for (const s of initialServices) {
      this.register(s);
    }
  }

  public register(descriptor: PolimiPortalServiceDescriptor): void {
    this.services.set(descriptor.serviceId, descriptor);
  }

  public get(serviceId: string): PolimiPortalServiceDescriptor | undefined {
    return this.services.get(serviceId);
  }

  public listAll(): PolimiPortalServiceDescriptor[] {
    return Array.from(this.services.values());
  }
}

export const defaultServiceRegistry = new PolimiServiceRegistry();
