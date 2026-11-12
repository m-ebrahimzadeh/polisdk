/**
 * @module @polisdk/poliauth/interfaces/session-pool-port
 * Segregated Browser Session Context Pool Ports (Interface Segregation Principle).
 *
 * Clients depend only on the role they need:
 * - `SessionContextLeasePort`       — acquire/release per-user contexts and their primary page.
 * - `SessionContextPersistencePort` — persist a user's context state (cookies, storage origins).
 * - `SessionContextDisposalPort`    — destroy, evict, and close contexts (e.g. on logout/shutdown).
 * - `SessionPoolStatsPort`          — observability.
 * - `SessionContextPoolPort`        — the full pool contract implemented by adapters.
 */

import type { IdentityId } from '../domain/entities.js';

/**
 * Managed per-user browser session entry with reference-counted lock protection.
 */
export interface ManagedSessionContext<TContext = unknown, TPage = unknown> {
  userId: IdentityId;
  context: TContext;
  primaryPage: TPage | null;
  lastActiveAt: number;
  activeLocks: number;
}

export interface SessionPoolStats {
  activeContexts: number;
  busyContexts: number;
  browserConnected: boolean;
}

export interface SessionContextDisposalOptions {
  /** Skip persisting the context state before closing it. */
  skipSaveState?: boolean;
  /** Also remove the persisted (encrypted) session state for the user. */
  clearPersistedState?: boolean;
}

/**
 * Leasing of isolated, reference-counted per-user browser contexts.
 */
export interface SessionContextLeasePort<TContext = unknown, TPage = unknown> {
  acquireUserContext(userId: IdentityId): Promise<ManagedSessionContext<TContext, TPage>>;
  releaseUserContext(userId: IdentityId): void;
  getOrCreatePrimaryPage(managed: ManagedSessionContext<TContext, TPage>): Promise<TPage>;
}

/**
 * Persistence of a user's browser context state.
 */
export interface SessionContextPersistencePort {
  saveUserContextState(userId: IdentityId): Promise<void>;
}

/**
 * Disposal and lifecycle management of pooled browser contexts.
 */
export interface SessionContextDisposalPort {
  destroyUserContext(userId: IdentityId, options?: SessionContextDisposalOptions): Promise<void>;
  evictExpiredContexts(): Promise<void>;
  closeAll(): Promise<void>;
}

/**
 * Pool observability.
 */
export interface SessionPoolStatsPort {
  getStats(): SessionPoolStats;
}

/**
 * Full session pool contract: isolated, reference-counted per-user browser contexts
 * with idle TTL eviction and encrypted session state persistence.
 */
export interface SessionContextPoolPort<TContext = unknown, TPage = unknown>
  extends SessionContextLeasePort<TContext, TPage>,
    SessionContextPersistencePort,
    SessionContextDisposalPort,
    SessionPoolStatsPort {}
