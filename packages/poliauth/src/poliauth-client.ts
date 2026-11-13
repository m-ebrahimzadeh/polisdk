import {
  normalizeIdentityId,
  type IdentityId,
  type PoliAuthFailureClassification,
  type SavedVaultCredentials
} from '../domain/entities.js';
import { redactSecrets, redactSensitiveErrorText } from '../domain/redaction.js';
import { TotpService } from '../domain/totp.js';
import { OtpChallengeCoordinator } from '../application/otp-challenge.js';
import { CredentialSetupWizard } from '../application/credential-wizard.js';
import {
  AuthorizationService,
  type AuthorizationServiceOptions
} from '../application/authorization.js';
import {
  checkPreBrowserCircuitBreakerForIdentity,
  executeWithSingleflight,
  PoliAuthOrchestrator,
  resolveFederatedSingleflightKey,
  resolveUserSingleflightKey,
  type PoliAuthExecutionOptions,
  type PolimiSessionAuthRequest,
  type PolimiSessionAuthOutcome,
  type FederatedSamlAuthRequest,
  type FederatedSamlAuthOutcome
} from '../application/login-orchestrator.js';
import type {
  AuthPageDriverPort,
  FederatedAuthPageDriverPort,
  FederatedSsoPageDriverPort
} from '../interfaces/browser-driver-port.js';
import type { MaybePromise } from '../interfaces/maybe-promise.js';
import type { LoginProgressCallbacks } from '../interfaces/otp-provider-port.js';
import type {
  VaultStoragePort,
  UserVaultStorageFactoryPort,
  UserIdentityRepositoryPort
} from '../interfaces/storage-port.js';
import type {
  ManagedSessionContext,
  SessionContextPoolPort
} from '../interfaces/session-pool-port.js';
import type { AuthLoggerPort } from '../interfaces/logger-port.js';
import {
  EncryptedCredentialVault,
  type VaultCryptoOptions
} from '../storage/vault.js';
import { InMemoryUserIdentityRepository } from '../storage/memory-storage.js';
import { createRedactingLogger } from '../application/redacting-logger.js';

export type PoliAuthDriverFactory<TContext = unknown, TPage = unknown> = (
  page: TPage,
  managedContext: ManagedSessionContext<TContext, TPage>
) => MaybePromise<AuthPageDriverPort | FederatedAuthPageDriverPort>;

export type PoliAuthSessionCredentials = PolimiSessionAuthRequest['credentials'];

export type PoliAuthClientSessionRequest = Omit<
  PolimiSessionAuthRequest,
  'driver' | 'credentials'
> & {
  /**
   * Optional pre-leased page driver. When omitted, `PoliAuth` leases a user context from
   * `sessionPool` and constructs a driver via `driverFactory` under per-user singleflight
   * deduplication.
   */
  driver?: AuthPageDriverPort;
  /**
   * Optional explicit credentials. When omitted, credentials are loaded from the
   * encrypted vault for `userId`.
   */
  credentials?: PoliAuthSessionCredentials;
};

export type PoliAuthClientFederatedSamlRequest = Omit<
  FederatedSamlAuthRequest,
  'driver' | 'credentials'
> & {
  /**
   * Optional pre-leased federated driver. When omitted, `PoliAuth` leases a user context
   * from `sessionPool` and constructs a driver via `driverFactory` under per-user
   * singleflight deduplication.
   */
  driver?: FederatedSamlAuthRequest['driver'];
  /**
   * Optional explicit credentials. When omitted, credentials are loaded from the
   * encrypted vault for `userId`.
   */
  credentials?: FederatedSamlAuthRequest['credentials'];
  /**
   * Optional federated Service Provider identifier used for singleflight scoping when
   * `entryUrl` and `driver` are omitted.
   */
  federatedProviderId?: string;
};

export interface PoliAuthConfig<TContext = unknown, TPage = unknown> {
  /**
   * Single-tenant storage backend (defaults to `InMemoryVaultStorage` / `localStorage`).
   */
  storage?: VaultStoragePort;
  /**
   * Multi-tenant per-user storage factory.
   */
  userStorageFactory?: UserVaultStorageFactoryPort;
  /**
   * Optional crypto options (such as a master encryption key).
   */
  cryptoOptions?: VaultCryptoOptions;
  /**
   * Optional user identity repository (defaults to `InMemoryUserIdentityRepository`).
   */
  userRepository?: UserIdentityRepositoryPort;
  /**
   * Alias for `userRepository` used for orchestrator/wizard circuit-breaker wiring.
   */
  identityRepository?: UserIdentityRepositoryPort;
  /**
   * Optional browser session pool (`SessionContextPoolPort`).
   */
  sessionPool?: SessionContextPoolPort<TContext, TPage>;
  /**
   * Optional factory adapting a pooled page + context into an `AuthPageDriverPort`
   * (or `FederatedAuthPageDriverPort`) when `authenticate` / `authenticateFederatedSaml`
   * is called without an explicit `driver`.
   */
  driverFactory?: PoliAuthDriverFactory<TContext, TPage>;
  /**
   * Alias for `driverFactory`.
   */
  createPageDriver?: PoliAuthDriverFactory<TContext, TPage>;
  /**
   * Enable per-user singleflight deduplication across concurrent authentication calls.
   * Default: `true`.
   */
  enableSingleflight?: boolean;
  /**
   * Probe existing/restored sessions via `sessionProbeUrl` before initiating full
   * multi-stage IdP login. Pool-managed calls automatically probe whenever a restored
   * `storageState` / session is detected unless explicitly set to `false`.
   */
  enablePreHydrationSessionProbe?: boolean;
  /**
   * Optional custom Tier 1 session probe URL.
   * Defaults to `DEFAULT_POLIMI_SESSION_PROBE_URL`.
   */
  sessionProbeUrl?: string;
  /**
   * Optional RBAC & allowlist configuration.
   */
  authorizationOptions?: AuthorizationServiceOptions;
  /**
   * Optional structured logger (automatically wrapped with secret redaction).
   */
  logger?: AuthLoggerPort;
}

/**
 * Unified facade and Dependency Injection container for the `@polisdk/poliauth` core library.
 */
type PreBrowserFailureOutcome = {
  ok: false;
  status: 'reauth_required' | 'failed';
  error: string;
  classification: PoliAuthFailureClassification;
  reauthRequired: boolean;
};

type PreBrowserCredentialsResult<TCreds> =
  | { ok: true; credentials: TCreds }
  | { ok: false; outcome: PreBrowserFailureOutcome };

async function hasManagedRestoredSessionState<TContext, TPage>(
  managed: ManagedSessionContext<TContext, TPage>,
  logger?: AuthLoggerPort
): Promise<boolean> {
  const candidate = managed as ManagedSessionContext<TContext, TPage> & {
    hasRestoredSessionState?: unknown;
  };
  if (typeof candidate.hasRestoredSessionState === 'boolean') {
    return candidate.hasRestoredSessionState;
  }
  const ctx = managed.context as
    | {
        restoredState?: unknown;
        storageState?: () => Promise<unknown>;
      }
    | null
    | undefined;
  if (ctx?.restoredState && typeof ctx.restoredState === 'object') {
    const cookies = (ctx.restoredState as { cookies?: unknown }).cookies;
    return Array.isArray(cookies) ? cookies.length > 0 : true;
  }
  if (typeof ctx?.storageState === 'function') {
    try {
      const state = await ctx.storageState();
      if (state && typeof state === 'object') {
        const cookies = (state as { cookies?: unknown }).cookies;
        if (Array.isArray(cookies)) {
          return cookies.length > 0;
        }
      }
    } catch (err) {
      logger?.debug(
        'Unable to inspect BrowserContext storageState during pre-hydration check.',
        redactSensitiveErrorText(err)
      );
    }
  }
  return false;
}

export class PoliAuth<TContext = unknown, TPage = unknown> {
  public readonly vault: EncryptedCredentialVault;
  public readonly totp: TotpService;
  public readonly otpChallenge: OtpChallengeCoordinator;
  public readonly wizard: CredentialSetupWizard;
  public readonly orchestrator: PoliAuthOrchestrator;
  public readonly authorization: AuthorizationService;
  public readonly users: UserIdentityRepositoryPort;
  public readonly sessionPool?: SessionContextPoolPort<TContext, TPage>;
  public readonly logger?: AuthLoggerPort;
  private readonly driverFactory?: PoliAuthDriverFactory<TContext, TPage>;
  private readonly enableSingleflight: boolean;
  private readonly enablePreHydrationSessionProbe?: boolean;
  private readonly sessionProbeUrl?: string;
  private readonly facadeInFlightAuth = new Map<string, Promise<PolimiSessionAuthOutcome>>();
  private readonly facadeInFlightFederatedAuth = new Map<
    string,
    Promise<FederatedSamlAuthOutcome>
  >();
  private readonly hasUserFactory: boolean;
  private readonly hasExplicitUserRepository: boolean;

  constructor(config: PoliAuthConfig<TContext, TPage> = {}) {
    this.logger = config.logger ? createRedactingLogger(config.logger) : undefined;
    const configuredUsers = config.identityRepository ?? config.userRepository;
    this.hasUserFactory = Boolean(config.userStorageFactory);
    this.hasExplicitUserRepository = Boolean(configuredUsers);
    this.enableSingleflight = config.enableSingleflight ?? true;
    this.enablePreHydrationSessionProbe = config.enablePreHydrationSessionProbe;
    this.sessionProbeUrl = config.sessionProbeUrl;
    this.driverFactory = config.driverFactory ?? config.createPageDriver;
    this.totp = new TotpService();
    this.otpChallenge = new OtpChallengeCoordinator({ totpGenerator: this.totp });
    this.users = configuredUsers ?? new InMemoryUserIdentityRepository();
    this.wizard = new CredentialSetupWizard({
      identityRepository: this.users,
      logger: this.logger
    });
    this.orchestrator = new PoliAuthOrchestrator({
      otpCoordinator: this.otpChallenge,
      logger: this.logger,
      identityRepository: this.users,
      enableSingleflight: this.enableSingleflight,
      ...(config.enablePreHydrationSessionProbe !== undefined
        ? { enablePreHydrationSessionProbe: config.enablePreHydrationSessionProbe }
        : {}),
      ...(config.sessionProbeUrl !== undefined
        ? { sessionProbeUrl: config.sessionProbeUrl }
        : {})
    });
    this.authorization = new AuthorizationService(config.authorizationOptions);
    this.sessionPool = config.sessionPool;
    this.vault = new EncryptedCredentialVault({
      storage: config.storage,
      userFactory: config.userStorageFactory,
      cryptoOptions: config.cryptoOptions
        ? { ...config.cryptoOptions, logger: this.logger }
        : { logger: this.logger }
    });
  }

  /**
   * Returns `true` if `userId` has an active in-flight login operation in either the
   * facade session-pool singleflight registry or the underlying orchestrator.
   */
  public isUserAuthenticationInFlight(userId: IdentityId): boolean {
    const userKey = resolveUserSingleflightKey(userId);
    if (!userKey) {
      return false;
    }
    if (this.facadeInFlightAuth.has(userKey)) {
      return true;
    }
    const federatedPrefix = `${userKey}::federated::`;
    for (const key of this.facadeInFlightFederatedAuth.keys()) {
      if (key.startsWith(federatedPrefix)) {
        return true;
      }
    }
    return this.orchestrator.isUserAuthenticationInFlight(userId);
  }

  private assertPoolPrerequisites(
    methodName: string,
    userId: IdentityId | undefined
  ): {
    pool: SessionContextPoolPort<TContext, TPage>;
    driverFactory: PoliAuthDriverFactory<TContext, TPage>;
  } {
    if (
      userId === undefined ||
      userId === null ||
      normalizeIdentityId(userId).length === 0
    ) {
      throw new Error(`${methodName} requires a non-empty userId when driver is omitted.`);
    }
    if (!this.sessionPool) {
      throw new Error(
        `${methodName} requires sessionPool in PoliAuthConfig when driver is omitted.`
      );
    }
    if (!this.driverFactory) {
      throw new Error(
        `${methodName} requires driverFactory (or createPageDriver) in PoliAuthConfig when driver is omitted.`
      );
    }
    return { pool: this.sessionPool, driverFactory: this.driverFactory };
  }

  private async resolvePreBrowserAndCredentials(
    userId: IdentityId,
    explicitCredentials: PolimiSessionAuthRequest['credentials'] | undefined,
    requirePersonCodeAndPassword: true,
    callbacks?: LoginProgressCallbacks
  ): Promise<PreBrowserCredentialsResult<PolimiSessionAuthRequest['credentials']>>;
  private async resolvePreBrowserAndCredentials(
    userId: IdentityId,
    explicitCredentials: FederatedSamlAuthRequest['credentials'] | undefined,
    requirePersonCodeAndPassword: false,
    callbacks?: LoginProgressCallbacks
  ): Promise<PreBrowserCredentialsResult<FederatedSamlAuthRequest['credentials']>>;
  private async resolvePreBrowserAndCredentials(
    userId: IdentityId,
    explicitCredentials:
      | PolimiSessionAuthRequest['credentials']
      | FederatedSamlAuthRequest['credentials']
      | undefined,
    requirePersonCodeAndPassword: boolean,
    callbacks?: LoginProgressCallbacks
  ): Promise<
    PreBrowserCredentialsResult<
      PolimiSessionAuthRequest['credentials'] | FederatedSamlAuthRequest['credentials']
    >
  > {
    const breakerReason = await checkPreBrowserCircuitBreakerForIdentity(
      this.users,
      userId,
      this.logger
    );
    if (breakerReason) {
      await callbacks?.onStatusChange?.('reauth_required', breakerReason);
      return {
        ok: false,
        outcome: {
          ok: false,
          status: 'reauth_required',
          error: breakerReason,
          classification: 'AUTHENTICATION_REJECTED',
          reauthRequired: true
        }
      };
    }

    if (explicitCredentials !== undefined) {
      if (requirePersonCodeAndPassword) {
        if (!explicitCredentials.personCode?.trim() || !explicitCredentials.password) {
          const error =
            'Person Code and Password are required to sign in on aunicalogin.polimi.it.';
          await callbacks?.onStatusChange?.('failed', error);
          return {
            ok: false,
            outcome: {
              ok: false,
              status: 'failed',
              error,
              classification: 'AUTHENTICATION_REJECTED',
              reauthRequired: false
            }
          };
        }
        return {
          ok: true,
          credentials: {
            ...explicitCredentials,
            personCode: explicitCredentials.personCode,
            password: explicitCredentials.password
          }
        };
      }
      return { ok: true, credentials: explicitCredentials };
    }

    if (
      userId === undefined ||
      userId === null ||
      normalizeIdentityId(userId).length === 0
    ) {
      const error = 'userId is required to load stored PoliMi credentials.';
      await callbacks?.onStatusChange?.('failed', error);
      return {
        ok: false,
        outcome: {
          ok: false,
          status: 'failed',
          error,
          classification: 'AUTHENTICATION_REJECTED',
          reauthRequired: false
        }
      };
    }

    const loaded = await this.loadCredentials(userId);
    if (!loaded || !loaded.personCode?.trim() || !loaded.password) {
      const error = `No complete stored PoliMi credentials found for user ${normalizeIdentityId(userId)}.`;
      await callbacks?.onStatusChange?.('failed', error);
      return {
        ok: false,
        outcome: {
          ok: false,
          status: 'failed',
          error,
          classification: 'AUTHENTICATION_REJECTED',
          reauthRequired: false
        }
      };
    }

    return { ok: true, credentials: loaded };
  }

  private async runPooledWithSingleflight<
    TCreds extends PolimiSessionAuthRequest['credentials'] | FederatedSamlAuthRequest['credentials'],
    TOutcome extends { ok: boolean }
  >(params: {
    methodName: string;
    flow: 'polimi' | 'federated_saml';
    userId: IdentityId;
    resolvePreflight: () => Promise<PreBrowserCredentialsResult<TCreds>>;
    registry: Map<string, Promise<TOutcome>>;
    singleflightKey: string | null;
    targetKey?: string;
    options?: PoliAuthExecutionOptions;
    runWithDriver: (
      driver: AuthPageDriverPort | FederatedAuthPageDriverPort,
      resolvedCredentials: TCreds,
      managed: ManagedSessionContext<TContext, TPage>
    ) => Promise<TOutcome>;
  }): Promise<TOutcome> {
    const { pool, driverFactory } = this.assertPoolPrerequisites(
      params.methodName,
      params.userId
    );
    const useSingleflight = params.options?.enableSingleflight ?? this.enableSingleflight;

    return executeWithSingleflight({
      registry: params.registry,
      key: params.singleflightKey,
      enabled: useSingleflight,
      onJoin: () => {
        const joinMeta: Record<string, unknown> = {
          scope: 'facade',
          flow: params.flow,
          userId: normalizeIdentityId(params.userId)
        };
        if (params.targetKey !== undefined) {
          joinMeta.target = redactSecrets(params.targetKey);
        }
        this.logger?.info(`Joining existing in-flight ${params.methodName}.`, joinMeta);
      },
      execute: async () => {
        const preflight = await params.resolvePreflight();
        if (!preflight.ok) {
          return preflight.outcome as unknown as TOutcome;
        }

        const managed = await pool.acquireUserContext(params.userId);
        try {
          const page = await pool.getOrCreatePrimaryPage(managed);
          const driver = await driverFactory(page, managed);
          const outcome = await params.runWithDriver(driver, preflight.credentials, managed);
          if (outcome.ok) {
            await pool.saveUserContextState(params.userId);
          }
          return outcome;
        } finally {
          await pool.releaseUserContext(params.userId);
        }
      }
    });
  }

  /**
   * Executes the Politecnico di Milano authentication state machine until an
   * authenticated PoliMi session is established.
   *
   * - When `request.driver` is provided, delegates directly to `PoliAuthOrchestrator.authenticate`
   *   without touching `sessionPool`.
   * - When `request.driver` is omitted, deduplicates concurrent calls per `userId` around the full
   *   `sessionPool` lease lifecycle (`reauth_required` pre-check -> vault load -> `acquireUserContext` ->
   *   `getOrCreatePrimaryPage` -> `driverFactory` -> `orchestrator.authenticate` ->
   *   `saveUserContextState` -> `releaseUserContext`).
   */
  async authenticate(
    request: PoliAuthClientSessionRequest,
    options?: PoliAuthExecutionOptions
  ): Promise<PolimiSessionAuthOutcome> {
    if (request.driver) {
      if (request.credentials !== undefined) {
        return this.orchestrator.authenticate(
          {
            ...request,
            driver: request.driver,
            credentials: request.credentials
          },
          options
        );
      }

      const preflight = await this.resolvePreBrowserAndCredentials(
        request.userId,
        request.credentials,
        true,
        request.callbacks
      );
      if (!preflight.ok) {
        return preflight.outcome;
      }

      return this.orchestrator.authenticate(
        {
          ...request,
          driver: request.driver,
          credentials: preflight.credentials
        },
        options
      );
    }

    const key = resolveUserSingleflightKey(request.userId, request.credentials?.personCode);
    return this.runPooledWithSingleflight({
      methodName: 'PoliAuth.authenticate',
      flow: 'polimi',
      userId: request.userId,
      resolvePreflight: () =>
        this.resolvePreBrowserAndCredentials(
          request.userId,
          request.credentials,
          true,
          request.callbacks
        ),
      registry: this.facadeInFlightAuth,
      singleflightKey: key,
      options,
      runWithDriver: async (driver, credentials, managed) => {
        const hasRestoredSession = await hasManagedRestoredSessionState(managed, this.logger);
        const probeExistingSession =
          request.probeExistingSession ??
          options?.enablePreHydrationSessionProbe ??
          this.enablePreHydrationSessionProbe ??
          hasRestoredSession;
        const resolvedProbeUrl =
          request.sessionProbeUrl ?? options?.sessionProbeUrl ?? this.sessionProbeUrl;
        return this.orchestrator.authenticate(
          {
            ...request,
            credentials,
            driver,
            probeExistingSession,
            ...(resolvedProbeUrl !== undefined ? { sessionProbeUrl: resolvedProbeUrl } : {})
          },
          options
        );
      }
    });
  }

  /**
   * Executes the multi-hop Federated SAML 2.0 SSO flow.
   *
   * - When `request.driver` is provided, delegates directly to
   *   `PoliAuthOrchestrator.authenticateFederatedSaml` without touching `sessionPool`.
   * - When `request.driver` is omitted, deduplicates concurrent calls per `userId` and federated
   *   target around the `sessionPool` context lease lifecycle.
   */
  async authenticateFederatedSaml(
    request: PoliAuthClientFederatedSamlRequest,
    options?: PoliAuthExecutionOptions
  ): Promise<FederatedSamlAuthOutcome> {
    if (request.driver) {
      if (request.credentials !== undefined) {
        return this.orchestrator.authenticateFederatedSaml(
          {
            ...request,
            driver: request.driver,
            credentials: request.credentials
          },
          options
        );
      }

      const preflight = await this.resolvePreBrowserAndCredentials(
        request.userId,
        request.credentials,
        false,
        request.callbacks
      );
      if (!preflight.ok) {
        return preflight.outcome;
      }

      return this.orchestrator.authenticateFederatedSaml(
        {
          ...request,
          driver: request.driver,
          credentials: preflight.credentials
        },
        options
      );
    }

    const targetKey =
      request.entryUrl?.trim() || request.federatedProviderId?.trim() || 'default';
    const key = resolveFederatedSingleflightKey(
      request.userId,
      request.credentials?.personCode,
      request.entryUrl,
      request.federatedProviderId
    );
    return this.runPooledWithSingleflight({
      methodName: 'PoliAuth.authenticateFederatedSaml',
      flow: 'federated_saml',
      userId: request.userId,
      resolvePreflight: () =>
        this.resolvePreBrowserAndCredentials(
          request.userId,
          request.credentials,
          false,
          request.callbacks
        ),
      registry: this.facadeInFlightFederatedAuth,
      singleflightKey: key,
      targetKey,
      options,
      runWithDriver: (driver, credentials) =>
        this.orchestrator.authenticateFederatedSaml(
          {
            ...request,
            credentials,
            driver: driver as
              | FederatedAuthPageDriverPort
              | (AuthPageDriverPort & Partial<FederatedSsoPageDriverPort>)
          },
          options
        )
    });
  }

  /**
   * Saves encrypted credentials for a user or single-tenant context, resetting any
   * `reauth_required` / `failed` circuit-breaker state back to `idle`.
   */
  async saveCredentials(
    creds: Partial<SavedVaultCredentials>,
    identityId?: IdentityId,
    secretOverride?: string
  ): Promise<SavedVaultCredentials> {
    const saved = await this.vault.saveCredentials(creds, identityId, secretOverride);
    if (identityId !== undefined) {
      const existing = await this.users.getUser(identityId);
      if (
        existing &&
        (existing.loginStatus === 'reauth_required' ||
          existing.loginStatus === 'failed' ||
          existing.loginError !== null)
      ) {
        await this.users.updateLoginStatus(identityId, 'idle', null);
      }
    }
    return saved;
  }

  /**
   * Loads decrypted credentials for a user or single-tenant context.
   */
  async loadCredentials(
    identityId?: IdentityId,
    secretOverride?: string
  ): Promise<SavedVaultCredentials | null> {
    return this.vault.loadCredentials(identityId, secretOverride);
  }

  /**
   * Terminates an active session and/or purges stored credentials for a user.
   */
  async logout(
    identityId?: IdentityId,
    options: { clearCredentials?: boolean; clearSessionState?: boolean } = {
      clearCredentials: true,
      clearSessionState: true
    }
  ): Promise<void> {
    if (identityId !== undefined) {
      this.wizard.cancelSession(identityId);
      this.otpChallenge.cancelPendingOtpWaiter(identityId, 'User logged out.');
      this.users.updateLoginStatus(identityId, 'idle', null);
    }

    const skipSharedSingleStorageWipe =
      identityId !== undefined && !this.hasUserFactory && this.hasExplicitUserRepository;

    if (options.clearCredentials !== false && !skipSharedSingleStorageWipe) {
      await this.vault.clearCredentials(identityId);
    }

    if (options.clearSessionState !== false) {
      if (!skipSharedSingleStorageWipe) {
        await this.vault.clearSessionState(identityId);
      }
      if (identityId !== undefined && this.sessionPool) {
        await this.sessionPool.destroyUserContext(identityId, {
          skipSaveState: true
        });
      }
    }
  }
}
