import type { IdentityId, SavedVaultCredentials } from '../domain/entities.js';
import { TotpService } from '../domain/totp.js';
import { OtpChallengeCoordinator } from '../domain/otp-challenge.js';
import { CredentialSetupWizard } from '../domain/credential-wizard.js';
import {
  AuthorizationService,
  type AuthorizationServiceOptions
} from '../domain/authorization.js';
import {
  PoliAuthOrchestrator,
  type PolimiSessionAuthRequest,
  type PolimiSessionAuthOutcome,
  type FederatedSamlAuthRequest,
  type FederatedSamlAuthOutcome
} from '../domain/login-orchestrator.js';
import type {
  VaultStoragePort,
  UserVaultStorageFactoryPort,
  UserIdentityRepositoryPort
} from '../interfaces/storage-port.js';
import type { SessionContextPoolPort } from '../interfaces/browser-driver-port.js';
import type { AuthLoggerPort } from '../interfaces/logger-port.js';
import {
  EncryptedCredentialVault,
  type VaultCryptoOptions
} from '../storage/vault.js';
import { InMemoryUserIdentityRepository } from '../storage/memory-storage.js';
import { createRedactingLogger } from '../middleware/redaction.js';

export interface PoliAuthConfig {
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
   * Optional browser session pool (`SessionContextPoolPort`).
   */
  sessionPool?: SessionContextPoolPort;
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
export class PoliAuth {
  public readonly vault: EncryptedCredentialVault;
  public readonly totp: TotpService;
  public readonly otpChallenge: OtpChallengeCoordinator;
  public readonly wizard: CredentialSetupWizard;
  public readonly orchestrator: PoliAuthOrchestrator;
  public readonly authorization: AuthorizationService;
  public readonly users: UserIdentityRepositoryPort;
  public readonly sessionPool?: SessionContextPoolPort;
  public readonly logger?: AuthLoggerPort;

  constructor(config: PoliAuthConfig = {}) {
    this.logger = config.logger ? createRedactingLogger(config.logger) : undefined;
    this.totp = new TotpService();
    this.otpChallenge = new OtpChallengeCoordinator({ totpGenerator: this.totp });
    this.wizard = new CredentialSetupWizard();
    this.orchestrator = new PoliAuthOrchestrator(this.otpChallenge);
    this.authorization = new AuthorizationService(config.authorizationOptions);
    this.users = config.userRepository ?? new InMemoryUserIdentityRepository();
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
   * Executes the Politecnico di Milano authentication state machine until an
   * authenticated PoliMi session is established.
   */
  async authenticate(
    request: PolimiSessionAuthRequest
  ): Promise<PolimiSessionAuthOutcome> {
    return this.orchestrator.authenticate(request);
  }

  /**
   * Executes the multi-hop Federated SAML 2.0 SSO flow.
   */
  async authenticateFederatedSaml(
    request: FederatedSamlAuthRequest
  ): Promise<FederatedSamlAuthOutcome> {
    return this.orchestrator.authenticateFederatedSaml(request);
  }

  /**
   * Saves encrypted credentials for a user or single-tenant context.
   */
  async saveCredentials(
    creds: Partial<SavedVaultCredentials>,
    identityId?: IdentityId,
    secretOverride?: string
  ): Promise<SavedVaultCredentials> {
    return this.vault.saveCredentials(creds, identityId, secretOverride);
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
    }

    if (options.clearCredentials !== false) {
      await this.vault.clearCredentials(identityId);
    }

    if (options.clearSessionState !== false) {
      await this.vault.clearSessionState(identityId);
      if (identityId !== undefined && this.sessionPool) {
        await this.sessionPool.destroyUserContext(identityId, {
          skipSaveState: true
        });
      }
    }
  }
}
