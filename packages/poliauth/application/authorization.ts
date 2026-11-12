/**
 * @module @polisdk/poliauth/application/authorization
 * Access Control, Allowlist/Admin RBAC, and Pluggable Resource Authorization Service (Application Layer).
 */

import {
  normalizeIdentityId,
  type AuthSubject,
  type IdentityId
} from '../domain/entities.js';
import type {
  AuthorizationDecision,
  AuthorizationServicePort,
  ResourceAuthorizationPolicyPort,
  ResourceDescriptor
} from '../interfaces/authorization-port.js';

export interface AuthorizationServiceOptions {
  /**
   * Optional allowlist of authorized user IDs.
   * When empty, any user who authenticates with valid PoliMi credentials is allowed.
   */
  allowedUserIds?: Iterable<IdentityId>;
  /**
   * Optional set of administrator user IDs (always allowed even if `allowedUserIds` is non-empty).
   */
  adminUserIds?: Iterable<IdentityId>;
  /**
   * Whether non-private channels should be rejected by default.
   * Default: `true`.
   */
  enforcePrivateChannel?: boolean;
  /**
   * Optional resource-level authorization policy.
   */
  resourcePolicy?: ResourceAuthorizationPolicyPort;
}

export class AuthorizationService implements AuthorizationServicePort {
  private readonly allowedUserIds = new Set<string>();
  private readonly adminUserIds = new Set<string>();
  private readonly enforcePrivateChannel: boolean;
  private resourcePolicy?: ResourceAuthorizationPolicyPort;

  constructor(options: AuthorizationServiceOptions = {}) {
    if (options.allowedUserIds) {
      for (const id of options.allowedUserIds) {
        this.allowedUserIds.add(normalizeIdentityId(id));
      }
    }
    if (options.adminUserIds) {
      for (const id of options.adminUserIds) {
        this.adminUserIds.add(normalizeIdentityId(id));
      }
    }
    this.enforcePrivateChannel = options.enforcePrivateChannel ?? true;
    this.resourcePolicy = options.resourcePolicy;
  }

  public setResourcePolicy(policy: ResourceAuthorizationPolicyPort): void {
    this.resourcePolicy = policy;
  }

  public isAdmin(userId: IdentityId): boolean {
    return this.adminUserIds.has(normalizeIdentityId(userId));
  }

  public isUserAllowed(userId: IdentityId): boolean {
    const key = normalizeIdentityId(userId);
    if (this.adminUserIds.has(key)) {
      return true;
    }
    if (this.allowedUserIds.size === 0) {
      return true;
    }
    return this.allowedUserIds.has(key);
  }

  public evaluateChannelAndUserAccess(params: {
    userId?: IdentityId | null;
    isPrivateChannel?: boolean;
    requireAdmin?: boolean;
  }): AuthorizationDecision {
    const isPrivate = params.isPrivateChannel ?? true;

    if (this.enforcePrivateChannel && !isPrivate) {
      return {
        allowed: false,
        reasonCode: 'NON_PRIVATE_CHANNEL',
        message:
          'PoliAuth only operates in private direct channels to protect student credentials.'
      };
    }

    if (
      params.userId === undefined ||
      params.userId === null ||
      String(params.userId).trim() === ''
    ) {
      return {
        allowed: false,
        reasonCode: 'UNAUTHENTICATED_SUBJECT',
        message: 'Missing user identity on request.'
      };
    }

    const userId = params.userId;
    const isAdmin = this.isAdmin(userId);
    const isAllowed = this.isUserAllowed(userId);

    const subject: AuthSubject = {
      userId,
      isAllowed,
      isAdmin,
      isPrivateChannel: isPrivate
    };

    if (!isAllowed) {
      return {
        allowed: false,
        reasonCode: 'NOT_IN_ALLOWLIST',
        message: `User ID (${userId}) is not on this server's allowlist.`,
        subject
      };
    }

    if (params.requireAdmin && !isAdmin) {
      return {
        allowed: false,
        reasonCode: 'ADMIN_REQUIRED',
        message: 'Administrator privileges are required for this action.',
        subject
      };
    }

    return {
      allowed: true,
      subject
    };
  }

  public async authorizeResource(
    userId: IdentityId,
    resource: ResourceDescriptor
  ): Promise<AuthorizationDecision> {
    if (!this.isUserAllowed(userId)) {
      return {
        allowed: false,
        reasonCode: 'NOT_IN_ALLOWLIST',
        message: `User ID (${userId}) is not authorized.`
      };
    }

    if (!this.resourcePolicy) {
      return { allowed: true };
    }

    const permitted = await this.resourcePolicy.isResourceAuthorized(
      userId,
      resource
    );
    if (!permitted) {
      return {
        allowed: false,
        reasonCode: 'RESOURCE_FORBIDDEN',
        message: `User ${userId} is not authorized to access ${resource.resourceType}:${resource.resourceId}.`
      };
    }

    return { allowed: true };
  }
}
