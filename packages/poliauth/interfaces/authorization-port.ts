/**
 * @module @polisdk/poliauth/interfaces/authorization-port
 * Access Control and Resource Authorization Ports.
 */

import type { AuthSubject, IdentityId } from '../domain/entities';

export type DenialReasonCode =
  | 'NON_PRIVATE_CHANNEL'
  | 'UNAUTHENTICATED_SUBJECT'
  | 'NOT_IN_ALLOWLIST'
  | 'ADMIN_REQUIRED'
  | 'VAULT_NOT_CONFIGURED'
  | 'RESOURCE_FORBIDDEN';

export interface AuthorizationDecision {
  allowed: boolean;
  reasonCode?: DenialReasonCode;
  message?: string;
  subject?: AuthSubject;
}

export interface ResourceDescriptor {
  resourceType: string;
  resourceId: string;
  attributes?: Record<string, unknown>;
}

/**
 * Pluggable policy port for evaluating resource-level ownership or access rights
 * (e.g., verifying whether a user has access to a course or recording transferId).
 */
export interface ResourceAuthorizationPolicyPort {
  isResourceAuthorized(
    userId: IdentityId,
    resource: ResourceDescriptor
  ): Promise<boolean> | boolean;
}

/**
 * Port for evaluating subject and channel access control rules.
 */
export interface AuthorizationServicePort {
  isUserAllowed(userId: IdentityId): boolean;
  isAdmin(userId: IdentityId): boolean;
  evaluateChannelAndUserAccess(params: {
    userId?: IdentityId | null;
    isPrivateChannel?: boolean;
    requireAdmin?: boolean;
  }): AuthorizationDecision;
  authorizeResource(
    userId: IdentityId,
    resource: ResourceDescriptor
  ): Promise<AuthorizationDecision>;
}
