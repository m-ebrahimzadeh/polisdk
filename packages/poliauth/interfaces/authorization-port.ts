/**
 * @module @polisdk/poliauth/interfaces/authorization-port
 * Segregated Access Control and Resource Authorization Ports.
 */

import type { AuthSubject, IdentityId } from '../domain/entities.js';
import type { MaybePromise } from './maybe-promise.js';

export type DenialReasonCode =
  | 'NON_PRIVATE_CHANNEL'
  | 'UNAUTHENTICATED_SUBJECT'
  | 'NOT_IN_ALLOWLIST'
  | 'ADMIN_REQUIRED'
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
 * Request evaluated by `AccessEvaluatorPort`.
 */
export interface AccessEvaluationRequest {
  userId?: IdentityId | null;
  isPrivateChannel?: boolean;
  requireAdmin?: boolean;
}

/**
 * Pluggable policy port for evaluating resource-level ownership or access rights.
 */
export interface ResourceAuthorizationPolicyPort {
  isResourceAuthorized(userId: IdentityId, resource: ResourceDescriptor): MaybePromise<boolean>;
}

/**
 * Channel privacy + allowlist/admin access evaluation (the only role needed by middleware).
 */
export interface AccessEvaluatorPort {
  evaluateChannelAndUserAccess(request: AccessEvaluationRequest): AuthorizationDecision;
}

/**
 * Subject role queries.
 */
export interface SubjectRoleQueryPort {
  isUserAllowed(userId: IdentityId): boolean;
  isAdmin(userId: IdentityId): boolean;
}

/**
 * Resource-level authorization.
 */
export interface ResourceAuthorizerPort {
  authorizeResource(userId: IdentityId, resource: ResourceDescriptor): Promise<AuthorizationDecision>;
}

/**
 * Full authorization service contract (implemented by `AuthorizationService`).
 */
export interface AuthorizationServicePort
  extends AccessEvaluatorPort,
    SubjectRoleQueryPort,
    ResourceAuthorizerPort {}
