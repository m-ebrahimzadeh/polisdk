import type { IdentityId, UserIdentity } from '../domain/entities.js';
import type {
  AuthorizationDecision,
  AuthorizationServicePort
} from '../interfaces/authorization-port.js';
import type { UserIdentityRepositoryPort } from '../interfaces/storage-port.js';

export interface IncomingSubjectInfo {
  userId?: IdentityId | null;
  username?: string | null;
  displayName?: string | null;
  isPrivateChannel?: boolean;
  requireAdmin?: boolean;
}

export interface AuthMiddlewareOptions<TContext> {
  /**
   * Authorization service evaluating channel privacy and allowlist/admin membership.
   */
  authorization: AuthorizationServicePort;
  /**
   * Optional user identity repository to automatically provision/update authorized users.
   */
  userRepository?: UserIdentityRepositoryPort;
  /**
   * Extracts the `IncomingSubjectInfo` from the incoming framework context.
   * Return `null` or `undefined` if the event has no actor (e.g., system background event).
   */
  extractSubject: (ctx: TContext) => IncomingSubjectInfo | null | undefined;
  /**
   * Optional callback invoked when access is denied.
   */
  onDenied?: (ctx: TContext, decision: AuthorizationDecision) => Promise<void> | void;
  /**
   * Optional callback invoked after the user identity is provisioned/updated.
   */
  onAuthorized?: (ctx: TContext, user?: UserIdentity) => Promise<void> | void;
}

export type NextFunction = () => Promise<void>;

/**
 * Creates a framework-agnostic authentication, authorization, and identity-provisioning
 * middleware function.
 */
export function createAuthMiddleware<TContext>(
  options: AuthMiddlewareOptions<TContext>
): (ctx: TContext, next: NextFunction) => Promise<void> {
  return async (ctx: TContext, next: NextFunction): Promise<void> => {
    const info = options.extractSubject(ctx);
    if (!info) {
      return;
    }

    const decision = options.authorization.evaluateChannelAndUserAccess({
      userId: info.userId,
      isPrivateChannel: info.isPrivateChannel,
      requireAdmin: info.requireAdmin
    });

    if (!decision.allowed) {
      if (options.onDenied) {
        await options.onDenied(ctx, decision);
      }
      return;
    }

    let provisionedUser: UserIdentity | undefined;
    if (options.userRepository && info.userId !== undefined && info.userId !== null) {
      provisionedUser = await options.userRepository.ensureUser(info.userId, {
        username: info.username ?? null,
        displayName: info.displayName ?? null
      });
    }

    if (options.onAuthorized) {
      await options.onAuthorized(ctx, provisionedUser);
    }

    await next();
  };
}
