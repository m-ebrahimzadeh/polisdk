import { describe, expect, it } from 'vitest';
import { AuthorizationService } from '../domain/authorization.js';
import { createAuthMiddleware } from '../middleware/auth-middleware.js';
import { redactSecrets, createRedactingLogger } from '../middleware/redaction.js';
import { InMemoryUserIdentityRepository, InMemoryVaultStorage } from '../storage/memory-storage.js';
import { PoliAuth } from '../src/poliauth-client.js';

describe('AuthorizationService, Middleware, Secret Redaction & PoliAuth Facade', () => {
  it('enforces private channel guard, allowlist, admin roles, and pluggable resource ownership policies', async () => {
    const ownedResources = new Map<string, number>([
      ['doc-100', 1001],
      ['doc-200', 2002]
    ]);

    const authz = new AuthorizationService({
      allowedUserIds: [1001, 2002],
      adminUserIds: [9999],
      enforcePrivateChannel: true,
      resourcePolicy: {
        async isResourceAuthorized(userId, resource) {
          if (Number(userId) === 9999) return true;
          return ownedResources.get(String(resource.resourceId)) === Number(userId);
        }
      }
    });

    // Non-private channel denied even for allowlisted user
    const groupDecision = authz.evaluateChannelAndUserAccess({
      userId: 1001,
      isPrivateChannel: false
    });
    expect(groupDecision.allowed).toBe(false);
    expect(groupDecision.reasonCode).toBe('NON_PRIVATE_CHANNEL');

    // Non-allowlisted user denied
    const strangerDecision = authz.evaluateChannelAndUserAccess({
      userId: 3333,
      isPrivateChannel: true
    });
    expect(strangerDecision.allowed).toBe(false);
    expect(strangerDecision.reasonCode).toBe('NOT_IN_ALLOWLIST');

    // Allowlisted user permitted
    const aliceDecision = authz.evaluateChannelAndUserAccess({
      userId: 1001,
      isPrivateChannel: true
    });
    expect(aliceDecision.allowed).toBe(true);

    // Admin user permitted even if only listed in adminUserIds
    const adminDecision = authz.evaluateChannelAndUserAccess({
      userId: 9999,
      isPrivateChannel: true,
      requireAdmin: true
    });
    expect(adminDecision.allowed).toBe(true);
    expect(authz.isAdmin(9999)).toBe(true);

    // Resource ownership check
    const ownResource = await authz.authorizeResource(1001, {
      resourceType: 'document',
      resourceId: 'doc-100'
    });
    expect(ownResource.allowed).toBe(true);

    const otherResource = await authz.authorizeResource(1001, {
      resourceType: 'document',
      resourceId: 'doc-200'
    });
    expect(otherResource.allowed).toBe(false);
    expect(otherResource.reasonCode).toBe('RESOURCE_FORBIDDEN');

    // Admin bypasses resource ownership restriction
    const adminResource = await authz.authorizeResource(9999, {
      resourceType: 'document',
      resourceId: 'doc-200'
    });
    expect(adminResource.allowed).toBe(true);
  });

  it('enforces framework-agnostic auth middleware and provisions authorized users automatically', async () => {
    const userRepo = new InMemoryUserIdentityRepository();
    const authz = new AuthorizationService({
      allowedUserIds: [1001]
    });

    interface MockRequestContext {
      actorId?: number;
      username?: string;
      displayName?: string;
      isPrivate: boolean;
      deniedReason?: string;
    }

    const middleware = createAuthMiddleware<MockRequestContext>({
      authorization: authz,
      userRepository: userRepo,
      extractSubject: (ctx) => ({
        userId: ctx.actorId,
        username: ctx.username,
        displayName: ctx.displayName,
        isPrivateChannel: ctx.isPrivate
      }),
      onDenied: (ctx, decision) => {
        ctx.deniedReason = decision.reasonCode;
      }
    });

    let nextCalled = false;

    // 1. Non-private channel rejected
    const publicCtx: MockRequestContext = {
      actorId: 1001,
      username: 'alice',
      displayName: 'Alice',
      isPrivate: false
    };
    await middleware(publicCtx, async () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(false);
    expect(publicCtx.deniedReason).toBe('NON_PRIVATE_CHANNEL');

    // 2. Non-allowlisted user rejected
    const unauthCtx: MockRequestContext = {
      actorId: 7777,
      username: 'mallory',
      displayName: 'Mallory',
      isPrivate: true
    };
    await middleware(unauthCtx, async () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(false);
    expect(unauthCtx.deniedReason).toBe('NOT_IN_ALLOWLIST');

    // 3. Allowlisted user in private channel allowed and provisioned in repository
    const validCtx: MockRequestContext = {
      actorId: 1001,
      username: 'alice',
      displayName: 'Alice',
      isPrivate: true
    };
    await middleware(validCtx, async () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(true);
    expect(userRepo.getUser(1001)?.username).toBe('alice');
  });

  it('redacts sensitive JAF, SAML, and custom secrets in redactSecrets and createRedactingLogger', () => {
    const rawUrl =
      'https://aunicalogin.polimi.it/aunicalogin/IdentificazioneUnica.do?jaf_currentWFID=wf12345&__pj1=tok999&ticket=ST-12345';
    const redacted = redactSecrets(rawUrl, ['SuperSecretPassword123']);

    expect(redacted).not.toContain('wf12345');
    expect(redacted).not.toContain('tok999');
    expect(redacted).not.toContain('ST-12345');
    expect(redacted).toContain('jaf_currentWFID=[REDACTED]');
    expect(redacted).toContain('__pj1=[REDACTED]');

    const loggedMessages: string[] = [];
    const safeLogger = createRedactingLogger(
      {
        debug(msg) {
          loggedMessages.push(msg);
        },
        info(msg) {
          loggedMessages.push(msg);
        },
        warn(msg) {
          loggedMessages.push(msg);
        },
        error(msg) {
          loggedMessages.push(msg);
        }
      },
      ['MyVaultPassword!'],
      [{ pattern: /API_KEY_[A-Z0-9]+/g, replacement: '[REDACTED_API_KEY]' }]
    );

    safeLogger.info('Using API_KEY_SECRET123 and pass MyVaultPassword!');
    expect(loggedMessages[0]).toContain('[REDACTED_API_KEY]');
    expect(loggedMessages[0]).not.toContain('MyVaultPassword!');
  });

  it('provides a unified PoliAuth facade for credential persistence, wizard management, and logout cleanup', async () => {
    const auth = new PoliAuth({
      storage: new InMemoryVaultStorage()
    });

    await auth.saveCredentials({
      personCode: '10987654',
      password: 'PoliPassword!',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      polimiEmail: 'mario.rossi@mail.polimi.it'
    });

    const loaded = await auth.loadCredentials();
    expect(loaded?.personCode).toBe('10987654');

    auth.wizard.startSession(1001);
    expect(auth.wizard.hasActiveSession(1001)).toBe(true);

    await auth.logout(1001);
    expect(auth.wizard.hasActiveSession(1001)).toBe(false);
    expect(await auth.loadCredentials()).toBeNull();
  });
});
