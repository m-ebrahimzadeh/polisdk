import { describe, expect, it } from 'vitest';
import { AuthorizationService } from '../domain/authorization.js';
import {
  createTelegramAuthMiddleware,
  deleteSensitiveTelegramMessage,
  type TelegramContextLike
} from '../middleware/telegram-middleware.js';
import { redactSecrets, createRedactingLogger } from '../middleware/redaction.js';
import { InMemoryUserIdentityRepository, InMemoryVaultStorage } from '../storage/memory-storage.js';
import { PoliAuth } from '../src/poliauth-client.js';

describe('AuthorizationService, Middleware, Secret Redaction & PoliAuth Facade', () => {
  it('enforces private channel guard, allowlist, admin roles, and pluggable resource ownership policies', async () => {
    const ownedResources = new Map<string, number>([
      ['transfer-100', 1001],
      ['transfer-200', 2002]
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

    // Group chat denied even for allowlisted user
    const groupDecision = authz.evaluateChannelAndUserAccess({
      userId: 1001,
      isPrivateChannel: false
    });
    expect(groupDecision.allowed).toBe(false);
    expect(groupDecision.reasonCode).toBe('NON_PRIVATE_CHANNEL');

    // Non-allowlisted user denied in private chat
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
      resourceType: 'transfer',
      resourceId: 'transfer-100'
    });
    expect(ownResource.allowed).toBe(true);

    const otherResource = await authz.authorizeResource(1001, {
      resourceType: 'transfer',
      resourceId: 'transfer-200'
    });
    expect(otherResource.allowed).toBe(false);
    expect(otherResource.reasonCode).toBe('RESOURCE_FORBIDDEN');

    // Admin bypasses resource ownership restriction
    const adminResource = await authz.authorizeResource(9999, {
      resourceType: 'transfer',
      resourceId: 'transfer-200'
    });
    expect(adminResource.allowed).toBe(true);
  });

  it('enforces Telegram auth middleware and provisions authorized users automatically', async () => {
    const userRepo = new InMemoryUserIdentityRepository();
    const authz = new AuthorizationService({
      allowedUserIds: [1001]
    });

    const middleware = createTelegramAuthMiddleware({
      authorization: authz,
      userRepository: userRepo
    });

    const replies: string[] = [];
    let nextCalled = false;

    // 1. Group chat rejected
    const groupCtx: TelegramContextLike = {
      from: { id: 1001, username: 'alice', first_name: 'Alice' },
      chat: { id: -500, type: 'group' },
      async reply(text) {
        replies.push(text);
      }
    };
    await middleware(groupCtx, async () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(false);
    expect(replies[0]).toContain('private');

    // 2. Non-allowlisted user rejected
    replies.length = 0;
    const unauthCtx: TelegramContextLike = {
      from: { id: 7777, username: 'mallory', first_name: 'Mallory' },
      chat: { id: 7777, type: 'private' },
      async reply(text) {
        replies.push(text);
      }
    };
    await middleware(unauthCtx, async () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(false);
    expect(replies[0]).toContain('7777');

    // 3. Allowlisted user in private chat allowed and provisioned in repository
    const validCtx: TelegramContextLike = {
      from: { id: 1001, username: 'alice', first_name: 'Alice' },
      chat: { id: 1001, type: 'private' },
      message: { message_id: 55, text: 'MySecretPassword' },
      api: {
        async deleteMessage() {
          return true;
        }
      },
      async reply(text) {
        replies.push(text);
      }
    };
    await middleware(validCtx, async () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(true);
    expect(userRepo.getUser(1001)?.username).toBe('alice');
    expect(await deleteSensitiveTelegramMessage(validCtx)).toBe(true);
  });

  it('redacts sensitive JAF, SAML, Webex, and Telegram Bot tokens in redactSecrets and createRedactingLogger', () => {
    const rawUrl =
      'https://onlineservices.polimi.it/archivioregistrazioni/Archivio.do?jaf_currentWFID=wf12345&__pj1=tok999&recordingViewerInfoToken=webexTok&ticket=ST-12345';
    const redacted = redactSecrets(rawUrl, ['SuperSecretPassword123']);

    expect(redacted).not.toContain('wf12345');
    expect(redacted).not.toContain('tok999');
    expect(redacted).not.toContain('webexTok');
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
      ['MyVaultPassword!']
    );

    safeLogger.info(
      'Bot token 123456789:AAHfiqksKZ8WmR2zS9xY0pL1mN2bV3cX4zA and pass MyVaultPassword!'
    );
    expect(loggedMessages[0]).toContain('[REDACTED_BOT_TOKEN]');
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
