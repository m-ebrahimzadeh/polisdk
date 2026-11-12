import type { AuthorizationServicePort } from '../interfaces/authorization-port.js';
import type { UserIdentityRepositoryPort } from '../interfaces/storage-port.js';
import {
  createAuthMiddleware,
  type IncomingSubjectInfo,
  type NextFunction
} from './auth-middleware.js';

/**
 * Structural interface matching `grammY` / `Telegraf` context objects.
 * Avoids hard runtime coupling to a specific Telegram bot framework version.
 */
export interface TelegramContextLike {
  from?: {
    id: number;
    username?: string;
    first_name?: string;
  };
  chat?: {
    id: number;
    type: string;
  };
  message?: {
    message_id: number;
    text?: string;
  };
  api?: {
    deleteMessage(chatId: number, messageId: number): Promise<unknown>;
  };
  reply(text: string, other?: Record<string, unknown>): Promise<unknown>;
}

export interface TelegramAuthMiddlewareOptions {
  /**
   * Authorization service checking private chat and allowlist/admin membership.
   */
  authorization: AuthorizationServicePort;
  /**
   * Optional user identity repository to provision/update the Telegram user in storage.
   */
  userRepository?: UserIdentityRepositoryPort;
  /**
   * Custom reply text when a user sends a command in a non-private (group/channel) chat.
   */
  nonPrivateChatReplyText?: string;
  /**
   * Custom reply text when a user's Telegram ID is not on the allowlist.
   */
  notAllowlistedReplyText?: (telegramUserId: number) => string;
}

const DEFAULT_NON_PRIVATE_TEXT =
  '🔒 For your security, PoliAuth only operates in private 1-on-1 chats.';

const defaultNotAllowlistedText = (userId: number): string =>
  `⛔ Access denied. Your Telegram ID (<code>${userId}</code>) is not on the authorized allowlist.`;

/**
 * Best-effort immediate deletion of a user's Telegram message containing sensitive
 * secrets (passwords, TOTP secrets, or 6-digit OTP codes).
 */
export async function deleteSensitiveTelegramMessage(ctx: TelegramContextLike): Promise<boolean> {
  try {
    if (ctx.chat?.id && ctx.message?.message_id && ctx.api) {
      await ctx.api.deleteMessage(ctx.chat.id, ctx.message.message_id);
      return true;
    }
  } catch {
    // Ignore deletion failure in private chats if message was already removed
  }
  return false;
}

/**
 * Creates a Telegram bot authentication & authorization middleware compatible with `grammY` (`bot.use(...)`).
 * Enforces:
 * 1. Private 1-on-1 chat (`ctx.chat.type === 'private'`)
 * 2. Allowlist / Admin authorization (`ALLOWED_TELEGRAM_USER_IDS`, `ADMIN_TELEGRAM_USER_IDS`)
 * 3. Automatic user provisioning in `UserIdentityRepositoryPort` (`ensureUser`)
 */
export function createTelegramAuthMiddleware<
  TContext extends TelegramContextLike = TelegramContextLike
>(
  options: TelegramAuthMiddlewareOptions
): (ctx: TContext, next: NextFunction) => Promise<void> {
  return createAuthMiddleware<TContext>({
    authorization: options.authorization,
    userRepository: options.userRepository,
    extractSubject(ctx): IncomingSubjectInfo | null {
      if (!ctx.from) {
        return null;
      }
      return {
        userId: ctx.from.id,
        username: ctx.from.username ?? null,
        displayName: ctx.from.first_name ?? null,
        isPrivateChannel: ctx.chat?.type === 'private'
      };
    },
    async onDenied(ctx, decision) {
      if (decision.reasonCode === 'NON_PRIVATE_CHANNEL') {
        await ctx
          .reply(options.nonPrivateChatReplyText ?? DEFAULT_NON_PRIVATE_TEXT)
          .catch(() => undefined);
        return;
      }

      if (decision.reasonCode === 'NOT_IN_ALLOWLIST' && ctx.from) {
        const formatMsg = options.notAllowlistedReplyText ?? defaultNotAllowlistedText;
        await ctx
          .reply(formatMsg(ctx.from.id), { parse_mode: 'HTML' })
          .catch(() => undefined);
      }
    }
  });
}
