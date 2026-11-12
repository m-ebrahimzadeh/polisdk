/**
 * @module @polisdk/telegram-auth
 * Framework-agnostic Telegram Bot authentication middleware (compatible with grammY, Telegraf, etc.).
 */

import {
  AuthorizationService,
  type AuthorizationServiceOptions,
  type RedactionRule,
  type UserIdentity,
  type UserIdentityRepositoryPort,
} from "@polisdk/poliauth";

export interface TelegramFromLike {
  id: number;
  username?: string;
  first_name?: string;
  last_name?: string;
}

export interface TelegramChatLike {
  id: number;
  type: "private" | "group" | "supergroup" | "channel" | string;
}

export interface TelegramMessageLike {
  message_id: number;
}

export interface TelegramContextLike {
  from?: TelegramFromLike;
  chat?: TelegramChatLike;
  message?: TelegramMessageLike;
  reply(text: string, extra?: Record<string, unknown>): Promise<unknown>;
  deleteMessage?(): Promise<unknown>;
}

export interface TelegramAuthMiddlewareOptions
  extends AuthorizationServiceOptions {
  /** Optional user identity repository to automatically upsert authorized users. */
  userRepository?: UserIdentityRepositoryPort;
  /** Optional callback invoked when a user record is upserted on authorized request. */
  onUserAuthenticated?: (
    ctx: TelegramContextLike,
    user: UserIdentity,
  ) => void | Promise<void>;
  /** Custom unauthorized reply message. */
  unauthorizedReplyText?: (userId: number) => string;
  /** Custom non-private chat rejection message. */
  nonPrivateChatReplyText?: string;
  /** Whether to restrict bot usage exclusively to private 1:1 chats (default: true). */
  requirePrivateChat?: boolean;
}

/**
 * Redaction rule matching Telegram Bot API tokens (`123456789:AA...`).
 */
export const TELEGRAM_BOT_TOKEN_REDACTION_RULE: RedactionRule = {
  pattern: /\b\d{8,12}:[A-Za-z0-9_-]{30,}\b/g,
  replacement: "[REDACTED_BOT_TOKEN]",
};

/**
 * Create a framework-agnostic Telegram middleware function `(ctx, next) => Promise<void>`
 * that enforces private-chat-only interaction, allowlist authorization, and automatic user identity registration.
 */
export function createTelegramAuthMiddleware<
  TContext extends TelegramContextLike = TelegramContextLike,
>(options: TelegramAuthMiddlewareOptions) {
  const authService = new AuthorizationService({
    ...options,
    enforcePrivateChannel: options.requirePrivateChat ?? true,
  });

  return async (
    ctx: TContext,
    next: () => Promise<void>,
  ): Promise<void> => {
    const from = ctx.from;
    if (!from) {
      return;
    }

    const isPrivate = !ctx.chat || ctx.chat.type === "private";
    const decision = authService.evaluateChannelAndUserAccess({
      userId: from.id,
      isPrivateChannel: isPrivate,
    });

    if (!decision.allowed) {
      if (decision.reasonCode === "NON_PRIVATE_CHANNEL") {
        const text =
          options.nonPrivateChatReplyText ??
          "🔒 Per motivi di sicurezza e privacy delle credenziali PoliMi, usa il bot solo in chat privata 1:1.";
        await ctx.reply(text);
        return;
      }

      const text = options.unauthorizedReplyText
        ? options.unauthorizedReplyText(from.id)
        : `⛔ Non sei autorizzato a usare questo bot.\nIl tuo ID utente è: \`${from.id}\``;
      await ctx.reply(text, { parse_mode: "Markdown" });
      return;
    }

    if (options.userRepository) {
      const displayName =
        [from.first_name, from.last_name].filter(Boolean).join(" ").trim() ||
        null;
      const userRecord = await options.userRepository.ensureUser(from.id, {
        username: from.username ?? null,
        displayName,
      });

      if (options.onUserAuthenticated) {
        await options.onUserAuthenticated(ctx, userRecord);
      }
    }

    await next();
  };
}

/**
 * Best-effort helper to delete a Telegram message containing sensitive credentials
 * (password, TOTP secret, or OTP code) immediately after reading it.
 */
export async function deleteSensitiveTelegramMessage(
  ctx: Pick<TelegramContextLike, "deleteMessage">,
): Promise<boolean> {
  if (typeof ctx.deleteMessage !== "function") {
    return false;
  }

  try {
    await ctx.deleteMessage();
    return true;
  } catch {
    return false;
  }
}
