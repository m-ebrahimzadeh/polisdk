import { describe, expect, it } from "vitest";
import { InMemoryUserIdentityRepository, redactSecrets } from "@polisdk/poliauth";
import {
  TELEGRAM_BOT_TOKEN_REDACTION_RULE,
  TelegramCredentialWizard,
  createTelegramAuthMiddleware,
  deleteSensitiveTelegramMessage,
} from "../src/index.js";

describe("@polisdk/telegram-auth", () => {
  it("enforces private chat, allowlist, and automatic user registration", async () => {
    const repo = new InMemoryUserIdentityRepository();
    const middleware = createTelegramAuthMiddleware({
      allowedUserIds: [111],
      userRepository: repo,
    });

    const replies: string[] = [];
    let nextCalled = false;

    // 1. Group chat rejected
    await middleware(
      {
        from: { id: 111, username: "mrossi" },
        chat: { id: -999, type: "group" },
        async reply(text) {
          replies.push(text);
        },
      },
      async () => {
        nextCalled = true;
      },
    );
    expect(nextCalled).toBe(false);
    expect(replies).toHaveLength(1);

    // 2. Unauthorized user rejected
    await middleware(
      {
        from: { id: 222, username: "intruder" },
        chat: { id: 222, type: "private" },
        async reply(text) {
          replies.push(text);
        },
      },
      async () => {
        nextCalled = true;
      },
    );
    expect(nextCalled).toBe(false);
    expect(replies).toHaveLength(2);

    // 3. Authorized user in private chat succeeds and upserts identity
    await middleware(
      {
        from: { id: 111, username: "mrossi", first_name: "Mario", last_name: "Rossi" },
        chat: { id: 111, type: "private" },
        async reply(text) {
          replies.push(text);
        },
      },
      async () => {
        nextCalled = true;
      },
    );
    expect(nextCalled).toBe(true);
    const saved = await repo.getUser(111);
    expect(saved?.displayName).toBe("Mario Rossi");
  });

  it("deletes sensitive messages and redacts Telegram bot tokens", async () => {
    let deleted = false;
    const ok = await deleteSensitiveTelegramMessage({
      async deleteMessage() {
        deleted = true;
      },
    });
    expect(ok).toBe(true);
    expect(deleted).toBe(true);

    const redacted = redactSecrets(
      "Telegram error on token 123456789:AAH_testTokenSecretString1234567890",
      [],
      [TELEGRAM_BOT_TOKEN_REDACTION_RULE],
    );
    expect(redacted).toContain("[REDACTED_BOT_TOKEN]");
  });

  it("tracks promptMessageId in TelegramCredentialWizard", () => {
    const wizard = new TelegramCredentialWizard();
    const session = wizard.startSession(111, 9001);
    expect(session.promptMessageId).toBe(9001);

    wizard.setPromptMessageId(111, 9002);
    expect(wizard.getSession(111)?.promptMessageId).toBe(9002);

    wizard.submitStepInput(111, "10654321");
    wizard.submitStepInput(111, "SuperSecretPassword!");
    wizard.submitStepInput(111, "mario.rossi@mail.polimi.it");
    const done = wizard.submitStepInput(111, "skip");
    expect(done?.status).toBe("completed");
    expect(wizard.getSession(111)).toBeNull();
  });

  it("calls next() when ctx.from is missing, skips Markdown on custom unauthorizedReplyText, and runs onUserAuthenticated without userRepository", async () => {
    const callbacks: Array<{ userId?: unknown }> = [];
    const replies: Array<{ text: string; extra?: unknown }> = [];
    let nextCalls = 0;

    const middleware = createTelegramAuthMiddleware({
      allowedUserIds: [111],
      unauthorizedReplyText: (id) => `Custom_${id}_unauthenticated*raw`,
      onUserAuthenticated: async (_ctx, user) => {
        callbacks.push({ userId: user?.userId });
      },
    });

    // 1. Missing ctx.from passes through to next()
    await middleware(
      {
        reply: async (text, extra) => {
          replies.push({ text, extra });
        },
      },
      async () => {
        nextCalls += 1;
      },
    );
    expect(nextCalls).toBe(1);
    expect(replies).toHaveLength(0);

    // 2. Custom unauthorizedReplyText is sent without parse_mode: Markdown
    await middleware(
      {
        from: { id: 999 },
        chat: { id: 999, type: "private" },
        reply: async (text, extra) => {
          replies.push({ text, extra });
        },
      },
      async () => {
        nextCalls += 1;
      },
    );
    expect(nextCalls).toBe(1);
    expect(replies[0]).toEqual({
      text: "Custom_999_unauthenticated*raw",
      extra: undefined,
    });

    // 3. Authorized user invokes onUserAuthenticated even without userRepository
    await middleware(
      {
        from: { id: 111 },
        chat: { id: 111, type: "private" },
        reply: async () => {},
      },
      async () => {
        nextCalls += 1;
      },
    );
    expect(nextCalls).toBe(2);
    expect(callbacks).toEqual([{ userId: undefined }]);
  });

  it("preserves promptMessageId when skipTotpStep is rejected on an earlier wizard step", () => {
    const wizard = new TelegramCredentialWizard();
    wizard.startSession(555, 777);

    const earlySkip = wizard.skipTotpStep(555);
    expect(earlySkip?.status).toBe("validation_error");
    expect(wizard.getSession(555)?.promptMessageId).toBe(777);
  });
});
