# `@polisdk/telegram-auth`

Telegram Bot authentication middleware, sensitive message cleanup, and interactive credential wizard for `@polisdk/poliauth`.

## Features

- **`createTelegramAuthMiddleware`**: Framework-agnostic middleware (`grammY`, `Telegraf`, custom bots) enforcing 1:1 private chat security, allowlist checks, and automatic `UserIdentityRepositoryPort` registration.
- **`deleteSensitiveTelegramMessage`**: Best-effort deletion of user messages containing passwords, TOTP secrets, or OTP codes.
- **`TelegramCredentialWizard`**: Wraps `CredentialSetupWizard` with per-user `promptMessageId` tracking.
- **`TELEGRAM_BOT_TOKEN_REDACTION_RULE`**: Redaction rule for `redactSensitiveErrorText` that strips Telegram Bot API tokens.
