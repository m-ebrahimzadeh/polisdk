import type { AuthLoggerPort } from '../interfaces/logger-port.js';

const SENSITIVE_QUERY_PARAM_REGEX =
  /([?&](?:__pj1|jaf_currentWFID|ticket|recordingViewerInfoToken|RCID|password|otp|secret)=)[^&\s#]+/gi;

const TELEGRAM_BOT_TOKEN_REGEX = /\b\d{8,11}:[A-Za-z0-9_-]{35}\b/g;

/**
 * Redacts sensitive PoliMi JAF tokens (`__pj1`, `jaf_currentWFID`), CAS/SAML tickets (`ticket`),
 * Webex tokens (`recordingViewerInfoToken`, `RCID`), credential query parameters,
 * Telegram Bot API tokens, and any caller-supplied `extraSecrets` from log/error text.
 */
export function redactSecrets(text: string, extraSecrets: string[] = []): string {
  let out = text;
  for (const secret of extraSecrets) {
    if (secret && secret.length >= 4) {
      out = out.split(secret).join('[REDACTED]');
    }
  }
  out = out.replace(SENSITIVE_QUERY_PARAM_REGEX, '$1[REDACTED]');
  out = out.replace(TELEGRAM_BOT_TOKEN_REGEX, '[REDACTED_BOT_TOKEN]');
  return out;
}

/**
 * Wraps an `AuthLoggerPort` so every log message and error argument is passed through `redactSecrets`.
 */
export function createRedactingLogger(
  delegate: AuthLoggerPort,
  extraSecrets: string[] = []
): AuthLoggerPort {
  const sanitizeMeta = (meta: unknown[]): unknown[] =>
    meta.map((item) => {
      if (typeof item === 'string') {
        return redactSecrets(item, extraSecrets);
      }
      if (item instanceof Error) {
        const cloned = new Error(redactSecrets(item.message, extraSecrets));
        cloned.name = item.name;
        if (item.stack) {
          cloned.stack = redactSecrets(item.stack, extraSecrets);
        }
        return cloned;
      }
      return item;
    });

  return {
    debug(message: string, ...meta: unknown[]) {
      delegate.debug?.(redactSecrets(message, extraSecrets), ...sanitizeMeta(meta));
    },
    info(message: string, ...meta: unknown[]) {
      delegate.info(redactSecrets(message, extraSecrets), ...sanitizeMeta(meta));
    },
    warn(message: string, ...meta: unknown[]) {
      delegate.warn(redactSecrets(message, extraSecrets), ...sanitizeMeta(meta));
    },
    error(message: string, ...meta: unknown[]) {
      delegate.error(redactSecrets(message, extraSecrets), ...sanitizeMeta(meta));
    }
  };
}
