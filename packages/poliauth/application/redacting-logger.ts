/**
 * @module @polisdk/poliauth/application/redacting-logger
 * Secret-redacting decorator around `AuthLoggerPort`.
 */

import type { AuthLoggerPort } from '../interfaces/logger-port.js';
import { type RedactionRule, redactSecrets } from '../domain/redaction.js';

/**
 * Wraps an `AuthLoggerPort` so every log message and metadata argument (including nested
 * plain objects, arrays, and `Error` instances) is recursively passed through `redactSecrets`.
 */
export function createRedactingLogger(
  delegate: AuthLoggerPort,
  extraSecrets: string[] = [],
  customRules: RedactionRule[] = []
): AuthLoggerPort {
  const sanitizeMeta = (meta: unknown[]): unknown[] =>
    meta.map((item) => redactSecrets(item, extraSecrets, customRules));

  return {
    debug(message: string, ...meta: unknown[]) {
      delegate.debug?.(
        redactSecrets(message, extraSecrets, customRules),
        ...sanitizeMeta(meta)
      );
    },
    info(message: string, ...meta: unknown[]) {
      delegate.info(
        redactSecrets(message, extraSecrets, customRules),
        ...sanitizeMeta(meta)
      );
    },
    warn(message: string, ...meta: unknown[]) {
      delegate.warn(
        redactSecrets(message, extraSecrets, customRules),
        ...sanitizeMeta(meta)
      );
    },
    error(message: string, ...meta: unknown[]) {
      delegate.error(
        redactSecrets(message, extraSecrets, customRules),
        ...sanitizeMeta(meta)
      );
    }
  };
}
