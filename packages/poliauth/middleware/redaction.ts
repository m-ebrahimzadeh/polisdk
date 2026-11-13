import type { AuthLoggerPort } from '../interfaces/logger-port.js';

const SENSITIVE_QUERY_PARAM_REGEX =
  /([?&](?:__pj1|jaf_currentWFID|ticket|SAMLRequest|SAMLResponse|password|otp|secret)=)[^&\s#]+/gi;

export interface RedactionRule {
  pattern: RegExp;
  replacement: string;
}

/**
 * Redacts sensitive PoliMi JAF tokens (`__pj1`, `jaf_currentWFID`), CAS/SAML tickets (`ticket`,
 * `SAMLRequest`, `SAMLResponse`), credential query parameters, caller-supplied `extraSecrets`,
 * and optional custom regex rules from log/error text.
 */
export function redactSecrets(
  text: string,
  extraSecrets: string[] = [],
  customRules: RedactionRule[] = []
): string {
  let out = text;
  for (const secret of extraSecrets) {
    if (secret && secret.length >= 4) {
      out = out.split(secret).join('[REDACTED]');
    }
  }
  out = out.replace(SENSITIVE_QUERY_PARAM_REGEX, '$1[REDACTED]');
  for (const rule of customRules) {
    out = out.replace(rule.pattern, rule.replacement);
  }
  return out;
}

/**
 * Extracts and redacts a diagnostic message from an unknown error value.
 */
export function redactSensitiveErrorText(
  error: unknown,
  extraSecrets: string[] = [],
  customRules: RedactionRule[] = []
): string {
  const raw =
    error instanceof Error
      ? error.message || error.name
      : typeof error === 'string'
        ? error
        : String(error);
  return redactSecrets(raw, extraSecrets, customRules);
}

/**
 * Wraps an `AuthLoggerPort` so every log message and error argument is passed through `redactSecrets`.
 */
export function createRedactingLogger(
  delegate: AuthLoggerPort,
  extraSecrets: string[] = [],
  customRules: RedactionRule[] = []
): AuthLoggerPort {
  const sanitizeMeta = (meta: unknown[]): unknown[] =>
    meta.map((item) => {
      if (typeof item === 'string') {
        return redactSecrets(item, extraSecrets, customRules);
      }
      if (item instanceof Error) {
        const cloned = new Error(redactSecrets(item.message, extraSecrets, customRules));
        cloned.name = item.name;
        if (item.stack) {
          cloned.stack = redactSecrets(item.stack, extraSecrets, customRules);
        }
        return cloned;
      }
      return item;
    });

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
