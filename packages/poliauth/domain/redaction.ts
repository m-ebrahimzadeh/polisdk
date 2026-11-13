/**
 * @module @polisdk/poliauth/domain/redaction
 * Pure, platform-agnostic secret redaction utilities for strings, URLs, Errors, and structured metadata.
 */

export interface RedactionRule {
  pattern: RegExp;
  replacement: string;
}

const SENSITIVE_QUERY_PARAM_REGEX =
  /([?&](?:__pj1|jaf_currentWFID|ticket|SAMLRequest|SAMLResponse|password|otp|totpSecret|secret|secretMaterial|masterKey|masterEncryptionKey|botToken|cookie)=)[^&\s#]+/gi;

const SENSITIVE_JSON_FIELD_REGEX =
  /("(?:password|totpSecret|totp_secret|otp|secret|secretMaterial|secret_material|masterKey|master_key|masterEncryptionKey|botToken|bot_token|cookie|SAMLResponse|SAMLRequest|__pj1|jaf_currentWFID)"\s*:\s*)(?:"[^"]*"|\d+(?:\.\d+)?)/gi;

const SENSITIVE_HEADER_REGEX = /(Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\s,;]+/gi;

const SENSITIVE_KEY_REGEX =
  /^(?:password|pass(?:phrase)?|totp[_-]?secret|otp(?:[_-]?code)?|secret|secret[_-]?material|master[_-]?(?:encryption[_-]?)?key|bot[_-]?token|cookies?|set-cookie|authorization|saml[_-]?(?:response|request)|__pj1|jaf_currentwfid|ticket|access[_-]?token|refresh[_-]?token|private[_-]?key)$/i;

function redactStringSecrets(
  text: string,
  extraSecrets: string[],
  customRules: RedactionRule[]
): string {
  let out = text;

  if (extraSecrets.length > 0) {
    const sorted = [...extraSecrets]
      .filter((s): s is string => typeof s === 'string' && s.length >= 4)
      .sort((a, b) => b.length - a.length);
    for (const secret of sorted) {
      out = out.split(secret).join('[REDACTED]');
    }
  }

  out = out.replace(SENSITIVE_QUERY_PARAM_REGEX, '$1[REDACTED]');
  out = out.replace(SENSITIVE_JSON_FIELD_REGEX, '$1"[REDACTED]"');
  out = out.replace(SENSITIVE_HEADER_REGEX, '$1[REDACTED]');

  for (const rule of customRules) {
    out = out.replace(rule.pattern, rule.replacement);
  }

  return out;
}

function redactValueRecursive(
  value: unknown,
  extraSecrets: string[],
  customRules: RedactionRule[],
  ancestors: WeakSet<object>
): unknown {
  if (typeof value === 'string') {
    return redactStringSecrets(value, extraSecrets, customRules);
  }

  if (
    value === null ||
    value === undefined ||
    typeof value === 'number' ||
    typeof value === 'boolean' ||
    typeof value === 'bigint' ||
    typeof value === 'symbol'
  ) {
    return value;
  }

  if (typeof value === 'function') {
    return '[Function]';
  }

  if (typeof value !== 'object') {
    return value;
  }

  if (ancestors.has(value)) {
    return '[Circular]';
  }

  if (value instanceof Date) {
    return new Date(value.getTime());
  }

  if (value instanceof RegExp) {
    return new RegExp(value.source, value.flags);
  }

  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    return '[REDACTED_BINARY]';
  }

  ancestors.add(value);
  try {
    if (value instanceof Error) {
      const cloned = new Error(redactStringSecrets(value.message, extraSecrets, customRules));
      cloned.name = value.name;
      if (value.stack) {
        cloned.stack = redactStringSecrets(value.stack, extraSecrets, customRules);
      }
      const errWithCause = value as Error & { cause?: unknown };
      if (errWithCause.cause !== undefined) {
        (cloned as Error & { cause?: unknown }).cause = redactValueRecursive(
          errWithCause.cause,
          extraSecrets,
          customRules,
          ancestors
        );
      }
      const sourceRecord = value as unknown as Record<string, unknown>;
      const targetRecord = cloned as unknown as Record<string, unknown>;
      for (const key of Object.keys(sourceRecord)) {
        const propVal = sourceRecord[key];
        if (SENSITIVE_KEY_REGEX.test(key) && propVal !== undefined && propVal !== null) {
          targetRecord[key] = '[REDACTED]';
        } else {
          targetRecord[key] = redactValueRecursive(propVal, extraSecrets, customRules, ancestors);
        }
      }
      return cloned;
    }

    if (Array.isArray(value)) {
      return value.map((item) =>
        redactValueRecursive(item, extraSecrets, customRules, ancestors)
      );
    }

    if (value instanceof Map) {
      const result: Record<string, unknown> = {};
      for (const [k, v] of value.entries()) {
        const keyStr = String(k);
        result[keyStr] =
          SENSITIVE_KEY_REGEX.test(keyStr) && v !== undefined && v !== null
            ? '[REDACTED]'
            : redactValueRecursive(v, extraSecrets, customRules, ancestors);
      }
      return result;
    }

    if (value instanceof Set) {
      return Array.from(value.values()).map((item) =>
        redactValueRecursive(item, extraSecrets, customRules, ancestors)
      );
    }

    const out: Record<string, unknown> = {};
    for (const [key, propVal] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_KEY_REGEX.test(key) && propVal !== undefined && propVal !== null) {
        out[key] = '[REDACTED]';
      } else {
        out[key] = redactValueRecursive(propVal, extraSecrets, customRules, ancestors);
      }
    }
    return out;
  } finally {
    ancestors.delete(value);
  }
}

/**
 * Redacts sensitive PoliMi JAF tokens (`__pj1`, `jaf_currentWFID`), CAS/SAML tickets (`ticket`,
 * `SAMLRequest`, `SAMLResponse`), credential/secret properties and query parameters,
 * caller-supplied `extraSecrets`, and optional custom regex rules from strings or structured objects.
 */
export function redactSecrets(
  text: string,
  extraSecrets?: string[],
  customRules?: RedactionRule[]
): string;
export function redactSecrets<T>(
  value: T,
  extraSecrets?: string[],
  customRules?: RedactionRule[]
): T;
export function redactSecrets(
  value: unknown,
  extraSecrets: string[] = [],
  customRules: RedactionRule[] = []
): unknown {
  if (typeof value === 'string') {
    return redactStringSecrets(value, extraSecrets, customRules);
  }
  return redactValueRecursive(value, extraSecrets, customRules, new WeakSet<object>());
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
  return redactStringSecrets(raw, extraSecrets, customRules);
}
