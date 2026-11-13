import {
  POLIMI_LOGIN_FLOW_SPEC,
  PoliAuthDiagnosticError,
  classifyPolimiFailure,
  cleanTotpSecret,
  generateStableTotp,
  isValidPersonCode,
  isValidPolimiEmail,
  isValidTotpSecret,
  redactSecrets,
  redactSensitiveErrorText,
  type PoliAuthFailureClassification,
  type PoliAuthStage,
  type PolimiLoginFlowSpec,
  type RedactionRule
} from '@polisdk/poliauth/domain';
import type { AuthLoggerPort } from '@polisdk/poliauth/interfaces';
import {
  SAML_PROTOCOL_FORM_SELECTOR,
  type PolimiPageActionResult
} from '@polisdk/poliauth/adapters';
import { createRedactingLogger } from '@polisdk/poliauth/middleware';
import { ensureAuthAdaptersInjected } from './injected-auth-bundle.js';
import {
  PlaywrightAuthPageDriver,
  type PlaywrightAuthPageDriverOptions,
  type PlaywrightPageLike
} from './playwright-page-driver.js';

export type { PoliAuthStage, PolimiLoginFlowSpec, PoliAuthFailureClassification };
export { PoliAuthDiagnosticError };

export interface LivePortalFormButtonInventoryEntry {
  index: number;
  tagName: string;
  id?: string;
  name?: string;
  type?: string;
  classes: string;
  text: string;
  visible: boolean;
  matchesPrimaryOtpSelector: boolean;
  isSubmitDissmsTrap: boolean;
  isJafVisuallyHiddenTrap: boolean;
}

export interface LiveProbeCredentials {
  personCode: string;
  password: string;
  totpSecret: string;
  polimiEmail?: string;
}

export interface LiveProbeCredentialsResult {
  ok: boolean;
  credentials?: LiveProbeCredentials;
  extraSecrets: readonly string[];
  redactionRules: readonly RedactionRule[];
  source: 'process_env' | 'dotenv_file' | 'merged' | 'missing';
  errors: readonly string[];
}

export interface LivePortalRedirectHop {
  stepIndex: number;
  url: string;
  status?: number;
  locationHeader?: string;
  cspHeader?: string;
  timestampIso: string;
}

export interface LivePortalDomTrapProbeResult {
  hasLoginInput: boolean;
  hasPasswordInput: boolean;
  hasVisibleSubmitButton: boolean;
  hasJafVisuallyHiddenTrap: boolean;
  hasOtpInput: boolean;
  hasSubmitDissmsTrap: boolean;
  hasSsoHandoffForm: boolean;
  hasExpiredSessionMarker: boolean;
  hasAuthenticatedMarker: boolean;
  hasErrorBanner: boolean;
  hasMaintenanceBanner?: boolean;
  hasEmptyBody?: boolean;
  otpFormButtonInventory?: readonly LivePortalFormButtonInventoryEntry[];
  sanitizedErrorMessage?: string;
}

export interface LivePortalStageProbeRecord {
  probeName: string;
  targetUrl: string;
  finalUrl: string;
  inspectedStage: PoliAuthStage;
  adapterInjectionMethod: 'evaluate' | 'addScriptTag' | 'pre_injected';
  httpStatus?: number;
  failureClassification?: PoliAuthFailureClassification;
  redirectChain: readonly LivePortalRedirectHop[];
  cspHeadersDetected: readonly string[];
  domSnapshot: LivePortalDomTrapProbeResult;
  durationMs: number;
  epistemicStatus: 'FACT:LIVE' | 'FACT:EXEC';
  notes: readonly string[];
}

export interface LivePortalProbeReport {
  generatedAtIso: string;
  environment: 'live_network' | 'synthetic_harness';
  stages: readonly LivePortalStageProbeRecord[];
  overallSuccess: boolean;
  errorSummary?: string;
}

export interface LivePortalProbeOptions {
  page: PlaywrightPageLike;
  driverOptions?: PlaywrightAuthPageDriverOptions;
  logger?: AuthLoggerPort;
  spec?: PolimiLoginFlowSpec;
  probeBareAunicaloginRecovery?: boolean;
  probeServiceEntryToCredentials?: boolean;
  probeAuthenticatedFlow?: boolean;
  credentials?: LiveProbeCredentials;
  customUrlsToInspect?: readonly string[];
  environment?: 'live_network' | 'synthetic_harness';
  extraSecrets?: readonly string[];
  redactionRules?: readonly RedactionRule[];
}

export interface AuthenticatedLivePortalProbeOptions
  extends Omit<LivePortalProbeOptions, 'probeAuthenticatedFlow'> {
  credentials?: LiveProbeCredentials;
  envFilePath?: string;
  env?: Record<string, string | undefined>;
}

interface PlaywrightRequestTelemetryLike {
  url?(): string;
  isNavigationRequest?(): boolean;
  resourceType?(): string;
  redirectedFrom?(): PlaywrightRequestTelemetryLike | null;
  response?(): Promise<PlaywrightResponseTelemetryLike | null>;
}

interface PlaywrightResponseTelemetryLike {
  url?(): string;
  status?(): number;
  headers?(): Record<string, string>;
  allHeaders?(): Promise<Record<string, string>>;
  request?(): PlaywrightRequestTelemetryLike | null;
}

interface ObservablePageLike extends PlaywrightPageLike {
  on?(event: string, listener: (...args: unknown[]) => void): unknown;
  off?(event: string, listener: (...args: unknown[]) => void): unknown;
  removeListener?(event: string, listener: (...args: unknown[]) => void): unknown;
  context?(): unknown;
  mainFrame?(): unknown;
}

interface DerivedDomSelectorBundle {
  personCodeInputSelector: string;
  passwordInputSelector: string;
  credentialsSubmitButtonSelector: string;
  credentialsFallbackSubmitButtonSelector: string;
  jafTrapSelectors: string[];
  otpFormSelector: string;
  otpInputSelector: string;
  fallbackOtpInputSelector: string;
  otpSubmitButtonSelector: string;
  dissmsTrapSelectors: string[];
  ssoHandoffFormSelector: string;
  checkCookieInputSelector: string;
  samlProtocolFormSelector: string;
  idpHostname: string;
  idpPathnameSubstring: string;
  sessionTerminatedMarker: string;
  sessionExpiredTextMarkers: string[];
  continueToPortalSelector: string;
  fallbackContinueToPortalSelector: string;
  authenticatedDomSelectors: string[];
  errorBannerSelectors: string[];
  maintenanceBannerSelectors: string[];
  maintenanceTextPatterns: string[];
}

interface RawDomSnapshotEvaluation {
  hasLoginInput: boolean;
  hasPasswordInput: boolean;
  hasVisibleSubmitButton: boolean;
  hasJafVisuallyHiddenTrap: boolean;
  hasOtpInput: boolean;
  hasSubmitDissmsTrap: boolean;
  hasSsoHandoffForm: boolean;
  hasExpiredSessionMarker: boolean;
  hasAuthenticatedMarker: boolean;
  hasErrorBannerSelector: boolean;
  hasMaintenanceBanner?: boolean;
  hasEmptyBody?: boolean;
  otpFormButtonInventory?: LivePortalFormButtonInventoryEntry[];
  rawErrorMessage?: string;
}

const EMPTY_DOM_SNAPSHOT: LivePortalDomTrapProbeResult = {
  hasLoginInput: false,
  hasPasswordInput: false,
  hasVisibleSubmitButton: false,
  hasJafVisuallyHiddenTrap: false,
  hasOtpInput: false,
  hasSubmitDissmsTrap: false,
  hasSsoHandoffForm: false,
  hasExpiredSessionMarker: false,
  hasAuthenticatedMarker: false,
  hasErrorBanner: false
};

interface ProbeRedactionContext {
  extraSecrets: string[];
  redactionRules: RedactionRule[];
}

function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function registerSecretValue(
  ctx: ProbeRedactionContext,
  value: string | undefined,
  caseInsensitive = false
): void {
  const trimmed = value?.trim();
  if (!trimmed) {
    return;
  }
  const variants = new Set<string>([trimmed]);
  try {
    const encoded = encodeURIComponent(trimmed);
    if (encoded !== trimmed) {
      variants.add(encoded);
    }
  } catch {
    // ignore encoding edge cases
  }
  for (const variant of variants) {
    if (!ctx.extraSecrets.includes(variant)) {
      ctx.extraSecrets.push(variant);
    }
    const flags = caseInsensitive ? 'gi' : 'g';
    const source = escapeRegExp(variant);
    const alreadyExists = ctx.redactionRules.some(
      (rule) => rule.pattern.source === source && rule.pattern.flags === flags
    );
    if (!alreadyExists) {
      ctx.redactionRules.push({
        pattern: new RegExp(source, flags),
        replacement: '[REDACTED]'
      });
    }
  }
}

function createCredentialRedactionContext(
  credentials?: Partial<LiveProbeCredentials>,
  baseExtraSecrets: readonly string[] = [],
  baseRules: readonly RedactionRule[] = []
): ProbeRedactionContext {
  const ctx: ProbeRedactionContext = {
    extraSecrets: [...baseExtraSecrets],
    redactionRules: [...baseRules]
  };
  if (!credentials) {
    return ctx;
  }
  registerSecretValue(ctx, credentials.personCode, false);
  registerSecretValue(ctx, credentials.password, false);
  if (credentials.totpSecret) {
    registerSecretValue(ctx, credentials.totpSecret, true);
    const cleaned = cleanTotpSecret(credentials.totpSecret);
    if (cleaned) {
      registerSecretValue(ctx, cleaned, true);
    }
  }
  registerSecretValue(ctx, credentials.polimiEmail, true);
  return ctx;
}

function readProcessEnv(): Record<string, string | undefined> | undefined {
  return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
}

function readProcessCwd(): string {
  const proc = (globalThis as { process?: { cwd?: () => string } }).process;
  return typeof proc?.cwd === 'function' ? proc.cwd() : '.';
}

interface NodeFsPromisesLike {
  readFile(filePath: string, encoding: 'utf8'): Promise<string>;
}

interface NodePathLike {
  resolve(...segments: string[]): string;
}

function parseDotEnvContent(content: string): Record<string, string> {
  const parsed: Record<string, string> = {};
  const lines = content.split(/\r?\n/);
  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const withoutExport = trimmed.startsWith('export ')
      ? trimmed.slice('export '.length).trim()
      : trimmed;
    const eqIndex = withoutExport.indexOf('=');
    if (eqIndex <= 0) {
      continue;
    }
    const key = withoutExport.slice(0, eqIndex).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      continue;
    }
    let rawVal = withoutExport.slice(eqIndex + 1).trim();
    if (
      (rawVal.startsWith('"') && rawVal.endsWith('"') && rawVal.length >= 2) ||
      (rawVal.startsWith("'") && rawVal.endsWith("'") && rawVal.length >= 2)
    ) {
      const quote = rawVal[0];
      rawVal = rawVal.slice(1, -1);
      if (quote === '"') {
        rawVal = rawVal
          .replace(/\\n/g, '\n')
          .replace(/\\r/g, '\r')
          .replace(/\\"/g, '"')
          .replace(/\\\\/g, '\\');
      }
    } else {
      const commentIdx = rawVal.search(/\s+#/);
      if (commentIdx >= 0) {
        rawVal = rawVal.slice(0, commentIdx).trim();
      }
    }
    parsed[key] = rawVal;
  }
  return parsed;
}

/**
 * Returns `true` when live network portal probing is explicitly opted in (`POLIAUTH_LIVE_PROBE=1`).
 */
export function isLivePortalProbeEnabled(
  env: Record<string, string | undefined> | undefined = readProcessEnv()
): boolean {
  return env?.POLIAUTH_LIVE_PROBE === '1';
}

/**
 * Returns `true` when authenticated `.env` live portal probing is explicitly opted in
 * (`POLIAUTH_LIVE_AUTH_PROBE=1`).
 */
export function isLiveAuthPortalProbeEnabled(
  env: Record<string, string | undefined> | undefined = readProcessEnv()
): boolean {
  return env?.POLIAUTH_LIVE_AUTH_PROBE === '1';
}

/**
 * Safely loads PoliMi test credentials from `process.env` and/or a local `.env` file using
 * zero-dependency Node built-ins, validating formats and returning custom `RedactionRule`s
 * so loaded secrets are automatically replaced with `[REDACTED]`.
 */
export async function loadLiveProbeCredentialsFromEnv(
  envFilePath?: string,
  envOverride?: Record<string, string | undefined>
): Promise<LiveProbeCredentialsResult> {
  let dotenvVars: Record<string, string> = {};
  let loadedFromFile = false;

  try {
    const fsModuleId = 'node:fs/promises';
    const pathModuleId = 'node:path';
    const fsMod = (await import(/* @vite-ignore */ fsModuleId)) as NodeFsPromisesLike;
    const pathMod = (await import(/* @vite-ignore */ pathModuleId)) as NodePathLike;

    const cwd = readProcessCwd();
    const candidatePaths = envFilePath
      ? [pathMod.resolve(envFilePath)]
      : [pathMod.resolve(cwd, '.env'), pathMod.resolve(cwd, '..', '..', '.env')];

    for (const candidate of candidatePaths) {
      try {
        const content = await fsMod.readFile(candidate, 'utf8');
        dotenvVars = parseDotEnvContent(content);
        loadedFromFile = true;
        break;
      } catch {
        // Try next candidate path if not readable
      }
    }
  } catch {
    // Non-Node environments fall back to envOverride/process.env
  }

  const runtimeEnv = envOverride ?? readProcessEnv() ?? {};
  const merged: Record<string, string | undefined> = { ...dotenvVars };
  let usedRuntimeEnv = false;
  for (const key of [
    'POLIAUTH_PERSON_CODE',
    'POLIAUTH_PASSWORD',
    'POLIAUTH_TOTP_SECRET',
    'POLIAUTH_EMAIL'
  ] as const) {
    const val = runtimeEnv[key];
    if (typeof val === 'string' && val.trim().length > 0) {
      merged[key] = val;
      usedRuntimeEnv = true;
    }
  }

  const source: LiveProbeCredentialsResult['source'] =
    loadedFromFile && usedRuntimeEnv
      ? 'merged'
      : loadedFromFile
        ? 'dotenv_file'
        : usedRuntimeEnv
          ? 'process_env'
          : 'missing';

  const personCode = (merged.POLIAUTH_PERSON_CODE ?? '').trim();
  const password = merged.POLIAUTH_PASSWORD ?? '';
  const rawTotpSecret = (merged.POLIAUTH_TOTP_SECRET ?? '').trim();
  const cleanedTotpSecret = cleanTotpSecret(rawTotpSecret);
  const polimiEmail = (merged.POLIAUTH_EMAIL ?? '').trim();

  const redactionCtx = createCredentialRedactionContext({
    personCode,
    password,
    totpSecret: rawTotpSecret,
    polimiEmail: polimiEmail || undefined
  });

  const errors: string[] = [];
  if (!personCode) {
    errors.push('Missing POLIAUTH_PERSON_CODE.');
  } else if (!isValidPersonCode(personCode)) {
    errors.push('Invalid POLIAUTH_PERSON_CODE format (expected 8 digits).');
  }

  if (!password || password.trim().length === 0) {
    errors.push('Missing POLIAUTH_PASSWORD.');
  }

  if (!rawTotpSecret) {
    errors.push('Missing POLIAUTH_TOTP_SECRET.');
  } else if (!isValidTotpSecret(cleanedTotpSecret)) {
    errors.push('Invalid POLIAUTH_TOTP_SECRET format (expected Base32 secret).');
  }

  if (polimiEmail && !isValidPolimiEmail(polimiEmail)) {
    errors.push('Invalid POLIAUTH_EMAIL format (expected @*.polimi.it institutional address).');
  }

  if (errors.length > 0) {
    return {
      ok: false,
      extraSecrets: redactionCtx.extraSecrets,
      redactionRules: redactionCtx.redactionRules,
      source,
      errors
    };
  }

  return {
    ok: true,
    credentials: {
      personCode,
      password,
      totpSecret: cleanedTotpSecret,
      ...(polimiEmail ? { polimiEmail } : {})
    },
    extraSecrets: redactionCtx.extraSecrets,
    redactionRules: redactionCtx.redactionRules,
    source,
    errors: []
  };
}

function isClosedTargetError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /target closed|page has been closed|browser has been closed|context has been closed|has been closed/i.test(
    msg
  );
}

function isTransientNavigationError(err: unknown): boolean {
  if (isClosedTargetError(err)) {
    return false;
  }
  const msg = err instanceof Error ? err.message : String(err);
  return /execution context was destroyed|most likely because of a navigation|cannot find context|frame was detached|navigating to|navigation in progress|interrupted by.*navigation/i.test(
    msg
  );
}

function isRealPlaywrightPage(page: PlaywrightPageLike): boolean {
  const candidate = page as ObservablePageLike;
  return typeof candidate.context === 'function' && typeof candidate.mainFrame === 'function';
}

function extractNotSelectors(selectors: readonly string[]): string[] {
  const found = new Set<string>();
  for (const selector of selectors) {
    const regex = /:not\(([^()]+)\)/g;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(selector)) !== null) {
      const inner = match[1]?.trim();
      if (inner && !inner.startsWith('#')) {
        found.add(inner);
      }
    }
  }
  return Array.from(found);
}

function extractIdSelectors(selectors: readonly string[]): string[] {
  const found = new Set<string>();
  for (const selector of selectors) {
    const regex = /#[A-Za-z_-][A-Za-z0-9_-]*/g;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(selector)) !== null) {
      if (match[0]) {
        found.add(match[0]);
      }
    }
  }
  return Array.from(found);
}

function buildSelectorBundle(spec: PolimiLoginFlowSpec): DerivedDomSelectorBundle {
  const jafTrapSelectors = extractNotSelectors([
    spec.credentialsPage.submitButtonSelector,
    spec.otpPage.submitButtonSelector
  ]);
  const dissmsTrapSelectors = extractIdSelectors([spec.otpPage.submitButtonSelector]);
  const errorBannerSelectors = Array.from(
    new Set([
      spec.credentialsPage.errorAlertSelector,
      spec.otpPage.errorAlertSelector,
      spec.entry.sessionExpiredSelectors.dangerAlert,
      spec.entry.sessionExpiredSelectors.warningAlert
    ])
  );

  return {
    personCodeInputSelector: spec.credentialsPage.personCodeInputSelector,
    passwordInputSelector: spec.credentialsPage.passwordInputSelector,
    credentialsSubmitButtonSelector: spec.credentialsPage.submitButtonSelector,
    credentialsFallbackSubmitButtonSelector: spec.credentialsPage.fallbackSubmitButtonSelector,
    jafTrapSelectors,
    otpFormSelector: spec.otpPage.formSelector,
    otpInputSelector: spec.otpPage.otpInputSelector,
    fallbackOtpInputSelector: spec.otpPage.fallbackOtpInputSelector,
    otpSubmitButtonSelector: spec.otpPage.submitButtonSelector,
    dissmsTrapSelectors,
    ssoHandoffFormSelector: spec.ssoHandoffPage.formSelector,
    checkCookieInputSelector: spec.ssoHandoffPage.checkCookieInputSelector,
    samlProtocolFormSelector: SAML_PROTOCOL_FORM_SELECTOR,
    idpHostname: spec.entry.idpHostname,
    idpPathnameSubstring: spec.entry.idpPathnameSubstring,
    sessionTerminatedMarker: spec.entry.sessionTerminatedMarker,
    sessionExpiredTextMarkers: [...spec.entry.sessionExpiredTextMarkers],
    continueToPortalSelector: spec.entry.sessionExpiredSelectors.continueToPortalLink,
    fallbackContinueToPortalSelector: spec.entry.sessionExpiredSelectors.fallbackContinueToPortalLink,
    authenticatedDomSelectors: [...spec.authenticatedSession.authenticatedDomSelectors],
    errorBannerSelectors,
    maintenanceBannerSelectors: [...spec.maintenanceIndicators.bannerSelectors],
    maintenanceTextPatterns: [...spec.maintenanceIndicators.textPatterns]
  };
}

function resolveBareAunicaloginUrl(spec: PolimiLoginFlowSpec): string {
  if (spec.entry.requestedUrl) {
    return spec.entry.requestedUrl;
  }
  const path = spec.entry.idpPathnameSubstring.endsWith('/')
    ? spec.entry.idpPathnameSubstring
    : `${spec.entry.idpPathnameSubstring}/`;
  try {
    return new URL(path, spec.entry.serviceEntryUrl).toString();
  } catch {
    return `https://${spec.entry.idpHostname}${path}`;
  }
}

function getHeaderCaseInsensitive(
  headers: Record<string, string>,
  headerName: string
): string | undefined {
  const lowerTarget = headerName.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lowerTarget && typeof value === 'string' && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

async function readResponseHeaders(
  response: PlaywrightResponseTelemetryLike
): Promise<Record<string, string>> {
  if (typeof response.allHeaders === 'function') {
    try {
      const all = await response.allHeaders();
      if (all && typeof all === 'object') {
        return all;
      }
    } catch {
      // Fall back to synchronous response.headers() when allHeaders() is unavailable
    }
  }
  if (typeof response.headers === 'function') {
    const syncHeaders = response.headers();
    if (syncHeaders && typeof syncHeaders === 'object') {
      return syncHeaders;
    }
  }
  return {};
}

function isResponseLike(value: unknown): value is PlaywrightResponseTelemetryLike {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const candidate = value as PlaywrightResponseTelemetryLike;
  return (
    typeof candidate.url === 'function' ||
    typeof candidate.status === 'function' ||
    typeof candidate.headers === 'function'
  );
}

async function createHopFromResponse(
  stepIndex: number,
  response: PlaywrightResponseTelemetryLike,
  timestampIso: string,
  redaction?: ProbeRedactionContext
): Promise<{ hop: LivePortalRedirectHop; cspHeaders: string[] }> {
  const extraSecrets = redaction?.extraSecrets ?? [];
  const customRules = redaction?.redactionRules ?? [];
  const rawUrl = typeof response.url === 'function' ? response.url() : '';
  const status = typeof response.status === 'function' ? response.status() : undefined;
  const headers = await readResponseHeaders(response);
  const rawLocation = getHeaderCaseInsensitive(headers, 'location');
  const rawCsp = getHeaderCaseInsensitive(headers, 'content-security-policy');
  const rawCspReportOnly = getHeaderCaseInsensitive(
    headers,
    'content-security-policy-report-only'
  );

  const cspHeaders: string[] = [];
  if (rawCsp) {
    cspHeaders.push(redactSecrets(rawCsp, extraSecrets, customRules));
  }
  if (rawCspReportOnly) {
    cspHeaders.push(redactSecrets(rawCspReportOnly, extraSecrets, customRules));
  }

  const sanitizedCsp = cspHeaders.length > 0 ? cspHeaders.join('; ') : undefined;

  return {
    hop: {
      stepIndex,
      url: redactSecrets(rawUrl, extraSecrets, customRules),
      ...(status !== undefined ? { status } : {}),
      ...(rawLocation
        ? { locationHeader: redactSecrets(rawLocation, extraSecrets, customRules) }
        : {}),
      ...(sanitizedCsp ? { cspHeader: sanitizedCsp } : {}),
      timestampIso
    },
    cspHeaders
  };
}

function isNavigationResponse(response: PlaywrightResponseTelemetryLike): boolean {
  const req = typeof response.request === 'function' ? response.request() : null;
  if (!req) {
    return true;
  }
  if (typeof req.isNavigationRequest === 'function' && !req.isNavigationRequest()) {
    return false;
  }
  if (typeof req.resourceType === 'function') {
    const rt = req.resourceType();
    if (rt && rt !== 'document') {
      return false;
    }
  }
  return true;
}

async function captureRedirectChainFromResponse(
  finalResponse: PlaywrightResponseTelemetryLike,
  redaction?: ProbeRedactionContext
): Promise<{ hops: LivePortalRedirectHop[]; cspHeaders: string[] }> {
  const chain: Array<{ url: string; response: PlaywrightResponseTelemetryLike | null }> = [];
  const seenRequests = new Set<PlaywrightRequestTelemetryLike>();

  let currentReq =
    typeof finalResponse.request === 'function' ? finalResponse.request() : null;
  if (currentReq) {
    while (currentReq && !seenRequests.has(currentReq)) {
      seenRequests.add(currentReq);
      let resp: PlaywrightResponseTelemetryLike | null = null;
      if (currentReq === finalResponse.request?.()) {
        resp = finalResponse;
      } else if (typeof currentReq.response === 'function') {
        try {
          resp = await currentReq.response();
        } catch (respErr) {
          // Earlier redirect hop response may be unavailable when navigating rapidly; retain URL-only hop
          void respErr;
          resp = null;
        }
      }
      const reqUrl = typeof currentReq.url === 'function' ? currentReq.url() : '';
      chain.unshift({ url: reqUrl, response: resp });
      currentReq =
        typeof currentReq.redirectedFrom === 'function' ? currentReq.redirectedFrom() : null;
    }
  } else {
    chain.push({
      url: typeof finalResponse.url === 'function' ? finalResponse.url() : '',
      response: finalResponse
    });
  }

  const hops: LivePortalRedirectHop[] = [];
  const cspHeaders: string[] = [];
  for (let i = 0; i < chain.length; i++) {
    const item = chain[i]!;
    const timestampIso = new Date().toISOString();
    if (item.response) {
      const built = await createHopFromResponse(i, item.response, timestampIso, redaction);
      hops.push(built.hop);
      cspHeaders.push(...built.cspHeaders);
    } else {
      hops.push({
        stepIndex: i,
        url: redactSecrets(
          item.url,
          redaction?.extraSecrets ?? [],
          redaction?.redactionRules ?? []
        ),
        timestampIso
      });
    }
  }

  return { hops, cspHeaders };
}

function createTrackedInjectionPage(
  rawPage: PlaywrightPageLike,
  onAddScriptTag: () => void
): PlaywrightPageLike {
  return new Proxy(rawPage, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target);
      if (prop === 'addScriptTag' && typeof value === 'function') {
        return async (options: { content?: string; url?: string; path?: string }) => {
          onAddScriptTag();
          return (value as (opts: typeof options) => Promise<unknown>).call(target, options);
        };
      }
      if (typeof value === 'function') {
        return (value as (...args: unknown[]) => unknown).bind(target);
      }
      return value;
    }
  });
}

function collectDomSnapshotInPage(
  selectors: DerivedDomSelectorBundle
): RawDomSnapshotEvaluation {
  const querySafe = (selector: string): Element | null => {
    if (!selector) return null;
    try {
      return document.querySelector(selector);
    } catch {
      return null;
    }
  };

  const queryAllSafe = (selector: string): Element[] => {
    if (!selector) return [];
    try {
      return Array.from(document.querySelectorAll(selector));
    } catch {
      return [];
    }
  };

  const matchesSafe = (el: Element, selector: string): boolean => {
    if (!selector) return false;
    try {
      return el.matches(selector);
    } catch {
      return false;
    }
  };

  const isElementVisible = (el: Element): boolean => {
    let current: Element | null = el;
    while (current) {
      if (current.hasAttribute('hidden')) {
        return false;
      }
      const htmlCurrent = current as HTMLElement;
      if (
        htmlCurrent.style &&
        (htmlCurrent.style.display === 'none' || htmlCurrent.style.visibility === 'hidden')
      ) {
        return false;
      }
      if (typeof window !== 'undefined' && typeof window.getComputedStyle === 'function') {
        const computed = window.getComputedStyle(current);
        if (computed.display === 'none' || computed.visibility === 'hidden') {
          return false;
        }
      }
      current = current.parentElement;
    }
    return true;
  };

  const hasLoginInput = Boolean(querySafe(selectors.personCodeInputSelector));
  const hasPasswordInput = Boolean(querySafe(selectors.passwordInputSelector));

  const submitMatches = queryAllSafe(selectors.credentialsSubmitButtonSelector);
  const hasVisibleSubmitButton = submitMatches.some((el) => {
    if (selectors.jafTrapSelectors.some((trapSel) => matchesSafe(el, trapSel))) {
      return false;
    }
    return isElementVisible(el);
  });

  const hasJafVisuallyHiddenTrap =
    selectors.jafTrapSelectors.some((trapSel) => Boolean(querySafe(trapSel))) ||
    queryAllSafe(selectors.credentialsFallbackSubmitButtonSelector).some(
      (btn) => !submitMatches.includes(btn)
    );

  const hasOtpInput = Boolean(
    querySafe(selectors.otpInputSelector) || querySafe(selectors.fallbackOtpInputSelector)
  );
  const hasSubmitDissmsTrap = selectors.dissmsTrapSelectors.some((idSel) =>
    Boolean(querySafe(idSel))
  );

  const hasSsoHandoffForm = Boolean(
    querySafe(selectors.ssoHandoffFormSelector) ||
      querySafe(selectors.checkCookieInputSelector) ||
      querySafe(selectors.samlProtocolFormSelector)
  );

  const lowerHost = (window.location?.hostname || '').toLowerCase();
  const idpHost = selectors.idpHostname.toLowerCase();
  const onPolimiIdp =
    lowerHost === idpHost ||
    lowerHost.endsWith(`.${idpHost}`) ||
    ((lowerHost === 'polimi.it' || lowerHost.endsWith('.polimi.it')) &&
      (window.location?.pathname || '').includes(selectors.idpPathnameSubstring));
  const pathname = window.location?.pathname || '';
  const bodyText = (document.body?.textContent ?? '').toLowerCase();
  const hasContinueLink = Boolean(
    querySafe(selectors.continueToPortalSelector) ||
      querySafe(selectors.fallbackContinueToPortalSelector)
  );
  const hasExpiredSessionMarker =
    pathname.includes(selectors.sessionTerminatedMarker) ||
    selectors.sessionExpiredTextMarkers.some((marker) =>
      bodyText.includes(marker.toLowerCase())
    ) ||
    (onPolimiIdp && hasContinueLink);

  const hasAuthenticatedMarker = selectors.authenticatedDomSelectors.some((sel) =>
    Boolean(querySafe(sel))
  );

  const hasEmptyBody =
    bodyText.trim().length === 0 && !document.querySelector('form, input, button, a[href]');

  const hasMaintenanceBanner =
    selectors.maintenanceBannerSelectors.some((sel) => {
      const matched = querySafe(sel);
      if (!matched) return false;
      const text = (matched.textContent || '').toLowerCase();
      return selectors.maintenanceTextPatterns.some((pattern) =>
        text.includes(pattern.toLowerCase())
      );
    }) ||
    (!hasLoginInput &&
      !hasPasswordInput &&
      !hasOtpInput &&
      !hasSsoHandoffForm &&
      !hasExpiredSessionMarker &&
      !hasAuthenticatedMarker &&
      selectors.maintenanceTextPatterns.some((pattern) =>
        bodyText.includes(pattern.toLowerCase())
      ));

  const otpForm =
    querySafe(selectors.otpFormSelector) ||
    querySafe(selectors.otpInputSelector)?.closest?.('form') ||
    querySafe(selectors.fallbackOtpInputSelector)?.closest?.('form') ||
    null;

  let otpFormButtonInventory: LivePortalFormButtonInventoryEntry[] | undefined;
  if (hasOtpInput || otpForm) {
    const scope: Element | Document = otpForm ?? document;
    const rawControls = Array.from(
      scope.querySelectorAll('button, input[type="submit"], input[type="button"], a[role="button"], a.btn')
    );
    const otpPrimaryParts = selectors.otpSubmitButtonSelector
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    otpFormButtonInventory = rawControls.map((el, index) => {
      const visible = isElementVisible(el);
      const classes = typeof el.className === 'string' ? el.className.trim() : '';
      const id = el.getAttribute('id') || undefined;
      const name = el.getAttribute('name') || undefined;
      const type = el.getAttribute('type') || undefined;
      const rawText = el.textContent || (el as HTMLInputElement).value || '';
      const text = rawText.replace(/\s+/g, ' ').trim();
      const isJafTrap =
        selectors.jafTrapSelectors.some((trapSel) => matchesSafe(el, trapSel)) ||
        classes.split(/\s+/).includes('jaf-visually-hidden');
      const isDissmsTrap =
        id === 'submit-dissms' ||
        selectors.dissmsTrapSelectors.some((trapSel) => matchesSafe(el, trapSel));
      const matchesPrimary =
        visible && otpPrimaryParts.some((sel) => matchesSafe(el, sel));
      return {
        index,
        tagName: el.tagName.toLowerCase(),
        ...(id ? { id } : {}),
        ...(name ? { name } : {}),
        ...(type ? { type } : {}),
        classes,
        text,
        visible,
        matchesPrimaryOtpSelector: matchesPrimary,
        isSubmitDissmsTrap: isDissmsTrap,
        isJafVisuallyHiddenTrap: isJafTrap
      };
    });
  }

  let hasErrorBannerSelector = false;
  const errorMessages: string[] = [];
  for (const errSel of selectors.errorBannerSelectors) {
    const matched = querySafe(errSel);
    if (matched) {
      hasErrorBannerSelector = true;
      const text = matched.textContent?.trim();
      if (text && !errorMessages.includes(text)) {
        errorMessages.push(text);
      }
    }
  }

  return {
    hasLoginInput,
    hasPasswordInput,
    hasVisibleSubmitButton,
    hasJafVisuallyHiddenTrap,
    hasOtpInput,
    hasSubmitDissmsTrap,
    hasSsoHandoffForm,
    hasExpiredSessionMarker,
    hasAuthenticatedMarker,
    hasErrorBannerSelector,
    hasMaintenanceBanner,
    hasEmptyBody,
    ...(otpFormButtonInventory ? { otpFormButtonInventory } : {}),
    ...(errorMessages.length > 0 ? { rawErrorMessage: errorMessages.join(' | ') } : {})
  };
}

async function runWithNetworkTelemetry<T>(
  page: PlaywrightPageLike,
  action: () => Promise<T>,
  targetUrlHint: string,
  redaction?: ProbeRedactionContext
): Promise<{
  result: T;
  redirectChain: LivePortalRedirectHop[];
  cspHeadersDetected: string[];
  finalHttpStatus?: number;
}> {
  const extraSecrets = redaction?.extraSecrets ?? [];
  const customRules = redaction?.redactionRules ?? [];
  const observable = page as ObservablePageLike;
  const recordedResponses: Array<{
    response: PlaywrightResponseTelemetryLike;
    timestampIso: string;
  }> = [];

  const responseListener = (arg: unknown) => {
    if (isResponseLike(arg) && isNavigationResponse(arg)) {
      recordedResponses.push({
        response: arg,
        timestampIso: new Date().toISOString()
      });
    }
  };

  if (typeof observable.on === 'function') {
    observable.on('response', responseListener);
  }

  let result: T;
  try {
    result = await action();
  } finally {
    if (typeof observable.off === 'function') {
      observable.off('response', responseListener);
    } else if (typeof observable.removeListener === 'function') {
      observable.removeListener('response', responseListener);
    }
  }

  const redirectChain: LivePortalRedirectHop[] = [];
  const cspSet = new Set<string>();

  if (recordedResponses.length > 0) {
    for (let i = 0; i < recordedResponses.length; i++) {
      const entry = recordedResponses[i]!;
      const built = await createHopFromResponse(
        i,
        entry.response,
        entry.timestampIso,
        redaction
      );
      redirectChain.push(built.hop);
      for (const csp of built.cspHeaders) {
        cspSet.add(csp);
      }
    }
  } else if (isResponseLike(result)) {
    const captured = await captureRedirectChainFromResponse(result, redaction);
    redirectChain.push(...captured.hops);
    for (const csp of captured.cspHeaders) {
      cspSet.add(csp);
    }
  } else {
    const nowIso = new Date().toISOString();
    const sanitizedTarget = redactSecrets(targetUrlHint, extraSecrets, customRules);
    const sanitizedFinal = redactSecrets(page.url(), extraSecrets, customRules);
    if (sanitizedTarget) {
      redirectChain.push({
        stepIndex: 0,
        url: sanitizedTarget,
        timestampIso: nowIso
      });
    }
    if (sanitizedFinal && sanitizedFinal !== sanitizedTarget) {
      redirectChain.push({
        stepIndex: redirectChain.length,
        url: sanitizedFinal,
        timestampIso: nowIso
      });
    }
  }

  let finalHttpStatus: number | undefined;
  for (let i = redirectChain.length - 1; i >= 0; i--) {
    const hopStatus = redirectChain[i]?.status;
    if (hopStatus !== undefined) {
      finalHttpStatus = hopStatus;
      break;
    }
  }

  return {
    result,
    redirectChain,
    cspHeadersDetected: Array.from(cspSet),
    ...(finalHttpStatus !== undefined ? { finalHttpStatus } : {})
  };
}

async function detectAndInjectAdapters(
  rawPage: PlaywrightPageLike,
  trackedPage: PlaywrightPageLike,
  driver: PlaywrightAuthPageDriver,
  logger: AuthLoggerPort | undefined
): Promise<'evaluate' | 'addScriptTag' | 'pre_injected'> {
  let addScriptTagUsed = false;
  const spyLogger: AuthLoggerPort | undefined = logger
    ? {
        debug: (m, ...meta) => logger.debug(m, ...meta),
        info: (m, ...meta) => logger.info(m, ...meta),
        warn: (m, ...meta) => {
          if (m.includes('addScriptTag')) {
            addScriptTagUsed = true;
          }
          logger.warn(m, ...meta);
        },
        error: (m, ...meta) => logger.error(m, ...meta)
      }
    : {
        debug: () => undefined,
        info: () => undefined,
        warn: (m) => {
          if (m.includes('addScriptTag')) {
            addScriptTagUsed = true;
          }
        },
        error: () => undefined
      };

  let alreadyInjected = false;
  try {
    alreadyInjected = Boolean(
      await rawPage.evaluate(() => typeof window.__PoliAuthAdapters !== 'undefined')
    );
  } catch (err) {
    if (!isTransientNavigationError(err)) {
      throw err;
    }
  }

  if (alreadyInjected) {
    return 'pre_injected';
  }

  let injected = await ensureAuthAdaptersInjected(trackedPage, spyLogger);
  if (!injected) {
    await driver.waitForNavigation(1_500);
    injected = await ensureAuthAdaptersInjected(trackedPage, spyLogger);
  }

  if (addScriptTagUsed) {
    return 'addScriptTag';
  }
  return 'evaluate';
}

async function evaluateDomSnapshotSafe(
  page: PlaywrightPageLike,
  driver: PlaywrightAuthPageDriver,
  selectorBundle: DerivedDomSelectorBundle,
  inspectionErrorMessage?: string,
  redaction?: ProbeRedactionContext
): Promise<LivePortalDomTrapProbeResult> {
  const extraSecrets = redaction?.extraSecrets ?? [];
  const customRules = redaction?.redactionRules ?? [];
  let raw: RawDomSnapshotEvaluation | undefined;
  try {
    raw = await page.evaluate(collectDomSnapshotInPage, selectorBundle);
  } catch (err) {
    if (!isTransientNavigationError(err)) {
      throw err;
    }
    await driver.waitForNavigation(1_000);
    raw = await page.evaluate(collectDomSnapshotInPage, selectorBundle);
  }

  if (!raw || typeof raw !== 'object') {
    const fallbackErr = inspectionErrorMessage
      ? redactSecrets(inspectionErrorMessage.trim(), extraSecrets, customRules)
      : undefined;
    return {
      ...EMPTY_DOM_SNAPSHOT,
      hasErrorBanner: Boolean(fallbackErr),
      ...(fallbackErr ? { sanitizedErrorMessage: fallbackErr } : {})
    };
  }

  const combinedErr = raw.rawErrorMessage || inspectionErrorMessage;
  const sanitizedErrorMessage = combinedErr
    ? redactSecrets(combinedErr.trim(), extraSecrets, customRules)
    : undefined;
  const sanitizedButtonInventory = raw.otpFormButtonInventory
    ? raw.otpFormButtonInventory.map((entry) => ({
        ...entry,
        text: redactSecrets(entry.text, extraSecrets, customRules)
      }))
    : undefined;

  return {
    hasLoginInput: Boolean(raw.hasLoginInput),
    hasPasswordInput: Boolean(raw.hasPasswordInput),
    hasVisibleSubmitButton: Boolean(raw.hasVisibleSubmitButton),
    hasJafVisuallyHiddenTrap: Boolean(raw.hasJafVisuallyHiddenTrap),
    hasOtpInput: Boolean(raw.hasOtpInput),
    hasSubmitDissmsTrap: Boolean(raw.hasSubmitDissmsTrap),
    hasSsoHandoffForm: Boolean(raw.hasSsoHandoffForm),
    hasExpiredSessionMarker: Boolean(raw.hasExpiredSessionMarker),
    hasAuthenticatedMarker: Boolean(raw.hasAuthenticatedMarker),
    hasErrorBanner: Boolean(raw.hasErrorBannerSelector || sanitizedErrorMessage),
    hasMaintenanceBanner: Boolean(raw.hasMaintenanceBanner),
    hasEmptyBody: Boolean(raw.hasEmptyBody),
    ...(sanitizedButtonInventory ? { otpFormButtonInventory: sanitizedButtonInventory } : {}),
    ...(sanitizedErrorMessage ? { sanitizedErrorMessage } : {})
  };
}

async function executeStageInspection(params: {
  probeName: string;
  targetUrl: string;
  rawPage: PlaywrightPageLike;
  selectorBundle: DerivedDomSelectorBundle;
  driverOptions?: PlaywrightAuthPageDriverOptions;
  logger?: AuthLoggerPort;
  epistemicStatus: 'FACT:LIVE' | 'FACT:EXEC';
  navigateAction: () => Promise<unknown>;
  allowSsoHandoffSettle?: boolean;
  redaction?: ProbeRedactionContext;
  extraNotes?: readonly string[];
}): Promise<{
  record: LivePortalStageProbeRecord;
  driver: PlaywrightAuthPageDriver;
  intermediateRecords: LivePortalStageProbeRecord[];
}> {
  const {
    probeName,
    targetUrl,
    rawPage,
    selectorBundle,
    driverOptions,
    logger,
    epistemicStatus,
    navigateAction,
    allowSsoHandoffSettle,
    redaction,
    extraNotes
  } = params;

  const extraSecrets = redaction?.extraSecrets ?? [];
  const customRules = redaction?.redactionRules ?? [];
  const startedAt = Date.now();
  if (rawPage.isClosed?.()) {
    throw new Error('Target page, context or browser has been closed');
  }

  let addScriptTagInvoked = false;
  const trackedPage = createTrackedInjectionPage(rawPage, () => {
    addScriptTagInvoked = true;
  });
  const driver = new PlaywrightAuthPageDriver(trackedPage, {
    ...driverOptions,
    logger: logger ?? driverOptions?.logger
  });

  const telemetry = await runWithNetworkTelemetry(rawPage, navigateAction, targetUrl, redaction);
  await driver.waitForNavigation(3_000);

  const detectedMethod = await detectAndInjectAdapters(rawPage, trackedPage, driver, logger);
  let inspection = await driver.inspectPolimiStage();

  const adapterInjectionMethod: 'evaluate' | 'addScriptTag' | 'pre_injected' = addScriptTagInvoked
    ? 'addScriptTag'
    : detectedMethod;

  const notes: string[] = [...(extraNotes ?? [])];
  const intermediateRecords: LivePortalStageProbeRecord[] = [];

  if (allowSsoHandoffSettle && inspection.stage === 'sso_handoff') {
    const handoffSnapshot = await evaluateDomSnapshotSafe(
      rawPage,
      driver,
      selectorBundle,
      inspection.errorMessage,
      redaction
    );
    intermediateRecords.push({
      probeName: `${probeName}_sso_handoff`,
      targetUrl: redactSecrets(targetUrl, extraSecrets, customRules),
      finalUrl: redactSecrets(inspection.url || rawPage.url(), extraSecrets, customRules),
      inspectedStage: 'sso_handoff',
      adapterInjectionMethod,
      ...(telemetry.finalHttpStatus !== undefined ? { httpStatus: telemetry.finalHttpStatus } : {}),
      redirectChain: telemetry.redirectChain,
      cspHeadersDetected: telemetry.cspHeadersDetected,
      domSnapshot: handoffSnapshot,
      durationMs: Math.max(0, Date.now() - startedAt),
      epistemicStatus,
      notes: [
        redactSecrets(
          'Observed intermediate Stage 0.5 sso_handoff; waiting for redirect settle.',
          extraSecrets,
          customRules
        )
      ]
    });

    notes.push('Observed intermediate Stage 0.5 sso_handoff; waiting briefly for redirect settle.');
    for (let attempt = 0; attempt < 6 && inspection.stage === 'sso_handoff'; attempt++) {
      await driver.waitForNavigation(1_500);
      if (rawPage.waitForTimeout) {
        try {
          await rawPage.waitForTimeout(250);
        } catch (waitErr) {
          logger?.debug(
            `Post-sso_handoff waitForTimeout interrupted: ${redactSensitiveErrorText(waitErr, extraSecrets, customRules)}`
          );
        }
      }
      inspection = await driver.inspectPolimiStage();
    }
    notes.push(`Post-sso_handoff settled stage: ${inspection.stage}.`);
  }

  const domSnapshot = await evaluateDomSnapshotSafe(
    rawPage,
    driver,
    selectorBundle,
    inspection.errorMessage,
    redaction
  );

  const effectiveHttpStatus = inspection.httpStatus ?? telemetry.finalHttpStatus;
  let failureClassification: PoliAuthFailureClassification | undefined;
  if (inspection.stage === 'unknown') {
    failureClassification =
      inspection.diagnosticError?.classification ??
      classifyPolimiFailure({
        component: '@polisdk/poliauth-playwright/live-portal-probe',
        operation: probeName,
        stage: inspection.stage,
        url: inspection.url || rawPage.url(),
        httpStatus: effectiveHttpStatus,
        diagnosticSnapshot: inspection.diagnosticSnapshot,
        extraSecrets,
        customRules
      }).classification;
    notes.push(`Diagnostic classification: ${failureClassification}.`);
  }

  const sanitizedTarget = redactSecrets(targetUrl, extraSecrets, customRules);
  const sanitizedFinal = redactSecrets(inspection.url || rawPage.url(), extraSecrets, customRules);
  if (telemetry.cspHeadersDetected.length === 0) {
    notes.push('No Content-Security-Policy response headers captured on navigation hops.');
  }

  const record: LivePortalStageProbeRecord = {
    probeName,
    targetUrl: sanitizedTarget,
    finalUrl: sanitizedFinal,
    inspectedStage: inspection.stage,
    adapterInjectionMethod,
    ...(effectiveHttpStatus !== undefined ? { httpStatus: effectiveHttpStatus } : {}),
    ...(failureClassification ? { failureClassification } : {}),
    redirectChain: telemetry.redirectChain,
    cspHeadersDetected: telemetry.cspHeadersDetected,
    domSnapshot,
    durationMs: Math.max(0, Date.now() - startedAt),
    epistemicStatus,
    notes: notes.map((note) => redactSecrets(note, extraSecrets, customRules))
  };

  return { record, driver, intermediateRecords };
}

/**
 * Executes a read-only diagnostic probe against Politecnico di Milano IdP entry stages
 * (`Stage 0` bare `/aunicalogin/` expired-session recovery and `Stage 0 -> 0.5 -> 1` service entry),
 * and optionally an opt-in authenticated E2E probe (`probeAuthenticatedFlow: true`) with strict
 * 1-attempt credential/OTP circuit breakers and full secret redaction.
 */
export async function runPolimiLivePortalProbe(
  options: LivePortalProbeOptions
): Promise<LivePortalProbeReport> {
  const generatedAtIso = new Date().toISOString();
  const spec = options.spec ?? POLIMI_LOGIN_FLOW_SPEC;
  const redactionCtx = createCredentialRedactionContext(
    options.credentials,
    options.extraSecrets ?? [],
    options.redactionRules ?? []
  );

  const safeLogger = options.logger
    ? createRedactingLogger(
        options.logger,
        redactionCtx.extraSecrets,
        redactionCtx.redactionRules
      )
    : options.driverOptions?.logger
      ? createRedactingLogger(
          options.driverOptions.logger,
          redactionCtx.extraSecrets,
          redactionCtx.redactionRules
        )
      : undefined;

  const environment: 'live_network' | 'synthetic_harness' =
    options.environment ??
    (isLivePortalProbeEnabled() && isRealPlaywrightPage(options.page)
      ? 'live_network'
      : 'synthetic_harness');
  const epistemicStatus: 'FACT:LIVE' | 'FACT:EXEC' =
    environment === 'live_network' ? 'FACT:LIVE' : 'FACT:EXEC';

  const selectorBundle = buildSelectorBundle(spec);
  const navigationTimeoutMs = options.driverOptions?.navigationTimeoutMs ?? 35_000;
  const stages: LivePortalStageProbeRecord[] = [];
  const errors: string[] = [];

  const handleFailure = (
    probeName: string,
    targetUrl: string,
    err: unknown,
    startedAt: number,
    fallbackClassification?: PoliAuthFailureClassification
  ): boolean => {
    const redactedErr = redactSensitiveErrorText(
      err,
      redactionCtx.extraSecrets,
      redactionCtx.redactionRules
    );
    safeLogger?.error(`Live portal probe "${probeName}" failed: ${redactedErr}`);
    errors.push(`${probeName}: ${redactedErr}`);

    let currentUrl = targetUrl;
    try {
      currentUrl = options.page.url() || targetUrl;
    } catch (urlErr) {
      safeLogger?.debug(
        `Unable to read page.url() after probe failure: ${redactSensitiveErrorText(urlErr, redactionCtx.extraSecrets, redactionCtx.redactionRules)}`
      );
      currentUrl = targetUrl;
    }

    const diagnosticClassification =
      err instanceof PoliAuthDiagnosticError
        ? err.payload.classification
        : (fallbackClassification ??
          classifyPolimiFailure({
            component: '@polisdk/poliauth-playwright/live-portal-probe',
            operation: probeName,
            url: currentUrl,
            selectorOrEndpoint: targetUrl,
            error: err,
            extraSecrets: redactionCtx.extraSecrets,
            customRules: redactionCtx.redactionRules
          }).classification);

    stages.push({
      probeName,
      targetUrl: redactSecrets(
        targetUrl,
        redactionCtx.extraSecrets,
        redactionCtx.redactionRules
      ),
      finalUrl: redactSecrets(
        currentUrl,
        redactionCtx.extraSecrets,
        redactionCtx.redactionRules
      ),
      inspectedStage: 'error',
      adapterInjectionMethod: 'evaluate',
      failureClassification: diagnosticClassification,
      redirectChain: [],
      cspHeadersDetected: [],
      domSnapshot: { ...EMPTY_DOM_SNAPSHOT },
      durationMs: Math.max(0, Date.now() - startedAt),
      epistemicStatus,
      notes: [`Probe failed (${diagnosticClassification}): ${redactedErr}`]
    });

    return isClosedTargetError(err) || Boolean(options.page.isClosed?.());
  };

  let abortedEarly = false;
  let latestDriver: PlaywrightAuthPageDriver | undefined;
  let latestRecord: LivePortalStageProbeRecord | undefined;

  // Probe 1: Stage 0 Bare /aunicalogin/ Expired-Session Trap & Recovery
  if (options.probeBareAunicaloginRecovery !== false) {
    const bareUrl = resolveBareAunicaloginUrl(spec);
    const probe1Start = Date.now();
    try {
      const stage0Result = await executeStageInspection({
        probeName: 'stage_0_bare_aunicalogin',
        targetUrl: bareUrl,
        rawPage: options.page,
        selectorBundle,
        driverOptions: options.driverOptions,
        logger: safeLogger,
        epistemicStatus,
        redaction: redactionCtx,
        navigateAction: () =>
          options.page.goto(bareUrl, {
            waitUntil: 'domcontentloaded',
            timeout: navigationTimeoutMs
          })
      });
      stages.push(...stage0Result.intermediateRecords, stage0Result.record);
      latestDriver = stage0Result.driver;
      latestRecord = stage0Result.record;

      if (stage0Result.record.inspectedStage === 'session_expired') {
        const recoveryStart = Date.now();
        try {
          let recoveryOutcome: { ok: boolean; navigatedTo: string } = {
            ok: false,
            navigatedTo: spec.entry.serviceEntryUrl
          };
          const recoveryStage = await executeStageInspection({
            probeName: 'stage_0_session_recovery',
            targetUrl: spec.entry.serviceEntryUrl,
            rawPage: options.page,
            selectorBundle,
            driverOptions: options.driverOptions,
            logger: safeLogger,
            epistemicStatus,
            allowSsoHandoffSettle: true,
            redaction: redactionCtx,
            navigateAction: async () => {
              recoveryOutcome = await stage0Result.driver.recoverSessionPage();
              return undefined;
            }
          });
          const recoveryNotes = [
            ...recoveryStage.record.notes,
            redactSecrets(
              `recoverSessionPage() ok=${String(recoveryOutcome.ok)} navigatedTo=${recoveryOutcome.navigatedTo}`,
              redactionCtx.extraSecrets,
              redactionCtx.redactionRules
            )
          ];
          const adjustedRecoveryRecord: LivePortalStageProbeRecord = {
            ...recoveryStage.record,
            targetUrl: redactSecrets(
              recoveryOutcome.navigatedTo || spec.entry.serviceEntryUrl,
              redactionCtx.extraSecrets,
              redactionCtx.redactionRules
            ),
            notes: recoveryNotes
          };
          stages.push(...recoveryStage.intermediateRecords, adjustedRecoveryRecord);
          latestDriver = recoveryStage.driver;
          latestRecord = adjustedRecoveryRecord;
        } catch (err) {
          abortedEarly = handleFailure(
            'stage_0_session_recovery',
            spec.entry.serviceEntryUrl,
            err,
            recoveryStart
          );
        }
      }
    } catch (err) {
      abortedEarly = handleFailure('stage_0_bare_aunicalogin', bareUrl, err, probe1Start);
    }
  }

  // Probe 2: Stage 0 -> Stage 0.5 (AunicaLogin.do) -> Stage 1 (IdentificazioneUnica.do) Entry & JAF Trap Audit
  if (!abortedEarly && options.probeServiceEntryToCredentials !== false) {
    const serviceEntryUrl = spec.entry.serviceEntryUrl;
    const probe2Start = Date.now();
    try {
      const stage1Result = await executeStageInspection({
        probeName: 'stage_1_service_entry_credentials',
        targetUrl: serviceEntryUrl,
        rawPage: options.page,
        selectorBundle,
        driverOptions: options.driverOptions,
        logger: safeLogger,
        epistemicStatus,
        allowSsoHandoffSettle: true,
        redaction: redactionCtx,
        navigateAction: () =>
          options.page.goto(serviceEntryUrl, {
            waitUntil: 'domcontentloaded',
            timeout: navigationTimeoutMs
          })
      });
      stages.push(...stage1Result.intermediateRecords, stage1Result.record);
      latestDriver = stage1Result.driver;
      latestRecord = stage1Result.record;
    } catch (err) {
      abortedEarly = handleFailure(
        'stage_1_service_entry_credentials',
        serviceEntryUrl,
        err,
        probe2Start
      );
    }
  }

  // Probe 3 (Opt-In Only): Authenticated Stages 1 -> 2 -> 0.5 -> 3 with strict 1-attempt circuit breakers
  if (!abortedEarly && options.probeAuthenticatedFlow) {
    const authCreds = options.credentials;
    if (!authCreds) {
      errors.push('probeAuthenticatedFlow enabled without credentials.');
      abortedEarly = true;
    } else {
      registerSecretValue(redactionCtx, authCreds.personCode, false);
      registerSecretValue(redactionCtx, authCreds.password, false);
      registerSecretValue(redactionCtx, authCreds.totpSecret, true);
      registerSecretValue(redactionCtx, cleanTotpSecret(authCreds.totpSecret), true);
      registerSecretValue(redactionCtx, authCreds.polimiEmail, true);

      let credentialsSubmitCount = 0;
      let otpSubmitCount = 0;

      // Ensure we have a baseline inspected stage when Probe 2 was skipped
      if (!latestRecord || !latestDriver) {
        const entryUrl = spec.entry.serviceEntryUrl;
        const entryStart = Date.now();
        try {
          const baseline = await executeStageInspection({
            probeName: 'stage_1_service_entry_credentials',
            targetUrl: entryUrl,
            rawPage: options.page,
            selectorBundle,
            driverOptions: options.driverOptions,
            logger: safeLogger,
            epistemicStatus,
            allowSsoHandoffSettle: true,
            redaction: redactionCtx,
            navigateAction: () =>
              options.page.goto(entryUrl, {
                waitUntil: 'domcontentloaded',
                timeout: navigationTimeoutMs
              })
          });
          stages.push(...baseline.intermediateRecords, baseline.record);
          latestDriver = baseline.driver;
          latestRecord = baseline.record;
        } catch (err) {
          abortedEarly = handleFailure(
            'stage_1_service_entry_credentials',
            entryUrl,
            err,
            entryStart
          );
        }
      }

      if (!abortedEarly && latestRecord && latestDriver) {
        if (latestRecord.domSnapshot.hasErrorBanner) {
          const msg =
            latestRecord.domSnapshot.sanitizedErrorMessage ||
            'Error banner visible prior to credential submission.';
          latestRecord.failureClassification =
            latestRecord.failureClassification ?? 'AUTHENTICATION_REJECTED';
          errors.push(`stage_1_service_entry_credentials: ${msg}`);
          abortedEarly = true;
        } else if (latestRecord.inspectedStage === 'credentials') {
          if (credentialsSubmitCount >= 1) {
            errors.push('Circuit breaker prevented credential retry.');
            abortedEarly = true;
          } else {
            credentialsSubmitCount += 1;
            const stage1SubmitStart = Date.now();
            const submitTargetUrl = latestRecord.finalUrl || spec.entry.serviceEntryUrl;
            let credSubmitResult: PolimiPageActionResult = {
              ok: false,
              error: 'Credential submission did not execute.'
            };

            try {
              const stage2Result = await executeStageInspection({
                probeName: 'stage_1_credentials_submit_to_otp',
                targetUrl: submitTargetUrl,
                rawPage: options.page,
                selectorBundle,
                driverOptions: options.driverOptions,
                logger: safeLogger,
                epistemicStatus,
                allowSsoHandoffSettle: true,
                redaction: redactionCtx,
                extraNotes: ['Submitted Stage 1 credentials (attempt 1/1).'],
                navigateAction: async () => {
                  const beforeUrl = options.page.url();
                  credSubmitResult = await latestDriver!.submitCredentials({
                    personCode: authCreds.personCode,
                    password: authCreds.password,
                    stayConnected: false
                  });
                  if (!credSubmitResult.ok) {
                    return undefined;
                  }
                  await latestDriver!.waitForNavigation(Math.min(navigationTimeoutMs, 10_000));
                  if (typeof options.page.waitForURL === 'function') {
                    await options.page
                      .waitForURL((u) => u.href !== beforeUrl, {
                        timeout: 6_000,
                        waitUntil: 'domcontentloaded'
                      })
                      .catch(() => undefined);
                  }
                  for (let tick = 0; tick < 8; tick++) {
                    const quick = await latestDriver!.inspectPolimiStage().catch(() => null);
                    if (!quick || quick.stage !== 'credentials' || quick.errorMessage) {
                      break;
                    }
                    if (options.page.waitForTimeout) {
                      await options.page.waitForTimeout(250).catch(() => undefined);
                    }
                    await latestDriver!.waitForNavigation(1_200);
                  }
                  return undefined;
                }
              });

              if (!credSubmitResult.ok) {
                const errText = redactSecrets(
                  credSubmitResult.error ||
                    credSubmitResult.diagnostic?.message ||
                    'Stage 1 credential submission failed.',
                  redactionCtx.extraSecrets,
                  redactionCtx.redactionRules
                );
                const classification =
                  credSubmitResult.diagnostic?.classification ?? 'AUTHENTICATION_REJECTED';
                stages.push(...stage2Result.intermediateRecords, {
                  ...stage2Result.record,
                  inspectedStage: 'error',
                  failureClassification: classification,
                  notes: [
                    ...stage2Result.record.notes,
                    `Credential submit failed (${classification}): ${errText}`
                  ]
                });
                errors.push(`stage_1_credentials_submit_to_otp: ${errText}`);
                abortedEarly = true;
              } else {
                stages.push(...stage2Result.intermediateRecords, stage2Result.record);
                latestDriver = stage2Result.driver;
                latestRecord = stage2Result.record;

                if (latestRecord.domSnapshot.hasErrorBanner) {
                  const msg =
                    latestRecord.domSnapshot.sanitizedErrorMessage ||
                    'Credentials rejected by PoliMi IdP; halting with zero retries.';
                  latestRecord.failureClassification =
                    latestRecord.failureClassification ?? 'AUTHENTICATION_REJECTED';
                  errors.push(`stage_1_credentials_submit_to_otp: ${msg}`);
                  abortedEarly = true;
                } else if (latestRecord.inspectedStage === 'credentials') {
                  latestRecord.failureClassification =
                    latestRecord.failureClassification ?? 'AUTHENTICATION_REJECTED';
                  errors.push(
                    'stage_1_credentials_submit_to_otp: Remained on credentials form after single submission; halting with zero retries.'
                  );
                  abortedEarly = true;
                }
              }
            } catch (err) {
              abortedEarly = handleFailure(
                'stage_1_credentials_submit_to_otp',
                submitTargetUrl,
                err,
                stage1SubmitStart
              );
            }
          }
        }
      }

      if (!abortedEarly && latestRecord && latestDriver && latestRecord.inspectedStage === 'otp') {
        if (latestRecord.domSnapshot.hasErrorBanner) {
          const msg =
            latestRecord.domSnapshot.sanitizedErrorMessage ||
            'Error banner visible on Stage 2 OTP page; halting with zero retries.';
          latestRecord.failureClassification =
            latestRecord.failureClassification ?? 'OTP_CHALLENGE_FAILED';
          errors.push(`stage_2_otp_submit_to_authenticated: ${msg}`);
          abortedEarly = true;
        } else if (otpSubmitCount >= 1) {
          errors.push('Circuit breaker prevented OTP retry.');
          abortedEarly = true;
        } else {
          otpSubmitCount += 1;
          const stage2SubmitStart = Date.now();
          const otpTargetUrl = latestRecord.finalUrl || spec.entry.serviceEntryUrl;
          let otpSubmitResult: PolimiPageActionResult = {
            ok: false,
            error: 'OTP submission did not execute.'
          };

          try {
            const stableTotp = await generateStableTotp(authCreds.totpSecret, {
              minRemainingSeconds: 5
            });
            registerSecretValue(redactionCtx, stableTotp.code, false);

            const stage3Result = await executeStageInspection({
              probeName: 'stage_2_otp_submit_to_authenticated',
              targetUrl: otpTargetUrl,
              rawPage: options.page,
              selectorBundle,
              driverOptions: options.driverOptions,
              logger: safeLogger,
              epistemicStatus,
              allowSsoHandoffSettle: true,
              redaction: redactionCtx,
              extraNotes: [
                `Submitted Stage 2 TOTP (attempt 1/1; minRemainingSeconds=5; remainingSeconds=${String(stableTotp.remainingSeconds)}; waitedMs=${String(stableTotp.waitedMs)}).`
              ],
              navigateAction: async () => {
                const beforeUrl = options.page.url();
                otpSubmitResult = await latestDriver!.submitOtp({ otp: stableTotp.code });
                if (!otpSubmitResult.ok) {
                  return undefined;
                }
                await latestDriver!.waitForNavigation(Math.min(navigationTimeoutMs, 10_000));
                if (typeof options.page.waitForURL === 'function') {
                  await options.page
                    .waitForURL((u) => u.href !== beforeUrl, {
                      timeout: 8_000,
                      waitUntil: 'domcontentloaded'
                    })
                    .catch(() => undefined);
                }
                for (let tick = 0; tick < 10; tick++) {
                  const quick = await latestDriver!.inspectPolimiStage().catch(() => null);
                  if (!quick || quick.stage !== 'otp' || quick.errorMessage) {
                    break;
                  }
                  if (options.page.waitForTimeout) {
                    await options.page.waitForTimeout(300).catch(() => undefined);
                  }
                  await latestDriver!.waitForNavigation(1_200);
                }
                return undefined;
              }
            });

            if (!otpSubmitResult.ok) {
              const errText = redactSecrets(
                otpSubmitResult.error ||
                  otpSubmitResult.diagnostic?.message ||
                  'Stage 2 OTP submission failed.',
                redactionCtx.extraSecrets,
                redactionCtx.redactionRules
              );
              const classification =
                otpSubmitResult.diagnostic?.classification ?? 'OTP_CHALLENGE_FAILED';
              stages.push(...stage3Result.intermediateRecords, {
                ...stage3Result.record,
                inspectedStage: 'error',
                failureClassification: classification,
                notes: [
                  ...stage3Result.record.notes,
                  `OTP submit failed (${classification}): ${errText}`
                ]
              });
              errors.push(`stage_2_otp_submit_to_authenticated: ${errText}`);
              abortedEarly = true;
            } else {
              stages.push(...stage3Result.intermediateRecords, stage3Result.record);
              latestDriver = stage3Result.driver;
              latestRecord = stage3Result.record;

              if (latestRecord.domSnapshot.hasErrorBanner) {
                const msg =
                  latestRecord.domSnapshot.sanitizedErrorMessage ||
                  'OTP rejected by PoliMi IdP; halting with zero retries.';
                latestRecord.failureClassification =
                  latestRecord.failureClassification ?? 'OTP_CHALLENGE_FAILED';
                errors.push(`stage_2_otp_submit_to_authenticated: ${msg}`);
                abortedEarly = true;
              } else if (latestRecord.inspectedStage !== 'authenticated') {
                const fallbackClass =
                  latestRecord.inspectedStage === 'otp'
                    ? 'OTP_CHALLENGE_FAILED'
                    : (latestRecord.failureClassification ?? 'UNKNOWN_FAILURE');
                latestRecord.failureClassification = fallbackClass;
                errors.push(
                  `stage_2_otp_submit_to_authenticated: Expected Stage 3 authenticated session, observed '${latestRecord.inspectedStage}'.`
                );
                abortedEarly = true;
              }
            }
          } catch (err) {
            abortedEarly = handleFailure(
              'stage_2_otp_submit_to_authenticated',
              otpTargetUrl,
              err,
              stage2SubmitStart
            );
          }
        }
      }
    }
  }

  // Optional Custom URLs to inspect (read-only)
  if (!abortedEarly && options.customUrlsToInspect && options.customUrlsToInspect.length > 0) {
    for (let i = 0; i < options.customUrlsToInspect.length; i++) {
      const customUrl = options.customUrlsToInspect[i]!;
      const probeName = `custom_url_${i + 1}`;
      const start = Date.now();
      try {
        const customResult = await executeStageInspection({
          probeName,
          targetUrl: customUrl,
          rawPage: options.page,
          selectorBundle,
          driverOptions: options.driverOptions,
          logger: safeLogger,
          epistemicStatus,
          allowSsoHandoffSettle: true,
          redaction: redactionCtx,
          navigateAction: () =>
            options.page.goto(customUrl, {
              waitUntil: 'domcontentloaded',
              timeout: navigationTimeoutMs
            })
        });
        stages.push(...customResult.intermediateRecords, customResult.record);
      } catch (err) {
        abortedEarly = handleFailure(probeName, customUrl, err, start);
        if (abortedEarly) {
          break;
        }
      }
    }
  }

  const overallSuccess =
    errors.length === 0 && stages.every((stage) => stage.inspectedStage !== 'error');

  return {
    generatedAtIso,
    environment,
    stages,
    overallSuccess,
    ...(errors.length > 0
      ? {
          errorSummary: redactSecrets(
            errors.join(' | '),
            redactionCtx.extraSecrets,
            redactionCtx.redactionRules
          )
        }
      : {})
  };
}

/**
 * Convenience helper combining `loadLiveProbeCredentialsFromEnv()` with
 * `runPolimiLivePortalProbe({ ..., probeAuthenticatedFlow: true })`.
 */
export async function runAuthenticatedPolimiLivePortalProbe(
  options: AuthenticatedLivePortalProbeOptions
): Promise<LivePortalProbeReport> {
  if (options.credentials) {
    return runPolimiLivePortalProbe({
      ...options,
      probeAuthenticatedFlow: true
    });
  }

  const loaded = await loadLiveProbeCredentialsFromEnv(options.envFilePath, options.env);
  if (!loaded.ok || !loaded.credentials) {
    const generatedAtIso = new Date().toISOString();
    const environment: 'live_network' | 'synthetic_harness' =
      options.environment ??
      (isLivePortalProbeEnabled(options.env) && isRealPlaywrightPage(options.page)
        ? 'live_network'
        : 'synthetic_harness');
    const summary = redactSecrets(
      `Failed to load .env credentials (source=${loaded.source}): ${loaded.errors.join(' ')}`,
      [...loaded.extraSecrets, ...(options.extraSecrets ?? [])],
      [...loaded.redactionRules, ...(options.redactionRules ?? [])]
    );
    return {
      generatedAtIso,
      environment,
      stages: [],
      overallSuccess: false,
      errorSummary: summary
    };
  }

  return runPolimiLivePortalProbe({
    ...options,
    credentials: loaded.credentials,
    probeAuthenticatedFlow: true,
    extraSecrets: [...loaded.extraSecrets, ...(options.extraSecrets ?? [])],
    redactionRules: [...loaded.redactionRules, ...(options.redactionRules ?? [])]
  });
}

function escapeCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim();
}

/**
 * Deterministically formats a `LivePortalProbeReport` into Markdown tables compatible
 * with `packages/poliauth/docs/06-live-polimi-website-verification-ledger.md`.
 */
export function formatLivePortalProbeReportMarkdown(
  report: LivePortalProbeReport,
  extraSecrets: readonly string[] = [],
  customRules: readonly RedactionRule[] = []
): string {
  const scrub = (value: string): string =>
    redactSecrets(value, [...extraSecrets], [...customRules]);

  const envLabel =
    report.environment === 'live_network' ? 'live_network' : 'synthetic_harness';
  const lines: string[] = [
    `### Automated Portal Probe Telemetry (${escapeCell(report.generatedAtIso)})`,
    '',
    `- **Environment:** \`${envLabel}\``,
    `- **Overall Success:** \`${String(report.overallSuccess)}\``,
    `- **Stages Probed:** \`${String(report.stages.length)}\``
  ];

  if (report.errorSummary) {
    lines.push(`- **Error Summary:** \`${escapeCell(scrub(report.errorSummary))}\``);
  }

  lines.push(
    '',
    '#### Stage Telemetry & Redirect Matrix',
    '',
    '| Probe | Target URL | Final URL | Inspected Stage | Adapter Injection | Redirect Hops | CSP Headers | Duration (ms) | Epistemic Status |',
    '| :--- | :--- | :--- | :--- | :--- | :---: | :--- | :---: | :--- |'
  );

  for (const stage of report.stages) {
    const cspCell =
      stage.cspHeadersDetected.length > 0
        ? stage.cspHeadersDetected.map((c) => escapeCell(scrub(c))).join('; ')
        : 'None';
    lines.push(
      `| \`${escapeCell(stage.probeName)}\` | \`${escapeCell(scrub(stage.targetUrl))}\` | \`${escapeCell(scrub(stage.finalUrl))}\` | \`${escapeCell(stage.inspectedStage)}\` | \`${escapeCell(stage.adapterInjectionMethod)}\` | ${String(stage.redirectChain.length)} | ${cspCell} | ${String(stage.durationMs)} | \`[${stage.epistemicStatus}]\` |`
    );
  }

  lines.push(
    '',
    '#### DOM Selector & Trap Audit Matrix',
    '',
    '| Probe | `#login` | `#password` | Visible Submit | JAF Trap | `#otp` | `#submit-dissms` | SSO Handoff | Expired Marker | Auth Marker | Error Banner | Sanitized Error |',
    '| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |'
  );

  for (const stage of report.stages) {
    const d = stage.domSnapshot;
    const errText = d.sanitizedErrorMessage
      ? `\`${escapeCell(scrub(d.sanitizedErrorMessage))}\``
      : '—';
    lines.push(
      `| \`${escapeCell(stage.probeName)}\` | ${String(d.hasLoginInput)} | ${String(d.hasPasswordInput)} | ${String(d.hasVisibleSubmitButton)} | ${String(d.hasJafVisuallyHiddenTrap)} | ${String(d.hasOtpInput)} | ${String(d.hasSubmitDissmsTrap)} | ${String(d.hasSsoHandoffForm)} | ${String(d.hasExpiredSessionMarker)} | ${String(d.hasAuthenticatedMarker)} | ${String(d.hasErrorBanner)} | ${errText} |`
    );
  }

  const stagesWithButtonInventory = report.stages.filter(
    (s) => s.domSnapshot.otpFormButtonInventory && s.domSnapshot.otpFormButtonInventory.length > 0
  );
  if (stagesWithButtonInventory.length > 0) {
    lines.push(
      '',
      '#### Stage 2 Button Inventory (`form#form_scelta2fa`)',
      '',
      '| Probe | Index | Tag | `id` | `name` | `type` | Visible | Text | Matches Primary OTP | `#submit-dissms` Trap | JAF Hidden Trap | Classes |',
      '| :--- | :---: | :--- | :--- | :--- | :--- | :---: | :--- | :---: | :---: | :---: | :--- |'
    );
    for (const stage of stagesWithButtonInventory) {
      for (const btn of stage.domSnapshot.otpFormButtonInventory ?? []) {
        lines.push(
          `| \`${escapeCell(stage.probeName)}\` | ${String(btn.index)} | \`${escapeCell(btn.tagName)}\` | ${btn.id ? `\`${escapeCell(btn.id)}\`` : '—'} | ${btn.name ? `\`${escapeCell(btn.name)}\`` : '—'} | ${btn.type ? `\`${escapeCell(btn.type)}\`` : '—'} | ${String(btn.visible)} | \`${escapeCell(scrub(btn.text || '—'))}\` | ${String(btn.matchesPrimaryOtpSelector)} | ${String(btn.isSubmitDissmsTrap)} | ${String(btn.isJafVisuallyHiddenTrap)} | ${btn.classes ? `\`${escapeCell(btn.classes)}\`` : '—'} |`
        );
      }
    }
  }

  const stagesWithDetails = report.stages.filter(
    (s) => s.redirectChain.length > 0 || s.notes.length > 0 || s.failureClassification !== undefined
  );
  if (stagesWithDetails.length > 0) {
    lines.push('', '#### Redirect Hops & Probe Notes', '');
    for (const stage of stagesWithDetails) {
      const statusTag =
        stage.httpStatus !== undefined ? ` HTTP ${String(stage.httpStatus)}` : '';
      const classTag = stage.failureClassification
        ? ` [${stage.failureClassification}]`
        : '';
      lines.push(
        `- **\`${escapeCell(stage.probeName)}\`** (\`[${stage.epistemicStatus}]\`${statusTag}${classTag}):`
      );
      for (const hop of stage.redirectChain) {
        const statusPart = hop.status !== undefined ? `HTTP ${String(hop.status)} ` : '';
        const locPart = hop.locationHeader
          ? ` -> Location: \`${escapeCell(scrub(hop.locationHeader))}\``
          : '';
        lines.push(
          `  - Hop ${String(hop.stepIndex)}: ${statusPart}\`${escapeCell(scrub(hop.url))}\`${locPart} (${escapeCell(hop.timestampIso)})`
        );
      }
      for (const note of stage.notes) {
        lines.push(`  - Note: ${escapeCell(scrub(note))}`);
      }
    }
  }

  return lines.join('\n');
}
