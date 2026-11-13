import {
  POLIMI_LOGIN_FLOW_SPEC,
  redactSecrets,
  redactSensitiveErrorText,
  type PolimiPageStage
} from '@polisdk/poliauth/domain';
import type { AuthLoggerPort } from '@polisdk/poliauth/interfaces';
import { SAML_PROTOCOL_FORM_SELECTOR } from '@polisdk/poliauth/adapters';
import { createRedactingLogger } from '@polisdk/poliauth/middleware';
import { ensureAuthAdaptersInjected } from './injected-auth-bundle.js';
import {
  PlaywrightAuthPageDriver,
  type PlaywrightAuthPageDriverOptions,
  type PlaywrightPageLike
} from './playwright-page-driver.js';

/**
 * Canonical authentication stage recorded by the live portal probe.
 * Extends `PolimiPageStage` with `'entry'` and `'error'` diagnostic states.
 */
export type PoliAuthStage = PolimiPageStage | 'entry' | 'error';

/**
 * Structural specification contract matching `POLIMI_LOGIN_FLOW_SPEC`.
 */
export interface PolimiLoginFlowSpec {
  readonly entry: {
    readonly requestedUrl: string;
    readonly serviceEntryUrl: string;
    readonly onlineServicesShortcutUrl: string;
    readonly ssoPortalServiceId: string;
    readonly idpHostname: string;
    readonly idpPathnameSubstring: string;
    readonly sessionTerminatedMarker: string;
    readonly sessionExpiredTextMarkers: readonly string[];
    readonly sessionExpiredSelectors: {
      readonly continueToPortalLink: string;
      readonly fallbackContinueToPortalLink: string;
      readonly logoutLink: string;
      readonly dangerAlert: string;
      readonly warningAlert: string;
    };
  };
  readonly ssoHandoffPage: {
    readonly formSelector: string;
    readonly checkCookieInputSelector: string;
  };
  readonly credentialsPage: {
    readonly titleSubstring: string;
    readonly urlSubstrings: readonly string[];
    readonly formSelector: string;
    readonly cardSelector: string;
    readonly personCodeInputSelector: string;
    readonly passwordInputSelector: string;
    readonly stayConnectedCheckboxSelector: string;
    readonly submitButtonSelector: string;
    readonly fallbackSubmitButtonSelector: string;
    readonly errorAlertSelector: string;
  };
  readonly otpPage: {
    readonly titleSubstring: string;
    readonly urlSubstrings: readonly string[];
    readonly formSelector: string;
    readonly otpInputSelector: string;
    readonly fallbackOtpInputSelector: string;
    readonly submitButtonSelector: string;
    readonly fallbackSubmitButtonSelector: string;
    readonly errorAlertSelector: string;
  };
  readonly authenticatedSession: {
    readonly portalHostname: string;
    readonly portalPathnameSubstring: string;
    readonly portalTitleSubstring: string;
    readonly authenticatedDomSelectors: readonly string[];
  };
  readonly samlIdentityProvider: {
    readonly transitHostnames: readonly string[];
  };
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
  sanitizedErrorMessage?: string;
}

export interface LivePortalStageProbeRecord {
  probeName: string;
  targetUrl: string;
  finalUrl: string;
  inspectedStage: PoliAuthStage;
  adapterInjectionMethod: 'evaluate' | 'addScriptTag' | 'pre_injected';
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
  customUrlsToInspect?: readonly string[];
  environment?: 'live_network' | 'synthetic_harness';
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

function readProcessEnv(): Record<string, string | undefined> | undefined {
  return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
}

/**
 * Returns `true` when live network portal probing is explicitly opted in (`POLIAUTH_LIVE_PROBE=1`).
 */
export function isLivePortalProbeEnabled(
  env: Record<string, string | undefined> | undefined = readProcessEnv()
): boolean {
  return env?.POLIAUTH_LIVE_PROBE === '1';
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
    errorBannerSelectors
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
  timestampIso: string
): Promise<{ hop: LivePortalRedirectHop; cspHeaders: string[] }> {
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
    cspHeaders.push(redactSecrets(rawCsp));
  }
  if (rawCspReportOnly) {
    cspHeaders.push(redactSecrets(rawCspReportOnly));
  }

  const sanitizedCsp = cspHeaders.length > 0 ? cspHeaders.join('; ') : undefined;

  return {
    hop: {
      stepIndex,
      url: redactSecrets(rawUrl),
      ...(status !== undefined ? { status } : {}),
      ...(rawLocation ? { locationHeader: redactSecrets(rawLocation) } : {}),
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
  finalResponse: PlaywrightResponseTelemetryLike
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
      const built = await createHopFromResponse(i, item.response, timestampIso);
      hops.push(built.hop);
      cspHeaders.push(...built.cspHeaders);
    } else {
      hops.push({
        stepIndex: i,
        url: redactSecrets(item.url),
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
    ...(errorMessages.length > 0 ? { rawErrorMessage: errorMessages.join(' | ') } : {})
  };
}

async function runWithNetworkTelemetry<T>(
  page: PlaywrightPageLike,
  action: () => Promise<T>,
  targetUrlHint: string
): Promise<{
  result: T;
  redirectChain: LivePortalRedirectHop[];
  cspHeadersDetected: string[];
}> {
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
      const built = await createHopFromResponse(i, entry.response, entry.timestampIso);
      redirectChain.push(built.hop);
      for (const csp of built.cspHeaders) {
        cspSet.add(csp);
      }
    }
  } else if (isResponseLike(result)) {
    const captured = await captureRedirectChainFromResponse(result);
    redirectChain.push(...captured.hops);
    for (const csp of captured.cspHeaders) {
      cspSet.add(csp);
    }
  } else {
    const nowIso = new Date().toISOString();
    const sanitizedTarget = redactSecrets(targetUrlHint);
    const sanitizedFinal = redactSecrets(page.url());
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

  return {
    result,
    redirectChain,
    cspHeadersDetected: Array.from(cspSet)
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
  inspectionErrorMessage?: string
): Promise<LivePortalDomTrapProbeResult> {
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
      ? redactSecrets(inspectionErrorMessage.trim())
      : undefined;
    return {
      ...EMPTY_DOM_SNAPSHOT,
      hasErrorBanner: Boolean(fallbackErr),
      ...(fallbackErr ? { sanitizedErrorMessage: fallbackErr } : {})
    };
  }

  const combinedErr = raw.rawErrorMessage || inspectionErrorMessage;
  const sanitizedErrorMessage = combinedErr ? redactSecrets(combinedErr.trim()) : undefined;

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
}): Promise<{
  record: LivePortalStageProbeRecord;
  driver: PlaywrightAuthPageDriver;
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
    allowSsoHandoffSettle
  } = params;

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

  const telemetry = await runWithNetworkTelemetry(rawPage, navigateAction, targetUrl);
  await driver.waitForNavigation(3_000);

  const detectedMethod = await detectAndInjectAdapters(rawPage, trackedPage, driver, logger);
  let inspection = await driver.inspectPolimiStage();

  const notes: string[] = [];
  if (allowSsoHandoffSettle && inspection.stage === 'sso_handoff') {
    notes.push('Observed intermediate Stage 0.5 sso_handoff; waiting briefly for redirect settle.');
    for (let attempt = 0; attempt < 2 && inspection.stage === 'sso_handoff'; attempt++) {
      await driver.waitForNavigation(1_500);
      if (rawPage.waitForTimeout) {
        try {
          await rawPage.waitForTimeout(100);
        } catch (waitErr) {
          logger?.debug(
            `Post-sso_handoff waitForTimeout interrupted: ${redactSensitiveErrorText(waitErr)}`
          );
        }
      }
      inspection = await driver.inspectPolimiStage();
    }
    notes.push(`Post-sso_handoff settled stage: ${inspection.stage}.`);
  }

  const adapterInjectionMethod: 'evaluate' | 'addScriptTag' | 'pre_injected' = addScriptTagInvoked
    ? 'addScriptTag'
    : detectedMethod;

  const domSnapshot = await evaluateDomSnapshotSafe(
    rawPage,
    driver,
    selectorBundle,
    inspection.errorMessage
  );

  const sanitizedTarget = redactSecrets(targetUrl);
  const sanitizedFinal = redactSecrets(inspection.url || rawPage.url());
  if (telemetry.cspHeadersDetected.length === 0) {
    notes.push('No Content-Security-Policy response headers captured on navigation hops.');
  }

  const record: LivePortalStageProbeRecord = {
    probeName,
    targetUrl: sanitizedTarget,
    finalUrl: sanitizedFinal,
    inspectedStage: inspection.stage,
    adapterInjectionMethod,
    redirectChain: telemetry.redirectChain,
    cspHeadersDetected: telemetry.cspHeadersDetected,
    domSnapshot,
    durationMs: Math.max(0, Date.now() - startedAt),
    epistemicStatus,
    notes: notes.map((note) => redactSecrets(note))
  };

  return { record, driver };
}

/**
 * Executes a read-only diagnostic probe against Politecnico di Milano IdP entry stages
 * (`Stage 0` bare `/aunicalogin/` expired-session recovery and `Stage 0 -> 0.5 -> 1` service entry).
 *
 * Strictly read-only with respect to credentials: never calls `submitCredentials()` or `submitOtp()`.
 */
export async function runPolimiLivePortalProbe(
  options: LivePortalProbeOptions
): Promise<LivePortalProbeReport> {
  const generatedAtIso = new Date().toISOString();
  const spec = options.spec ?? POLIMI_LOGIN_FLOW_SPEC;
  const safeLogger = options.logger
    ? createRedactingLogger(options.logger)
    : options.driverOptions?.logger
      ? createRedactingLogger(options.driverOptions.logger)
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
    startedAt: number
  ): boolean => {
    const redactedErr = redactSensitiveErrorText(err);
    safeLogger?.error(`Live portal probe "${probeName}" failed: ${redactedErr}`);
    errors.push(`${probeName}: ${redactedErr}`);

    let currentUrl = targetUrl;
    try {
      currentUrl = options.page.url() || targetUrl;
    } catch (urlErr) {
      safeLogger?.debug(
        `Unable to read page.url() after probe failure: ${redactSensitiveErrorText(urlErr)}`
      );
      currentUrl = targetUrl;
    }

    stages.push({
      probeName,
      targetUrl: redactSecrets(targetUrl),
      finalUrl: redactSecrets(currentUrl),
      inspectedStage: 'error',
      adapterInjectionMethod: 'evaluate',
      redirectChain: [],
      cspHeadersDetected: [],
      domSnapshot: { ...EMPTY_DOM_SNAPSHOT },
      durationMs: Math.max(0, Date.now() - startedAt),
      epistemicStatus,
      notes: [`Probe failed: ${redactedErr}`]
    });

    return isClosedTargetError(err) || Boolean(options.page.isClosed?.());
  };

  let abortedEarly = false;

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
        navigateAction: () =>
          options.page.goto(bareUrl, {
            waitUntil: 'domcontentloaded',
            timeout: navigationTimeoutMs
          })
      });
      stages.push(stage0Result.record);

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
            navigateAction: async () => {
              recoveryOutcome = await stage0Result.driver.recoverSessionPage();
              return undefined;
            }
          });
          const recoveryNotes = [
            ...recoveryStage.record.notes,
            `recoverSessionPage() ok=${String(recoveryOutcome.ok)} navigatedTo=${redactSecrets(recoveryOutcome.navigatedTo)}`
          ];
          stages.push({
            ...recoveryStage.record,
            targetUrl: redactSecrets(recoveryOutcome.navigatedTo || spec.entry.serviceEntryUrl),
            notes: recoveryNotes
          });
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
        navigateAction: () =>
          options.page.goto(serviceEntryUrl, {
            waitUntil: 'domcontentloaded',
            timeout: navigationTimeoutMs
          })
      });
      stages.push(stage1Result.record);
    } catch (err) {
      abortedEarly = handleFailure(
        'stage_1_service_entry_credentials',
        serviceEntryUrl,
        err,
        probe2Start
      );
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
          navigateAction: () =>
            options.page.goto(customUrl, {
              waitUntil: 'domcontentloaded',
              timeout: navigationTimeoutMs
            })
        });
        stages.push(customResult.record);
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
    ...(errors.length > 0 ? { errorSummary: redactSecrets(errors.join(' | ')) } : {})
  };
}

function escapeCell(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim();
}

/**
 * Deterministically formats a `LivePortalProbeReport` into Markdown tables compatible
 * with `packages/poliauth/docs/06-live-polimi-website-verification-ledger.md`.
 */
export function formatLivePortalProbeReportMarkdown(report: LivePortalProbeReport): string {
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
    lines.push(`- **Error Summary:** \`${escapeCell(redactSecrets(report.errorSummary))}\``);
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
        ? stage.cspHeadersDetected.map((c) => escapeCell(redactSecrets(c))).join('; ')
        : 'None';
    lines.push(
      `| \`${escapeCell(stage.probeName)}\` | \`${escapeCell(redactSecrets(stage.targetUrl))}\` | \`${escapeCell(redactSecrets(stage.finalUrl))}\` | \`${escapeCell(stage.inspectedStage)}\` | \`${escapeCell(stage.adapterInjectionMethod)}\` | ${String(stage.redirectChain.length)} | ${cspCell} | ${String(stage.durationMs)} | \`[${stage.epistemicStatus}]\` |`
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
      ? `\`${escapeCell(redactSecrets(d.sanitizedErrorMessage))}\``
      : '—';
    lines.push(
      `| \`${escapeCell(stage.probeName)}\` | ${String(d.hasLoginInput)} | ${String(d.hasPasswordInput)} | ${String(d.hasVisibleSubmitButton)} | ${String(d.hasJafVisuallyHiddenTrap)} | ${String(d.hasOtpInput)} | ${String(d.hasSubmitDissmsTrap)} | ${String(d.hasSsoHandoffForm)} | ${String(d.hasExpiredSessionMarker)} | ${String(d.hasAuthenticatedMarker)} | ${String(d.hasErrorBanner)} | ${errText} |`
    );
  }

  const stagesWithDetails = report.stages.filter(
    (s) => s.redirectChain.length > 0 || s.notes.length > 0
  );
  if (stagesWithDetails.length > 0) {
    lines.push('', '#### Redirect Hops & Probe Notes', '');
    for (const stage of stagesWithDetails) {
      lines.push(`- **\`${escapeCell(stage.probeName)}\`** (\`[${stage.epistemicStatus}]\`):`);
      for (const hop of stage.redirectChain) {
        const statusPart = hop.status !== undefined ? `HTTP ${String(hop.status)} ` : '';
        const locPart = hop.locationHeader
          ? ` -> Location: \`${escapeCell(redactSecrets(hop.locationHeader))}\``
          : '';
        lines.push(
          `  - Hop ${String(hop.stepIndex)}: ${statusPart}\`${escapeCell(redactSecrets(hop.url))}\`${locPart} (${escapeCell(hop.timestampIso)})`
        );
      }
      for (const note of stage.notes) {
        lines.push(`  - Note: ${escapeCell(redactSecrets(note))}`);
      }
    }
  }

  return lines.join('\n');
}
