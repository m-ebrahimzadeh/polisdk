/**
 * @module @polisdk/poliauth-chrome
 * Chrome Extension Tab (`chrome.tabs.sendMessage`) implementation of `FederatedAuthPageDriverPort`
 * and matching Content Script handler factory.
 */

import {
  DomAuthPageDriver,
  POLIMI_LOGIN_FLOW_SPEC,
  createRedactingLogger,
  inspectFederatedSsoPageBySpec,
  redactSensitiveErrorText,
  submitFederatedIdentifierBySpec,
  triggerFederatedLoginBySpec,
  type AuthLoggerPort,
  type FederatedAuthPageDriverPort,
  type FederatedSsoInspectionResult,
  type FederatedSsoProviderSpec,
  type PageActionResult,
  type PolimiCredentialSubmission,
  type PolimiOtpSubmission,
  type PolimiStageInspectionResult,
  type SessionRecoveryResult,
} from "@polisdk/poliauth";

export interface ChromeTabsLike {
  sendMessage<TMessage = unknown, TResponse = unknown>(
    tabId: number,
    message: TMessage,
  ): Promise<TResponse>;
  get?(tabId: number): Promise<{ url?: string; id?: number }>;
  update?(
    tabId: number,
    updateProperties: { url?: string; active?: boolean },
  ): Promise<unknown>;
}

export interface ChromeExtensionTabDriverOptions {
  tabs?: ChromeTabsLike;
  federatedProviderSpec?: FederatedSsoProviderSpec;
  logger?: AuthLoggerPort;
  maxTransientRetries?: number;
}

export type PoliAuthTabMessage =
  | { type: "POLIAUTH_INSPECT_STAGE" }
  | { type: "POLIAUTH_RECOVER_SESSION" }
  | {
      type: "POLIAUTH_SUBMIT_CREDENTIALS";
      personCode: string;
      password: string;
      stayConnected?: boolean;
    }
  | { type: "POLIAUTH_SUBMIT_OTP"; otp: string }
  | {
      type: "POLIAUTH_INSPECT_FEDERATED_SSO";
      spec?: FederatedSsoProviderSpec;
    }
  | {
      type: "POLIAUTH_SUBMIT_FEDERATED_IDENTIFIER";
      identifier: string;
      spec?: FederatedSsoProviderSpec;
    }
  | {
      type: "POLIAUTH_TRIGGER_FEDERATED_LOGIN";
      spec?: FederatedSsoProviderSpec;
    };

function resolveDefaultChromeTabs(): ChromeTabsLike {
  const chromeObj = (globalThis as { chrome?: typeof chrome }).chrome;
  if (!chromeObj?.tabs?.sendMessage) {
    throw new Error(
      "chrome.tabs is not available in the current environment. Provide a ChromeTabsLike instance.",
    );
  }
  return chromeObj.tabs as unknown as ChromeTabsLike;
}

function isChromeTabsLike(value: unknown): value is ChromeTabsLike {
  return (
    typeof value === "object" &&
    value !== null &&
    "sendMessage" in value &&
    typeof (value as { sendMessage?: unknown }).sendMessage === "function"
  );
}

function isTransientTabError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  if (
    /no tab with id|tab was closed|target closed|page has been closed|browser has been closed|context has been closed|has been closed/i.test(
      msg,
    )
  ) {
    return false;
  }
  return /execution context was destroyed|most likely because of a navigation|cannot find context|frame was detached|receiving end does not exist|receiving end returned empty response|message port closed|cannot access contents of (?:the )?page|navigating|interrupted by.*navigation|navigation in progress/i.test(
    msg,
  );
}

/**
 * `FederatedAuthPageDriverPort` implementation that communicates with a content script
 * injected into a Chrome browser tab via `chrome.tabs.sendMessage`.
 */
export class ChromeExtensionTabDriver implements FederatedAuthPageDriverPort {
  readonly federatedProviderId: string;
  private readonly tabId: number;
  private readonly tabs: ChromeTabsLike;
  private readonly federatedProviderSpec?: FederatedSsoProviderSpec;
  private readonly logger?: AuthLoggerPort;
  private readonly maxTransientRetries: number;
  private lastKnownUrl = "";

  constructor(
    tabId: number,
    tabsOrOptions?: ChromeTabsLike | ChromeExtensionTabDriverOptions,
    extraOptions?: Omit<ChromeExtensionTabDriverOptions, "tabs">,
  ) {
    this.tabId = tabId;
    const opts: ChromeExtensionTabDriverOptions = isChromeTabsLike(tabsOrOptions)
      ? { tabs: tabsOrOptions, ...extraOptions }
      : (tabsOrOptions ?? {});
    this.tabs = opts.tabs ?? resolveDefaultChromeTabs();
    this.federatedProviderSpec = opts.federatedProviderSpec;
    this.federatedProviderId = opts.federatedProviderSpec?.providerId ?? "";
    this.logger = opts.logger ? createRedactingLogger(opts.logger) : undefined;
    this.maxTransientRetries = opts.maxTransientRetries ?? 2;
  }

  /**
   * Returns a new `ChromeExtensionTabDriver` bound to the same tab and configured
   * with the given `FederatedSsoProviderSpec`.
   */
  withFederatedProviderSpec(
    spec: FederatedSsoProviderSpec,
  ): ChromeExtensionTabDriver {
    return new ChromeExtensionTabDriver(this.tabId, {
      tabs: this.tabs,
      federatedProviderSpec: spec,
      logger: this.logger,
      maxTransientRetries: this.maxTransientRetries,
    });
  }

  getCurrentUrl(): string {
    return this.lastKnownUrl;
  }

  private async sendMessageWithRetry<TResponse>(
    message: PoliAuthTabMessage,
  ): Promise<TResponse> {
    const maxAttempts = Math.max(1, this.maxTransientRetries + 1);
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const response = await this.tabs.sendMessage<
          PoliAuthTabMessage,
          TResponse | undefined
        >(this.tabId, message);
        if (response === undefined || response === null) {
          throw new Error(
            `Receiving end returned empty response for ${message.type} (content script not ready or frame unloading).`,
          );
        }
        return response;
      } catch (err) {
        const redacted = redactSensitiveErrorText(err);
        if (!isTransientTabError(err)) {
          this.logger?.error(
            `Chrome tab message ${message.type} failed: ${redacted}`,
          );
          throw err;
        }
        this.logger?.warn(
          `Transient Chrome tab error during ${message.type} (attempt ${attempt}/${maxAttempts}): ${redacted}`,
        );
        if (attempt < maxAttempts) {
          await this.waitForNavigation(250);
          continue;
        }
        throw err;
      }
    }
    throw new Error(`Chrome tab message ${message.type} exhausted retries.`);
  }

  async goto(url: string, _timeoutMs?: number): Promise<void> {
    this.lastKnownUrl = url;
    if (this.tabs.update) {
      await this.tabs.update(this.tabId, { url });
    }
  }

  async waitForNavigation(timeoutMs = 1500): Promise<void> {
    await new Promise((resolve) =>
      setTimeout(resolve, Math.min(timeoutMs, 1500)),
    );
  }

  async inspectPolimiStage(): Promise<PolimiStageInspectionResult> {
    try {
      const response = await this.sendMessageWithRetry<PolimiStageInspectionResult>(
        { type: "POLIAUTH_INSPECT_STAGE" },
      );
      if (response?.url) {
        this.lastKnownUrl = response.url;
      }
      return response;
    } catch (err) {
      if (!isTransientTabError(err)) {
        throw err;
      }
      this.logger?.warn(
        `Chrome inspectPolimiStage interrupted by tab navigation; reporting sso_handoff: ${redactSensitiveErrorText(err)}`,
      );
      return {
        stage: "sso_handoff",
        url: this.lastKnownUrl,
        title: "",
      };
    }
  }

  async recoverSessionPage(): Promise<SessionRecoveryResult> {
    try {
      const recovery = await this.sendMessageWithRetry<SessionRecoveryResult>({
        type: "POLIAUTH_RECOVER_SESSION",
      });
      if (!recovery.ok) {
        const targetUrl =
          recovery.navigatedTo || POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl;
        await this.goto(targetUrl);
        return { ok: false, navigatedTo: targetUrl };
      }
      await this.waitForNavigation(1800);
      return recovery;
    } catch (err) {
      if (!isTransientTabError(err)) {
        throw err;
      }
      this.logger?.warn(
        `Chrome recoverSessionPage interrupted by tab navigation; falling back to serviceEntryUrl: ${redactSensitiveErrorText(err)}`,
      );
      const fallbackUrl = POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl;
      await this.goto(fallbackUrl);
      return { ok: false, navigatedTo: fallbackUrl };
    }
  }

  async submitCredentials(
    params: PolimiCredentialSubmission,
  ): Promise<PageActionResult> {
    return this.sendMessageWithRetry<PageActionResult>({
      type: "POLIAUTH_SUBMIT_CREDENTIALS",
      personCode: params.personCode,
      password: params.password,
      stayConnected: params.stayConnected,
    });
  }

  async submitOtp(params: PolimiOtpSubmission): Promise<PageActionResult> {
    return this.sendMessageWithRetry<PageActionResult>({
      type: "POLIAUTH_SUBMIT_OTP",
      otp: params.otp,
    });
  }

  async inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult> {
    try {
      const response =
        await this.sendMessageWithRetry<FederatedSsoInspectionResult>({
          type: "POLIAUTH_INSPECT_FEDERATED_SSO",
          ...(this.federatedProviderSpec
            ? { spec: this.federatedProviderSpec }
            : {}),
        });
      if (response?.url) {
        this.lastKnownUrl = response.url;
      }
      return response;
    } catch (err) {
      if (!isTransientTabError(err)) {
        throw err;
      }
      this.logger?.warn(
        `Chrome inspectFederatedSsoPage interrupted by tab navigation: ${redactSensitiveErrorText(err)}`,
      );
      return {
        providerId: this.federatedProviderId,
        status: "sso_in_transit",
        isIdentifierPrompt: false,
        isLoginTrigger: false,
        isSamlTransitPage: true,
        url: this.lastKnownUrl,
        reason: "Tab navigating across SAML SSO redirect",
      };
    }
  }

  async submitFederatedIdentifier(
    identifier: string,
  ): Promise<PageActionResult> {
    return this.sendMessageWithRetry<PageActionResult>({
      type: "POLIAUTH_SUBMIT_FEDERATED_IDENTIFIER",
      identifier,
      ...(this.federatedProviderSpec
        ? { spec: this.federatedProviderSpec }
        : {}),
    });
  }

  async triggerFederatedLogin(): Promise<PageActionResult> {
    return this.sendMessageWithRetry<PageActionResult>({
      type: "POLIAUTH_TRIGGER_FEDERATED_LOGIN",
      ...(this.federatedProviderSpec
        ? { spec: this.federatedProviderSpec }
        : {}),
    });
  }
}

/**
 * Helper to create a content-script message dispatcher that delegates
 * `PoliAuthTabMessage` messages to a local `DomAuthPageDriver` bound to the tab's DOM.
 *
 * When a federated SSO message includes an inline `FederatedSsoProviderSpec`, it is
 * evaluated directly against the tab's DOM without requiring the content script to
 * pre-register every Service Provider.
 */
export function createPoliAuthContentScriptHandler(
  domDriver: DomAuthPageDriver,
) {
  return async (message: PoliAuthTabMessage): Promise<unknown> => {
    switch (message?.type) {
      case "POLIAUTH_INSPECT_STAGE":
        return domDriver.inspectPolimiStage();
      case "POLIAUTH_RECOVER_SESSION":
        return domDriver.recoverSessionPage();
      case "POLIAUTH_SUBMIT_CREDENTIALS":
        return domDriver.submitCredentials({
          personCode: message.personCode,
          password: message.password,
          stayConnected: message.stayConnected,
        });
      case "POLIAUTH_SUBMIT_OTP":
        return domDriver.submitOtp({ otp: message.otp });
      case "POLIAUTH_INSPECT_FEDERATED_SSO":
        if (
          message.spec &&
          typeof domDriver.getDocument === "function" &&
          typeof domDriver.getLocationSnapshot === "function"
        ) {
          return inspectFederatedSsoPageBySpec(
            message.spec,
            domDriver.getDocument(),
            domDriver.getLocationSnapshot(),
          );
        }
        return domDriver.inspectFederatedSsoPage();
      case "POLIAUTH_SUBMIT_FEDERATED_IDENTIFIER":
        if (message.spec && typeof domDriver.getDocument === "function") {
          return submitFederatedIdentifierBySpec(
            message.spec,
            domDriver.getDocument(),
            message.identifier,
          );
        }
        return domDriver.submitFederatedIdentifier(message.identifier);
      case "POLIAUTH_TRIGGER_FEDERATED_LOGIN":
        if (message.spec && typeof domDriver.getDocument === "function") {
          return triggerFederatedLoginBySpec(
            message.spec,
            domDriver.getDocument(),
          );
        }
        return domDriver.triggerFederatedLogin();
      default:
        return undefined;
    }
  };
}

export type ChromeRuntimeMessageListener = (
  message: unknown,
  sender: unknown,
  sendResponse: (response?: unknown) => void,
) => boolean;

/**
 * Wraps `createPoliAuthContentScriptHandler` into a standard Chrome MV3
 * `chrome.runtime.onMessage` listener (`(message, sender, sendResponse) => boolean`)
 * that returns `true` only for `POLIAUTH_*` messages and resolves asynchronously via `sendResponse`.
 */
export function createPoliAuthChromeRuntimeMessageListener(
  domDriver: DomAuthPageDriver,
): ChromeRuntimeMessageListener {
  const handler = createPoliAuthContentScriptHandler(domDriver);
  return (message, _sender, sendResponse) => {
    const msg = message as Partial<PoliAuthTabMessage> | null | undefined;
    if (!msg || typeof msg.type !== "string" || !msg.type.startsWith("POLIAUTH_")) {
      return false;
    }

    void handler(msg as PoliAuthTabMessage)
      .then((result) => {
        sendResponse(result);
      })
      .catch((err) => {
        sendResponse({
          ok: false,
          error: redactSensitiveErrorText(err),
        });
      });

    return true;
  };
}
