/**
 * @module @polisdk/poliauth-chrome
 * Chrome Extension Tab (`chrome.tabs.sendMessage`) implementation of `AuthPageDriverPort`
 * and matching Content Script handler factory.
 */

import {
  DomAuthPageDriver,
  type AuthPageDriverPort,
  type FederatedAuthPageDriverPort,
  type FederatedSsoInspectionResult,
  type PolimiStageInspectionResult,
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
  | { type: "POLIAUTH_INSPECT_FEDERATED_SSO" }
  | { type: "POLIAUTH_SUBMIT_FEDERATED_EMAIL"; email: string }
  | { type: "POLIAUTH_SUBMIT_FEDERATED_IDENTIFIER"; identifier: string };

function resolveDefaultChromeTabs(): ChromeTabsLike {
  const chromeObj = (globalThis as { chrome?: typeof chrome }).chrome;
  if (!chromeObj?.tabs?.sendMessage) {
    throw new Error(
      "chrome.tabs is not available in the current environment. Provide a ChromeTabsLike instance.",
    );
  }
  return chromeObj.tabs as unknown as ChromeTabsLike;
}

/**
 * `FederatedAuthPageDriverPort` implementation that communicates with a content script
 * injected into a Chrome browser tab via `chrome.tabs.sendMessage`.
 */
export class ChromeExtensionTabDriver implements FederatedAuthPageDriverPort {
  readonly federatedProviderId: string;
  private readonly tabId: number;
  private readonly tabs: ChromeTabsLike;
  private lastKnownUrl = "";

  constructor(tabId: number, tabs?: ChromeTabsLike, federatedProviderId = "webex") {
    this.tabId = tabId;
    this.tabs = tabs ?? resolveDefaultChromeTabs();
    this.federatedProviderId = federatedProviderId;
  }

  getCurrentUrl(): string {
    return this.lastKnownUrl;
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
    const response = await this.tabs.sendMessage<
      PoliAuthTabMessage,
      PolimiStageInspectionResult
    >(this.tabId, {
      type: "POLIAUTH_INSPECT_STAGE",
    });
    if (response?.url) {
      this.lastKnownUrl = response.url;
    }
    return response;
  }

  async recoverSessionPage(): Promise<{ ok: boolean; navigatedTo: string }> {
    return this.tabs.sendMessage<
      PoliAuthTabMessage,
      { ok: boolean; navigatedTo: string }
    >(this.tabId, {
      type: "POLIAUTH_RECOVER_SESSION",
    });
  }

  async submitCredentials(params: {
    personCode: string;
    password: string;
    stayConnected?: boolean;
  }): Promise<{ ok: boolean; error?: string }> {
    return this.tabs.sendMessage<
      PoliAuthTabMessage,
      { ok: boolean; error?: string }
    >(this.tabId, {
      type: "POLIAUTH_SUBMIT_CREDENTIALS",
      personCode: params.personCode,
      password: params.password,
      stayConnected: params.stayConnected,
    });
  }

  async submitOtp(params: { otp: string }): Promise<{ ok: boolean; error?: string }> {
    return this.tabs.sendMessage<
      PoliAuthTabMessage,
      { ok: boolean; error?: string }
    >(this.tabId, {
      type: "POLIAUTH_SUBMIT_OTP",
      otp: params.otp,
    });
  }

  async inspectFederatedSsoPage(): Promise<FederatedSsoInspectionResult> {
    return this.tabs.sendMessage<
      PoliAuthTabMessage,
      FederatedSsoInspectionResult
    >(this.tabId, {
      type: "POLIAUTH_INSPECT_FEDERATED_SSO",
    });
  }

  async submitFederatedIdentifier(
    identifier: string,
  ): Promise<{ ok: boolean; error?: string }> {
    return this.tabs.sendMessage<
      PoliAuthTabMessage,
      { ok: boolean; error?: string }
    >(this.tabId, {
      type: "POLIAUTH_SUBMIT_FEDERATED_IDENTIFIER",
      identifier,
    });
  }

  async submitFederatedEmailLogin(
    email: string,
  ): Promise<{ ok: boolean; error?: string }> {
    return this.submitFederatedIdentifier(email);
  }
}

/**
 * Helper to create a content-script message dispatcher that delegates
 * `PoliAuthTabMessage` messages to a local `DomAuthPageDriver` bound to the tab's DOM.
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
        return domDriver.inspectFederatedSsoPage();
      case "POLIAUTH_SUBMIT_FEDERATED_IDENTIFIER":
        return typeof domDriver.submitFederatedIdentifier === 'function'
          ? domDriver.submitFederatedIdentifier(message.identifier)
          : domDriver.submitFederatedEmailLogin(message.identifier);
      case "POLIAUTH_SUBMIT_FEDERATED_EMAIL":
        return typeof domDriver.submitFederatedEmailLogin === 'function'
          ? domDriver.submitFederatedEmailLogin(message.email)
          : domDriver.submitFederatedIdentifier(message.email);
      default:
        return undefined;
    }
  };
}
