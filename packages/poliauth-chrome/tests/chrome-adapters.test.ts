import { describe, expect, it } from "vitest";
import {
  ChromeLocalVaultStorage,
  ChromeExtensionTabDriver,
  createPoliAuthContentScriptHandler,
  type ChromeStorageAreaLike,
  type ChromeTabsLike,
  type PoliAuthTabMessage,
} from "../src/index.js";
import type { DomAuthPageDriver } from "@polisdk/poliauth";

class FakeChromeStorageArea implements ChromeStorageAreaLike {
  private readonly store = new Map<string, unknown>();

  async get(keys: string | string[]): Promise<Record<string, unknown>> {
    const keyList = Array.isArray(keys) ? keys : [keys];
    const result: Record<string, unknown> = {};
    for (const key of keyList) {
      if (this.store.has(key)) {
        result[key] = this.store.get(key);
      }
    }
    return result;
  }

  async set(items: Record<string, unknown>): Promise<void> {
    for (const [key, value] of Object.entries(items)) {
      this.store.set(key, value);
    }
  }

  async remove(keys: string | string[]): Promise<void> {
    const keyList = Array.isArray(keys) ? keys : [keys];
    for (const key of keyList) {
      this.store.delete(key);
    }
  }
}

describe("ChromeLocalVaultStorage & ChromeExtensionTabDriver", () => {
  it("stores, reads, and removes values via ChromeLocalVaultStorage", async () => {
    const fakeArea = new FakeChromeStorageArea();
    const storage = new ChromeLocalVaultStorage(fakeArea);

    expect(await storage.get("missing")).toEqual({});
    await storage.set({ key1: { ok: true } });
    expect(await storage.get("key1")).toEqual({ key1: { ok: true } });
    await storage.remove("key1");
    expect(await storage.get("key1")).toEqual({});
  });

  it("dispatches tab messages to content script handler via ChromeExtensionTabDriver", async () => {
    const fakeDomDriver = {
      inspectPolimiStage: async () => ({
        stage: "authenticated" as const,
        url: "https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp",
        title: "Servizi Online",
      }),
      recoverSessionPage: async () => ({
        ok: true,
        navigatedTo: "https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376",
      }),
      submitCredentials: async () => ({ ok: true }),
      submitOtp: async () => ({ ok: true }),
      inspectFederatedSsoPage: async () => ({
        status: "login_required" as const,
        isEmailSsoPage: true,
        isSamlTransitPage: false,
        url: "https://web.webex.com/sign-in",
      }),
      submitFederatedIdentifier: async () => ({ ok: true }),
      submitFederatedEmailLogin: async () => ({ ok: true }),
    } as unknown as DomAuthPageDriver;

    const handler = createPoliAuthContentScriptHandler(fakeDomDriver);
    let updatedUrl = "";

    const fakeTabs: ChromeTabsLike = {
      async sendMessage<TMessage = unknown, TResponse = unknown>(
        _tabId: number,
        message: TMessage,
      ): Promise<TResponse> {
        return (await handler(message as PoliAuthTabMessage)) as TResponse;
      },
      async update(_tabId: number, props: { url?: string }) {
        updatedUrl = props.url ?? "";
      },
    };

    const driver = new ChromeExtensionTabDriver(42, fakeTabs);
    await driver.goto("https://aunicalogin.polimi.it/aunicalogin/");
    expect(updatedUrl).toBe("https://aunicalogin.polimi.it/aunicalogin/");
    expect(driver.getCurrentUrl()).toBe("https://aunicalogin.polimi.it/aunicalogin/");

    const stage = await driver.inspectPolimiStage();
    expect(stage.stage).toBe("authenticated");
    expect(driver.getCurrentUrl()).toBe(
      "https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp",
    );

    const rec = await driver.recoverSessionPage();
    expect(rec.ok).toBe(true);

    const cred = await driver.submitCredentials({
      personCode: "10654321",
      password: "Secret!",
    });
    expect(cred.ok).toBe(true);

    const otp = await driver.submitOtp({ otp: "123456" });
    expect(otp.ok).toBe(true);

    const sso = await driver.inspectFederatedSsoPage();
    expect(sso.isEmailSsoPage).toBe(true);

    const ssoSub = await driver.submitFederatedEmailLogin(
      "mario.rossi@mail.polimi.it",
    );
    expect(ssoSub.ok).toBe(true);

    const idSub = await driver.submitFederatedIdentifier(
      "mario.rossi@mail.polimi.it",
    );
    expect(idSub.ok).toBe(true);
  });
});
