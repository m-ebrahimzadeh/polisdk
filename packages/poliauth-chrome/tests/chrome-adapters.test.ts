import { describe, expect, it } from "vitest";
import { JSDOM } from "jsdom";
import {
  DomAuthPageDriver,
  type AuthLoggerPort,
  type FederatedSsoProviderSpec,
} from "@polisdk/poliauth";
import {
  ChromeLocalVaultStorage,
  ChromeExtensionTabDriver,
  createPoliAuthContentScriptHandler,
  type ChromeStorageAreaLike,
  type ChromeTabsLike,
  type PoliAuthTabMessage,
} from "../src/index.js";

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
        providerId: "zoom",
        status: "login_required" as const,
        isIdentifierPrompt: true,
        isLoginTrigger: false,
        isSamlTransitPage: false,
        url: "https://polimi-it.zoom.us/signin",
      }),
      submitFederatedIdentifier: async () => ({ ok: true }),
      triggerFederatedLogin: async () => ({ ok: true }),
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
    expect(sso.isIdentifierPrompt).toBe(true);
    expect(sso.isLoginTrigger).toBe(false);

    const idSub = await driver.submitFederatedIdentifier(
      "mario.rossi@mail.polimi.it",
    );
    expect(idSub.ok).toBe(true);

    const trigRes = await driver.triggerFederatedLogin();
    expect(trigRes.ok).toBe(true);
  });

  it("Scenario 4: passes arbitrary FederatedSsoProviderSpec configs dynamically over Chrome tab messages and retries transient redirect errors", async () => {
    const webeepSpec: FederatedSsoProviderSpec = {
      providerId: "webeep",
      displayName: "WeBeep",
      entryUrl: "https://webeep.polimi.it/login/index.php",
      loginTrigger: {
        hostnames: ["webeep.polimi.it"],
        pathnameSubstrings: ["/login/index.php"],
        triggerSelector: "a.btn-shibboleth",
      },
      transitHostnames: ["shibidp.polimi.it"],
      transitUrlSubstrings: ["/auth/shibboleth/"],
      authenticatedHostnames: ["webeep.polimi.it"],
      authenticatedSelectors: [".usermenu"],
    };

    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <a class="btn-shibboleth" href="/auth/shibboleth/index.php">Login PoliMi</a>
        </body>
      </html>`,
      { url: "https://webeep.polimi.it/login/index.php" },
    );

    let clicked = false;
    dom.window.document
      .querySelector(".btn-shibboleth")
      ?.addEventListener("click", (e) => {
        e.preventDefault();
        clicked = true;
      });

    // DomAuthPageDriver has NO pre-registered federated provider; spec arrives in the Chrome message!
    const domDriver = new DomAuthPageDriver({
      getDocument: () => dom.window.document,
      getLocation: () => dom.window.location,
    });
    const handler = createPoliAuthContentScriptHandler(domDriver);

    const logs: string[] = [];
    const logger: AuthLoggerPort = {
      debug: (m) => logs.push(m),
      info: (m) => logs.push(m),
      warn: (m) => logs.push(m),
      error: (m) => logs.push(m),
    };

    let attempts = 0;
    const flakyTabs: ChromeTabsLike = {
      async sendMessage<TMessage = unknown, TResponse = unknown>(
        _tabId: number,
        message: TMessage,
      ): Promise<TResponse> {
        attempts += 1;
        if (attempts === 1) {
          throw new Error(
            "Receiving end does not exist during navigation ?SAMLRequest=TOP_SECRET_REQ",
          );
        }
        return (await handler(message as PoliAuthTabMessage)) as TResponse;
      },
    };

    const driver = new ChromeExtensionTabDriver(7, {
      tabs: flakyTabs,
      federatedProviderSpec: webeepSpec,
      logger,
    });

    expect(driver.federatedProviderId).toBe("webeep");

    const sso = await driver.inspectFederatedSsoPage();
    expect(sso.providerId).toBe("webeep");
    expect(sso.status).toBe("login_required");
    expect(sso.isLoginTrigger).toBe(true);
    expect(sso.isIdentifierPrompt).toBe(false);
    expect(attempts).toBe(2);
    expect(logs.some((m) => m.includes("SAMLRequest=[REDACTED]"))).toBe(true);
    expect(logs.some((m) => m.includes("TOP_SECRET_REQ"))).toBe(false);

    const trig = await driver.triggerFederatedLogin();
    expect(trig.ok).toBe(true);
    expect(clicked).toBe(true);
  });
});
