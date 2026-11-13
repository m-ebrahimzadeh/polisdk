import { describe, expect, it } from "vitest";
import { JSDOM } from "jsdom";
import { DomAuthPageDriver, POLIMI_LOGIN_FLOW_SPEC } from "@polisdk/poliauth";
import {
  ChromeExtensionTabDriver,
  createPoliAuthChromeRuntimeMessageListener,
  type ChromeTabsLike,
} from "../src/index.js";

describe("Phase 5B Remediation Edge Cases (@polisdk/poliauth-chrome)", () => {
  it("explicitly navigates tab in recoverSessionPage when content script returns { ok: false, navigatedTo }", async () => {
    const updatedUrls: string[] = [];
    const tabsMock: ChromeTabsLike = {
      sendMessage: (async () => ({
        ok: false,
        navigatedTo: POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl,
      })) as ChromeTabsLike["sendMessage"],
      async update(_tabId, props) {
        if (props.url) {
          updatedUrls.push(props.url);
        }
      },
    };

    const driver = new ChromeExtensionTabDriver(7, tabsMock);
    const result = await driver.recoverSessionPage();

    expect(result.ok).toBe(false);
    expect(updatedUrls).toEqual([POLIMI_LOGIN_FLOW_SPEC.entry.serviceEntryUrl]);
  });

  it("treats undefined sendMessage response as transient and retries cleanly", async () => {
    let attempts = 0;
    const tabsMock: ChromeTabsLike = {
      sendMessage: (async () => {
        attempts += 1;
        if (attempts === 1) {
          return undefined;
        }
        return {
          stage: "authenticated",
          url: "https://servizionline.polimi.it/portaleservizi/",
          title: "Portale servizi",
        };
      }) as ChromeTabsLike["sendMessage"],
    };

    const driver = new ChromeExtensionTabDriver(9, tabsMock, {
      maxTransientRetries: 2,
    });
    const stage = await driver.inspectPolimiStage();

    expect(attempts).toBe(2);
    expect(stage.stage).toBe("authenticated");
  });

  it("bridges chrome.runtime.onMessage asynchronously for POLIAUTH_* messages and returns false for unrelated messages", async () => {
    const dom = new JSDOM(
      `<!DOCTYPE html><html><head><title>Portale servizi</title></head><body><input class="cercaServizio" name="search" /></body></html>`,
    );
    const domDriver = new DomAuthPageDriver({
      getDocument: () => dom.window.document,
      getLocation: () => ({
        href: "https://servizionline.polimi.it/portaleservizi/",
        hostname: "servizionline.polimi.it",
        pathname: "/portaleservizi/",
      }),
    });

    const listener = createPoliAuthChromeRuntimeMessageListener(domDriver);

    // 1. Unrelated extension message is ignored synchronously (returns false)
    let called = false;
    const ignored = listener({ type: "OTHER_MESSAGE" }, {}, () => {
      called = true;
    });
    expect(ignored).toBe(false);
    expect(called).toBe(false);

    // 2. POLIAUTH_* message returns true and invokes sendResponse asynchronously
    const response = await new Promise<unknown>((resolve) => {
      const keepChannelOpen = listener(
        { type: "POLIAUTH_INSPECT_STAGE" },
        {},
        (resp) => {
          resolve(resp);
        },
      );
      expect(keepChannelOpen).toBe(true);
    });

    expect((response as { stage: string }).stage).toBe("authenticated");

    // 3. Errors thrown inside DOM inspection are caught and redacted in sendResponse
    const failingDomDriver = new DomAuthPageDriver({
      getDocument: () => {
        throw new Error(
          "Failed navigating https://aunicalogin.polimi.it/login?password=SuperSecretValue!",
        );
      },
      getLocation: () => ({
        href: "https://aunicalogin.polimi.it/",
        hostname: "aunicalogin.polimi.it",
        pathname: "/",
      }),
    });
    const failingListener =
      createPoliAuthChromeRuntimeMessageListener(failingDomDriver);

    const errResponse = await new Promise<{ ok: boolean; error: string }>(
      (resolve) => {
        expect(
          failingListener({ type: "POLIAUTH_INSPECT_STAGE" }, {}, (resp) => {
            resolve(resp as { ok: boolean; error: string });
          }),
        ).toBe(true);
      },
    );

    expect(errResponse.ok).toBe(false);
    expect(errResponse.error).not.toContain("SuperSecretValue!");
  });
});
