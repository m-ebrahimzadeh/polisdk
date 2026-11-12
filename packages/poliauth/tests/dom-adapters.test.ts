import { describe, expect, it } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  isPolimiLoginPage,
  isPolimiAuthenticatedSessionPage,
  inspectPolimiPageStage,
  recoverPolimiSessionPage,
  submitPolimiCredentials,
  submitPolimiOtp
} from '../adapters/polimi-dom-adapter.js';
import {
  isWebexEmailSsoPage,
  inspectWebexSsoPage,
  submitWebexEmailLogin,
  WebexSamlProviderAdapter
} from '../adapters/webex-sso-dom-adapter.js';
import {
  FederatedSsoProviderRegistry,
  SelectorFederatedSsoProviderAdapter
} from '../adapters/index.js';
import { DomAuthPageDriver, DomFederatedAuthPageDriver } from '../adapters/dom-page-driver.js';

describe('PoliMi & Federated SAML SSO DOM Adapters', () => {
  it('detects and recovers from Stage 0 SessioneTerminata security violation page', () => {
    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <div class="error">La sessione di lavoro è stata chiusa per violazione della sicurezza.</div>
          <a class="btn-primary" href="https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376">Continua...</a>
        </body>
      </html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/SessioneTerminataLogoutSSO.do' }
    );

    const doc = dom.window.document;
    const loc = dom.window.location;
    expect(isPolimiLoginPage(doc, loc)).toBe(true);

    const stage = inspectPolimiPageStage(doc, loc);
    expect(stage.stage).toBe('session_expired');

    let clicked = false;
    doc.querySelector('a')?.addEventListener('click', (e) => {
      e.preventDefault();
      clicked = true;
    });

    const recovery = recoverPolimiSessionPage(doc);
    expect(recovery.ok).toBe(true);
    expect(clicked).toBe(true);
    expect(recovery.navigatedTo).toContain('id_servizio=376');
  });

  it('prioritizes sso_handoff over credentials when AunicaLogin.do auto-submit form coexists with #login/#password', () => {
    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <form name="form1" action="/aunicalogin/controller/AunicaLogin.do" method="POST">
            <input type="submit" name="evn_checkCookieSSO" value="Continua" />
          </form>
          <div style="display:none">
            <input id="login" name="login" />
            <input id="password" name="password" type="password" />
          </div>
        </body>
      </html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376' }
    );

    const stage = inspectPolimiPageStage(dom.window.document, dom.window.location);
    expect(stage.stage).toBe('sso_handoff');
  });

  it('submits Stage 1 credentials via the visible evn_conferma button while skipping the hidden .jaf-visually-hidden duplicate', () => {
    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <form action="/aunicalogin/controller/IdentificazioneUnica.do" method="POST">
            <input id="login" name="login" type="text" />
            <input id="password" name="password" type="password" />
            <button type="submit" name="evn_conferma" class="jaf-visually-hidden">Hidden</button>
            <button type="submit" name="evn_conferma" id="visible-login-btn">Accedi</button>
          </form>
        </body>
      </html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=376' }
    );

    const doc = dom.window.document;
    const stage = inspectPolimiPageStage(doc, dom.window.location);
    expect(stage.stage).toBe('credentials');

    let hiddenClicked = false;
    let visibleClicked = false;

    doc.querySelector('.jaf-visually-hidden')?.addEventListener('click', (e) => {
      e.preventDefault();
      hiddenClicked = true;
    });
    doc.querySelector('#visible-login-btn')?.addEventListener('click', (e) => {
      e.preventDefault();
      visibleClicked = true;
    });

    const res = submitPolimiCredentials(doc, {
      personCode: ' 10987654 ',
      password: 'MyPoliPassword!'
    });

    expect(res.ok).toBe(true);
    expect(hiddenClicked).toBe(false);
    expect(visibleClicked).toBe(true);
    expect((doc.querySelector('#login') as HTMLInputElement).value).toBe('10987654');
    expect((doc.querySelector('#password') as HTMLInputElement).value).toBe('MyPoliPassword!');
  });

  it('submits Stage 2 2FA OTP via #submit-dissms[name="evn_continua"] while skipping hidden buttons', () => {
    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <form id="form_scelta2fa" action="/aunicalogin/controller/IdentificazioneDFA.do" method="POST">
            <input id="otp" name="otp" type="text" />
            <button type="submit" name="evn_continua" class="jaf-visually-hidden">Hidden</button>
            <button type="submit" id="submit-dissms" name="evn_continua">Continua</button>
          </form>
        </body>
      </html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do' }
    );

    const doc = dom.window.document;
    expect(inspectPolimiPageStage(doc, dom.window.location).stage).toBe('otp');

    let hiddenClicked = false;
    let visibleClicked = false;
    doc.querySelector('.jaf-visually-hidden')?.addEventListener('click', (e) => {
      e.preventDefault();
      hiddenClicked = true;
    });
    doc.querySelector('#submit-dissms')?.addEventListener('click', (e) => {
      e.preventDefault();
      visibleClicked = true;
    });

    const res = submitPolimiOtp(doc, ' 654 321 ');
    expect(res.ok).toBe(true);
    expect(hiddenClicked).toBe(false);
    expect(visibleClicked).toBe(true);
    expect((doc.querySelector('#otp') as HTMLInputElement).value).toBe('654321');
  });

  it('detects authenticated PoliMi session page without coupling to downstream portal services', async () => {
    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <h1>Servizi Online</h1>
          <input class="cercaServizio" name="search" />
          <a href="/portaleservizi/Logout.do">Esci</a>
        </body>
      </html>`,
      { url: 'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do' }
    );

    const doc = dom.window.document;
    const loc = dom.window.location;
    expect(isPolimiAuthenticatedSessionPage(doc, loc)).toBe(true);
    expect(inspectPolimiPageStage(doc, loc).stage).toBe('authenticated');

    const driver = new DomAuthPageDriver({
      getDocument: () => doc,
      getLocation: () => loc
    });
    expect((await driver.inspectPolimiStage()).stage).toBe('authenticated');
  });

  it('handles Federated SAML SSO email prompt and dispatches input/change/blur events to enable #IDButton2', () => {
    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <form id="md-form" action="/idb/saml2/jsp/doSSO.jsp" method="POST">
            <input id="IDToken1" name="IDToken1" type="email" />
            <button id="IDButton2" name="btnOK" type="button" disabled>Next</button>
          </form>
        </body>
      </html>`,
      { url: 'https://idbroker-eu.webex.com/idb/saml2/jsp/doSSO.jsp' }
    );

    const doc = dom.window.document;
    const loc = dom.window.location;
    expect(isWebexEmailSsoPage(doc, loc)).toBe(true);
    const inspection = inspectWebexSsoPage(doc, loc);
    expect(inspection.status).toBe('login_required');
    expect(inspection.isIdentifierPrompt).toBe(true);
    expect(inspection.isEmailSsoPage).toBe(true);
    expect(inspection.providerId).toBe('webex');

    const eventsFired: string[] = [];
    const emailInput = doc.querySelector<HTMLInputElement>('#IDToken1')!;
    const nextButton = doc.querySelector<HTMLButtonElement>('#IDButton2')!;

    for (const evtName of ['input', 'change', 'blur']) {
      emailInput.addEventListener(evtName, () => {
        eventsFired.push(evtName);
      });
    }

    let buttonClicked = false;
    nextButton.addEventListener('click', (e) => {
      e.preventDefault();
      buttonClicked = true;
    });

    const res = submitWebexEmailLogin(doc, ' mario.rossi@mail.polimi.it ');
    expect(res.ok).toBe(true);
    expect(emailInput.value).toBe('mario.rossi@mail.polimi.it');
    expect(eventsFired).toEqual(['input', 'change', 'blur']);
    expect(nextButton.disabled).toBe(false);
    expect(buttonClicked).toBe(true);
  });

  it('supports pluggable WebexSamlProviderAdapter implementing FederatedSsoProviderAdapterPort', async () => {
    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <form id="md-form" action="/idb/saml2/jsp/doSSO.jsp" method="POST">
            <input id="IDToken1" name="IDToken1" type="email" />
            <button id="IDButton2" name="btnOK" type="button" disabled>Next</button>
          </form>
        </body>
      </html>`,
      { url: 'https://idbroker-eu.webex.com/idb/saml2/jsp/doSSO.jsp' }
    );

    const doc = dom.window.document;
    const loc = dom.window.location;
    const adapter = new WebexSamlProviderAdapter();
    expect(adapter.providerId).toBe('webex');
    expect(adapter.displayName).toBe('Webex');

    const inspection = adapter.inspectPage(doc, loc);
    expect(inspection.status).toBe('login_required');
    expect(inspection.providerId).toBe('webex');
    expect(inspection.isIdentifierPrompt).toBe(true);

    let clicked = false;
    doc.querySelector<HTMLButtonElement>('#IDButton2')?.addEventListener('click', () => {
      clicked = true;
    });

    const submitRes = adapter.submitIdentifier(doc, 'student@mail.polimi.it');
    expect(submitRes.ok).toBe(true);
    expect(clicked).toBe(true);
    expect((doc.querySelector('#IDToken1') as HTMLInputElement).value).toBe('student@mail.polimi.it');
  });

  it('proves Open/Closed Principle: plugs a custom Zoom SAML provider into DomFederatedAuthPageDriver without modifying core interfaces', async () => {
    const customZoomSpec = {
      providerId: 'zoom',
      displayName: 'Zoom',
      identifierPrompt: {
        hostnames: ['polimi-it.zoom.us'],
        pathnameSubstrings: ['/signin'],
        identifierInputSelector: 'input#email',
        submitButtonSelector: 'button#btn-continue',
        forceEnableSubmitButton: false
      },
      transitHostnames: ['polimi-it.zoom.us'],
      transitUrlSubstrings: ['/saml/sso'],
      authenticatedHostnames: ['zoom.us'],
      authenticatedSelectors: ['.zoom-profile-header']
    } as const;

    const zoomAdapter = new SelectorFederatedSsoProviderAdapter(customZoomSpec);
    const registry = new FederatedSsoProviderRegistry([zoomAdapter]);
    expect(registry.has('zoom')).toBe(true);
    expect(registry.require('zoom').displayName).toBe('Zoom');

    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <form id="zoom-form" action="/saml/sso">
            <input id="email" type="email" />
            <button id="btn-continue" type="button">Continue</button>
          </form>
        </body>
      </html>`,
      { url: 'https://polimi-it.zoom.us/signin' }
    );

    const driver = new DomFederatedAuthPageDriver({
      getDocument: () => dom.window.document,
      getLocation: () => dom.window.location,
      provider: zoomAdapter
    });

    expect(driver.federatedProviderId).toBe('zoom');
    const inspection = await driver.inspectFederatedSsoPage();
    expect(inspection.providerId).toBe('zoom');
    expect(inspection.status).toBe('login_required');
    expect(inspection.isIdentifierPrompt).toBe(true);

    let clicked = false;
    dom.window.document.querySelector('#btn-continue')?.addEventListener('click', () => {
      clicked = true;
    });

    const res = await driver.submitFederatedIdentifier('professor@polimi.it');
    expect(res.ok).toBe(true);
    expect(clicked).toBe(true);
    expect((dom.window.document.querySelector('#email') as HTMLInputElement).value).toBe('professor@polimi.it');
  });
});
