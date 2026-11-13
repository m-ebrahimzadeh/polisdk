import { describe, expect, it } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  isPolimiLoginPage,
  isPolimiAuthenticatedSessionPage,
  inspectPolimiPageStage,
  recoverPolimiSessionPage,
  submitPolimiCredentials,
  submitPolimiOtp,
  classifyPolimiSemanticError
} from '../adapters/polimi-dom-adapter.js';
import { classifyPolimiSemanticError as classifyFromDomain } from '../domain/index.js';
import { classifyPolimiSemanticError as classifyFromRoot } from '../src/index.js';
import {
  WEBEX_SAML_FLOW_SPEC,
  WebexSamlProviderAdapter
} from '../adapters/webex-sso-dom-adapter.js';
import {
  FederatedSsoProviderRegistry,
  SelectorFederatedSsoProviderAdapter,
  inspectFederatedSsoPageBySpec,
  isFederatedIdentifierPromptPage,
  isFederatedLoginTriggerPage,
  isFederatedSsoTransitLocation,
  submitFederatedIdentifierBySpec,
  triggerFederatedLoginBySpec
} from '../adapters/index.js';
import { DomAuthPageDriver, DomFederatedAuthPageDriver } from '../adapters/dom-page-driver.js';
import type { FederatedSsoProviderSpec } from '../interfaces/federated-sso-provider-port.js';

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

  it('handles Mode A identifierPrompt via WEBEX_SAML_FLOW_SPEC and dispatches input/change/blur events to enable #IDButton2', () => {
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
    expect(isFederatedIdentifierPromptPage(WEBEX_SAML_FLOW_SPEC, doc, loc)).toBe(true);
    expect(isFederatedSsoTransitLocation(WEBEX_SAML_FLOW_SPEC, loc.href, loc.hostname)).toBe(true);
    const inspection = inspectFederatedSsoPageBySpec(WEBEX_SAML_FLOW_SPEC, doc, loc);
    expect(inspection.status).toBe('login_required');
    expect(inspection.isIdentifierPrompt).toBe(true);
    expect(inspection.isLoginTrigger).toBe(false);
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

    const res = submitFederatedIdentifierBySpec(
      WEBEX_SAML_FLOW_SPEC,
      doc,
      ' mario.rossi@mail.polimi.it '
    );
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
    expect(inspection.isLoginTrigger).toBe(false);

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
    const customZoomSpec: FederatedSsoProviderSpec = {
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
    };

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
    expect(inspection.isLoginTrigger).toBe(false);

    let clicked = false;
    dom.window.document.querySelector('#btn-continue')?.addEventListener('click', () => {
      clicked = true;
    });

    const res = await driver.submitFederatedIdentifier('professor@polimi.it');
    expect(res.ok).toBe(true);
    expect(clicked).toBe(true);
    expect((dom.window.document.querySelector('#email') as HTMLInputElement).value).toBe('professor@polimi.it');
  });

  it('supports Mode B click-through loginTrigger Shibboleth SPs (e.g., WeBeep /login/index.php)', async () => {
    const webeepSpec: FederatedSsoProviderSpec = {
      providerId: 'webeep',
      displayName: 'WeBeep',
      entryUrl: 'https://webeep.polimi.it/login/index.php',
      loginTrigger: {
        hostnames: ['webeep.polimi.it'],
        pathnameSubstrings: ['/login/index.php'],
        triggerSelector: 'a.btn-shibboleth',
        contextualErrorSelector: '.loginerrors .alert-danger',
        forceEnableTrigger: true
      },
      transitHostnames: ['shibidp.polimi.it'],
      transitUrlSubstrings: ['/auth/shibboleth/'],
      authenticatedHostnames: ['webeep.polimi.it'],
      authenticatedSelectors: ['.usermenu', '#page-my-index']
    };

    const loginDom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <a class="btn-shibboleth" href="/auth/shibboleth/index.php" disabled>PoliMi Credentials</a>
        </body>
      </html>`,
      { url: 'https://webeep.polimi.it/login/index.php' }
    );

    expect(isFederatedLoginTriggerPage(webeepSpec, loginDom.window.document, loginDom.window.location)).toBe(true);

    const driver = new DomFederatedAuthPageDriver({
      getDocument: () => loginDom.window.document,
      getLocation: () => loginDom.window.location,
      provider: new SelectorFederatedSsoProviderAdapter(webeepSpec)
    });

    const loginInspect = await driver.inspectFederatedSsoPage();
    expect(loginInspect.providerId).toBe('webeep');
    expect(loginInspect.status).toBe('login_required');
    expect(loginInspect.isIdentifierPrompt).toBe(false);
    expect(loginInspect.isLoginTrigger).toBe(true);
    expect(loginInspect.isSamlTransitPage).toBe(false);

    let triggerClicked = false;
    loginDom.window.document
      .querySelector('.btn-shibboleth')
      ?.addEventListener('click', (e) => {
        e.preventDefault();
        triggerClicked = true;
      });

    const triggerRes = await driver.triggerFederatedLogin();
    expect(triggerRes.ok).toBe(true);
    expect(triggerClicked).toBe(true);

    // Contextual error on loginTrigger page
    const errorDom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <div class="loginerrors"><div class="alert-danger">Invalid Shibboleth session</div></div>
          <a class="btn-shibboleth" href="/auth/shibboleth/index.php">PoliMi Credentials</a>
        </body>
      </html>`,
      { url: 'https://webeep.polimi.it/login/index.php' }
    );
    const errorInspect = inspectFederatedSsoPageBySpec(
      webeepSpec,
      errorDom.window.document,
      errorDom.window.location
    );
    expect(errorInspect.status).toBe('error');
    expect(errorInspect.isLoginTrigger).toBe(true);
    expect(errorInspect.reason).toContain('Invalid Shibboleth session');

    // Authenticated SP landing on same hostname
    const authDom = new JSDOM(
      `<!DOCTYPE html><html><body id="page-my-index"><div class="usermenu">Student</div></body></html>`,
      { url: 'https://webeep.polimi.it/my/' }
    );
    const authInspect = inspectFederatedSsoPageBySpec(
      webeepSpec,
      authDom.window.document,
      authDom.window.location
    );
    expect(authInspect.status).toBe('authenticated');
    expect(authInspect.isLoginTrigger).toBe(false);
  });

  it('supports Mode C direct-redirect Shibboleth SPs without identifierPrompt or loginTrigger', () => {
    const directSpec: FederatedSsoProviderSpec = {
      providerId: 'career-direct',
      displayName: 'PoliMi Career Services',
      entryUrl: 'https://webeep.polimi.it/auth/shibboleth/index.php',
      transitHostnames: ['shibidp.polimi.it'],
      transitUrlSubstrings: ['/auth/shibboleth/'],
      authenticatedHostnames: ['webeep.polimi.it']
    };

    const transitDom = new JSDOM(`<!DOCTYPE html><html><body>Redirecting...</body></html>`, {
      url: 'https://webeep.polimi.it/auth/shibboleth/index.php'
    });
    const transitInspect = inspectFederatedSsoPageBySpec(
      directSpec,
      transitDom.window.document,
      transitDom.window.location
    );
    expect(transitInspect.status).toBe('sso_in_transit');
    expect(transitInspect.isSamlTransitPage).toBe(true);
    expect(transitInspect.isIdentifierPrompt).toBe(false);
    expect(transitInspect.isLoginTrigger).toBe(false);

    const idpDom = new JSDOM(`<!DOCTYPE html><html><body>IdP</body></html>`, {
      url: 'https://shibidp.polimi.it/idp/profile/SAML2/Redirect/SSO'
    });
    const idpInspect = inspectFederatedSsoPageBySpec(
      directSpec,
      idpDom.window.document,
      idpDom.window.location
    );
    expect(idpInspect.status).toBe('sso_in_transit');
    expect(idpInspect.isSamlTransitPage).toBe(true);

    const authDom = new JSDOM(`<!DOCTYPE html><html><body>Dashboard</body></html>`, {
      url: 'https://webeep.polimi.it/my/'
    });
    const authInspect = inspectFederatedSsoPageBySpec(
      directSpec,
      authDom.window.document,
      authDom.window.location
    );
    expect(authInspect.status).toBe('authenticated');

    expect(submitFederatedIdentifierBySpec(directSpec, authDom.window.document, 'a@polimi.it').ok).toBe(
      false
    );
    expect(triggerFederatedLoginBySpec(directSpec, authDom.window.document).ok).toBe(false);
  });

  it('classifies HTTP 503, maintenance banner, and empty body as PORTAL_OUTAGE_OR_NETWORK_ERROR', () => {
    const gwDom = new JSDOM(`<!DOCTYPE html><html><body>503 Service Unavailable</body></html>`, {
      url: 'https://aunicalogin.polimi.it/aunicalogin/getservizio.xml?id_servizio=376'
    });
    const res503 = inspectPolimiPageStage(gwDom.window.document, gwDom.window.location, {
      httpStatus: 503
    });
    expect(res503.stage).toBe('unknown');
    expect(res503.httpStatus).toBe(503);
    expect(res503.diagnosticError?.classification).toBe('PORTAL_OUTAGE_OR_NETWORK_ERROR');

    const maintDom = new JSDOM(
      `<!DOCTYPE html><html><body>
        <div class="poli-messages"><div class="alert-warning"><span class="jaf-message">Servizio temporaneamente non disponibile per manutenzione programmata.</span></div></div>
      </body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp' }
    );
    const resMaint = inspectPolimiPageStage(maintDom.window.document, maintDom.window.location, {
      httpStatus: 200
    });
    expect(resMaint.stage).toBe('unknown');
    expect(resMaint.diagnosticSnapshot?.hasMaintenanceBanner).toBe(true);
    expect(resMaint.diagnosticError?.classification).toBe('PORTAL_OUTAGE_OR_NETWORK_ERROR');

    const emptyDom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
      url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp'
    });
    const resEmpty = inspectPolimiPageStage(emptyDom.window.document, emptyDom.window.location, {
      httpStatus: 200
    });
    expect(resEmpty.stage).toBe('unknown');
    expect(resEmpty.diagnosticSnapshot?.hasEmptyBody).toBe(true);
    expect(resEmpty.diagnosticError?.classification).toBe('PORTAL_OUTAGE_OR_NETWORK_ERROR');
  });

  it('classifies populated HTTP 200 redesigned PoliMi IdP DOM as DOM_SELECTOR_DRIFT and scrubs secrets', () => {
    const redesignedDom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <head><title>Politecnico di Milano - New SSO</title></head>
        <body>
          <main class="new-idp-layout">
            <h1>Accesso Unico</h1>
            <form action="/new-login">
              <input id="renamed-user-field" name="username" />
              <input id="renamed-pass-field" type="password" name="pass" />
              <button type="submit">Entra</button>
            </form>
          </main>
        </body>
      </html>`,
      {
        url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do?SAMLRequest=TOPSECRET_SAML_PAYLOAD&__pj1=SECRET_PJ1_HASH&ticket=ST-999-SECRET&password=SecretPassword123!'
      }
    );

    const inspection = inspectPolimiPageStage(
      redesignedDom.window.document,
      redesignedDom.window.location,
      { httpStatus: 200 }
    );

    expect(inspection.stage).toBe('unknown');
    expect(inspection.diagnosticSnapshot?.hasEmptyBody).toBe(false);
    expect(inspection.diagnosticSnapshot?.hasMaintenanceBanner).toBe(false);
    expect(inspection.diagnosticError?.classification).toBe('DOM_SELECTOR_DRIFT');

    const serialized = JSON.stringify(inspection);
    expect(serialized).not.toContain('TOPSECRET_SAML_PAYLOAD');
    expect(serialized).not.toContain('SECRET_PJ1_HASH');
    expect(serialized).not.toContain('ST-999-SECRET');
    expect(serialized).not.toContain('SecretPassword123!');
    expect(serialized).toContain('[REDACTED]');
  });

  it('prioritizes non-dissms evn_continua button over earlier #submit-dissms trap, falls back safely, and flags missing submit drift', () => {
    const clickedIds: string[] = [];
    const domTrapFirst = new JSDOM(
      `<!DOCTYPE html><html><body>
        <form id="form_scelta2fa" action="IdentificazioneDFA.do">
          <input id="otp" name="otp" type="text" />
          <button id="submit-dissms" name="evn_continua" type="submit">Disabilita SMS</button>
          <button id="btn-continua-otp" name="evn_continua" type="submit">Continua</button>
        </form>
      </body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneDFA.do' }
    );
    domTrapFirst.window.document
      .getElementById('submit-dissms')
      ?.addEventListener('click', (e) => {
        e.preventDefault();
        clickedIds.push('submit-dissms');
      });
    domTrapFirst.window.document
      .getElementById('btn-continua-otp')
      ?.addEventListener('click', (e) => {
        e.preventDefault();
        clickedIds.push('btn-continua-otp');
      });

    const priorityRes = submitPolimiOtp(
      domTrapFirst.window.document,
      '654321',
      domTrapFirst.window.location
    );
    expect(priorityRes.ok).toBe(true);
    expect(clickedIds).toEqual(['btn-continua-otp']);

    // Sole visible button fallback to #submit-dissms (while skipping .jaf-visually-hidden)
    const fallbackClicks: string[] = [];
    const domSoleDissms = new JSDOM(
      `<!DOCTYPE html><html><body>
        <form id="form_scelta2fa" action="IdentificazioneDFA.do">
          <button class="jaf-visually-hidden" name="evn_continua" type="submit">Hidden</button>
          <input id="otp" name="otp" type="text" />
          <button id="submit-dissms" name="evn_continua" type="submit">Continua</button>
        </form>
      </body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneDFA.do' }
    );
    domSoleDissms.window.document
      .getElementById('submit-dissms')
      ?.addEventListener('click', (e) => {
        e.preventDefault();
        fallbackClicks.push('submit-dissms');
      });
    const fallbackRes = submitPolimiOtp(
      domSoleDissms.window.document,
      '654321',
      domSoleDissms.window.location
    );
    expect(fallbackRes.ok).toBe(true);
    expect(fallbackClicks).toEqual(['submit-dissms']);

    // Missing submit button and no form -> DOM_SELECTOR_DRIFT diagnostic
    const domNoSubmit = new JSDOM(
      `<!DOCTYPE html><html><body><div id="otp-wrap"><input id="otp" name="otp" /></div></body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneDFA.do' }
    );
    const missingSubmitRes = submitPolimiOtp(
      domNoSubmit.window.document,
      '654321',
      domNoSubmit.window.location
    );
    expect(missingSubmitRes.ok).toBe(false);
    expect(missingSubmitRes.diagnostic?.classification).toBe('DOM_SELECTOR_DRIFT');
  });

  it('classifies all 6 PolimiSemanticErrorCode variants across Italian and English IdP banners', () => {
    expect(classifyFromDomain).toBe(classifyPolimiSemanticError);
    expect(classifyFromRoot).toBe(classifyPolimiSemanticError);

    // 1. INVALID_CREDENTIALS (Italian & English Stage 1 banners)
    const domInvalidIt = new JSDOM(
      `<!DOCTYPE html><html><head><title>Polimi - Autenticazione</title></head><body>
        <div class="poli-messages"><div class="alert-danger"><span class="jaf-message">Credenziali non valide</span></div></div>
        <form id="login"><input id="login" name="login" /><input id="password" name="password" /></form>
      </body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do' }
    );
    const resInvalidIt = inspectPolimiPageStage(
      domInvalidIt.window.document,
      domInvalidIt.window.location
    );
    expect(resInvalidIt.stage).toBe('credentials');
    expect(resInvalidIt.semanticErrorCode).toBe('INVALID_CREDENTIALS');

    const domInvalidEn = new JSDOM(
      `<!DOCTYPE html><html><head><title>Polimi - Autenticazione</title></head><body>
        <div class="alert-danger">Invalid credentials: wrong username or password</div>
        <form id="login"><input id="login" name="login" /><input id="password" name="password" /></form>
      </body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do' }
    );
    const resInvalidEn = inspectPolimiPageStage(
      domInvalidEn.window.document,
      domInvalidEn.window.location
    );
    expect(resInvalidEn.stage).toBe('credentials');
    expect(resInvalidEn.semanticErrorCode).toBe('INVALID_CREDENTIALS');

    // 2. PASSWORD_EXPIRED (Italian warning & English danger)
    const domExpiredIt = new JSDOM(
      `<!DOCTYPE html><html><head><title>Polimi - Autenticazione</title></head><body>
        <div class="alert-warning">Password scaduta: cambio password obbligatorio</div>
        <form id="login"><input id="login" name="login" /><input id="password" name="password" /></form>
      </body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do' }
    );
    const resExpiredIt = inspectPolimiPageStage(
      domExpiredIt.window.document,
      domExpiredIt.window.location
    );
    expect(resExpiredIt.stage).toBe('credentials');
    expect(resExpiredIt.semanticErrorCode).toBe('PASSWORD_EXPIRED');

    expect(
      classifyPolimiSemanticError({
        operation: 'submitCredentials',
        stage: 'credentials',
        errorMessage: 'Password expired - modify your password before continuing'
      })
    ).toBe('PASSWORD_EXPIRED');

    // 3. ACCOUNT_LOCKED (Italian & English, including Stage 2 override)
    const domLockedIt = new JSDOM(
      `<!DOCTYPE html><html><head><title>Polimi - Autenticazione 2FA</title></head><body>
        <div class="poli-messages"><div class="alert-danger"><span class="jaf-message">Account bloccato per troppi tentativi</span></div></div>
        <form id="form_scelta2fa"><input id="otp" name="otp" /></form>
      </body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneDFA.do' }
    );
    const resLockedIt = inspectPolimiPageStage(
      domLockedIt.window.document,
      domLockedIt.window.location
    );
    expect(resLockedIt.stage).toBe('otp');
    expect(resLockedIt.semanticErrorCode).toBe('ACCOUNT_LOCKED');

    expect(
      classifyPolimiSemanticError({
        operation: 'inspectPolimiPageStage',
        stage: 'unknown',
        errorMessage: 'Account locked due to too many attempts'
      })
    ).toBe('ACCOUNT_LOCKED');

    // 4. OTP_REJECTED (Stage 2 Italian & English)
    const domOtpRejectedIt = new JSDOM(
      `<!DOCTYPE html><html><head><title>Polimi - Autenticazione 2FA</title></head><body>
        <div class="poli-messages"><div class="alert-danger"><span class="jaf-message">Codice OTP non valido</span></div></div>
        <form id="form_scelta2fa"><input id="otp" name="otp" /></form>
      </body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneDFA.do' }
    );
    const resOtpRejectedIt = inspectPolimiPageStage(
      domOtpRejectedIt.window.document,
      domOtpRejectedIt.window.location
    );
    expect(resOtpRejectedIt.stage).toBe('otp');
    expect(resOtpRejectedIt.semanticErrorCode).toBe('OTP_REJECTED');

    expect(
      classifyPolimiSemanticError({
        operation: 'submitOtp',
        stage: 'otp',
        errorMessage: 'Invalid verification code provided'
      })
    ).toBe('OTP_REJECTED');

    // 5. IDP_MAINTENANCE (HTTP 503 / maintenance banner)
    const domMaint = new JSDOM(
      `<!DOCTYPE html><html><head><title>Manutenzione</title></head><body>
        <div class="maintenance-banner">Servizio momentaneamente non disponibile per manutenzione</div>
      </body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do' }
    );
    const resMaint = inspectPolimiPageStage(
      domMaint.window.document,
      domMaint.window.location,
      { httpStatus: 503 }
    );
    expect(resMaint.semanticErrorCode).toBe('IDP_MAINTENANCE');
    expect(resMaint.diagnosticError?.classification).toBe('PORTAL_OUTAGE_OR_NETWORK_ERROR');

    // 6. DOM_SELECTOR_DRIFT (populated HTTP 200 DOM on *.polimi.it without matched stage)
    const domDrift = new JSDOM(
      `<!DOCTYPE html><html><head><title>Polimi - Nuovo Portale</title></head><body>
        <main><div id="redesigned-sso-app">Unexpected Login Layout</div></main>
      </body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do' }
    );
    const resDrift = inspectPolimiPageStage(
      domDrift.window.document,
      domDrift.window.location,
      { httpStatus: 200 }
    );
    expect(resDrift.stage).toBe('unknown');
    expect(resDrift.semanticErrorCode).toBe('DOM_SELECTOR_DRIFT');
    expect(resDrift.diagnosticError?.classification).toBe('DOM_SELECTOR_DRIFT');

    // Non-regression: Stage 0 session expired warning must not trigger semantic credential error
    const domExpiredSession = new JSDOM(
      `<!DOCTYPE html><html><head><title>Polimi</title></head><body>
        <div class="alert-warning">Sessione di lavoro scaduta</div>
      </body></html>`,
      { url: 'https://aunicalogin.polimi.it/aunicalogin/SessioneTerminata.do' }
    );
    const resExpiredSession = inspectPolimiPageStage(
      domExpiredSession.window.document,
      domExpiredSession.window.location
    );
    expect(resExpiredSession.stage).toBe('session_expired');
    expect(resExpiredSession.semanticErrorCode).toBeUndefined();
  });
});
