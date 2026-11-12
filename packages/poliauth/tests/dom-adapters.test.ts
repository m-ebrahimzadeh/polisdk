import { describe, expect, it } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  isPolimiLoginPage,
  isPolimiArchivePage,
  isPolimiTargetServicePage,
  inspectPolimiPageStage,
  recoverPolimiSessionPage,
  submitPolimiCredentials,
  submitPolimiOtp,
  clickPortalService,
  clickRecordingArchivesOnPortal
} from '../adapters/polimi-dom-adapter.js';
import {
  isWebexEmailSsoPage,
  inspectWebexSsoPage,
  submitWebexEmailLogin
} from '../adapters/webex-sso-dom-adapter.js';
import { WEBEEP_SERVICE } from '../domain/service-registry.js';
import { getInjectedAuthAdapterBundleCode } from '../adapters/injected-auth-bundle.js';

describe('PoliMi & Webex SAML SSO DOM Adapters', () => {
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
      { url: 'https://aunicalogin.polimi.it/aunicalogin/aunicalogin.jsp?id_servizio=2314' }
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

  it('detects Stage 3 Servizi Online portal and clicks target service link (both Recordings Archive and custom services)', () => {
    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <h1>Servizi Online</h1>
          <a id="arch-link" href="/portaleservizi/portaleservizi/controller/servizi/Servizi.do?evn_srv=evento&idServizio=2314">
            Archivio registrazioni didattica
          </a>
          <a id="webeep-link" href="/portaleservizi/portaleservizi/controller/servizi/Servizi.do?evn_srv=evento&idServizio=2166">
            WeBeep
          </a>
        </body>
      </html>`,
      { url: 'https://servizionline.polimi.it/portaleservizi/portaleservizi/controller/Portale.do' }
    );

    const doc = dom.window.document;
    expect(inspectPolimiPageStage(doc, dom.window.location).stage).toBe('portal');

    let archiveClicked = false;
    doc.querySelector('#arch-link')?.addEventListener('click', (e) => {
      e.preventDefault();
      archiveClicked = true;
    });

    const archRes = clickRecordingArchivesOnPortal(doc);
    expect(archRes.ok).toBe(true);
    expect(archiveClicked).toBe(true);

    let webeepClicked = false;
    doc.querySelector('#webeep-link')?.addEventListener('click', (e) => {
      e.preventDefault();
      webeepClicked = true;
    });

    const webeepRes = clickPortalService(doc, WEBEEP_SERVICE);
    expect(webeepRes.ok).toBe(true);
    expect(webeepClicked).toBe(true);
  });

  it('detects Stage 4 authenticated target service page', () => {
    const dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <h1>Archivio registrazioni didattica</h1>
          <select name="aa"><option value="2024">2024/2025</option></select>
        </body>
      </html>`,
      {
        url: 'https://onlineservices.polimi.it/archivioregistrazioni/archivioregistrazioni/controller/ArchivioListActivity.do'
      }
    );

    const doc = dom.window.document;
    const loc = dom.window.location;
    expect(isPolimiArchivePage(doc, loc)).toBe(true);
    expect(isPolimiTargetServicePage(doc, loc)).toBe(true);
    expect(inspectPolimiPageStage(doc, loc).stage).toBe('archive');
  });

  it('handles Stage 5 Webex SAML SSO email prompt and dispatches input/change/blur events to enable #IDButton2', () => {
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
    expect(inspection.isEmailSsoPage).toBe(true);

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

  it('compiles and evaluates the self-contained IIFE injected adapter bundle in a browser window', () => {
    const bundleCode = getInjectedAuthAdapterBundleCode();
    expect(bundleCode.length).toBeGreaterThan(500);

    const dom = new JSDOM(`<!DOCTYPE html><html><body><input id="otp" name="otp" /></body></html>`, {
      url: 'https://aunicalogin.polimi.it/aunicalogin/controller/IdentificazioneUnica.do',
      runScripts: 'outside-only'
    });

    dom.window.eval(bundleCode);
    const injected = (dom.window as unknown as { __PoliAuthAdapters: Record<string, any> })
      .__PoliAuthAdapters;
    expect(injected).toBeDefined();
    expect(typeof injected.polimi.inspectPolimiPageStage).toBe('function');
    expect(typeof injected.webexSso.submitWebexEmailLogin).toBe('function');

    const stage = injected.polimi.inspectPolimiPageStage(
      dom.window.document,
      dom.window.location
    );
    expect(stage.stage).toBe('otp');
  });
});
