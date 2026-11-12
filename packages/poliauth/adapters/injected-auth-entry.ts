import * as polimi from './polimi-dom-adapter.js';
import * as webexSso from './webex-sso-dom-adapter.js';

export interface InjectedPoliAuthAdapters {
  polimi: typeof polimi;
  webexSso: typeof webexSso;
}

declare global {
  interface Window {
    __PoliAuthAdapters?: InjectedPoliAuthAdapters;
  }
}

if (typeof window !== 'undefined') {
  window.__PoliAuthAdapters = {
    polimi,
    webexSso
  };
}
