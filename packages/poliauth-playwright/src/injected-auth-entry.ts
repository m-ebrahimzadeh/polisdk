import {
  isPolimiLoginPage,
  isPolimiAuthenticatedSessionPage,
  inspectPolimiPageStage,
  recoverPolimiSessionPage,
  submitPolimiCredentials,
  submitPolimiOtp,
  isWebexOrPolimiSsoTransitUrl,
  isWebexEmailSsoPage,
  inspectWebexSsoPage,
  submitWebexEmailLogin
} from '@polisdk/poliauth/adapters';

export interface InjectedPoliAuthAdapters {
  polimi: {
    isPolimiLoginPage: typeof isPolimiLoginPage;
    isPolimiAuthenticatedSessionPage: typeof isPolimiAuthenticatedSessionPage;
    inspectPolimiPageStage: typeof inspectPolimiPageStage;
    recoverPolimiSessionPage: typeof recoverPolimiSessionPage;
    submitPolimiCredentials: typeof submitPolimiCredentials;
    submitPolimiOtp: typeof submitPolimiOtp;
  };
  webexSso: {
    isWebexOrPolimiSsoTransitUrl: typeof isWebexOrPolimiSsoTransitUrl;
    isWebexEmailSsoPage: typeof isWebexEmailSsoPage;
    inspectWebexSsoPage: typeof inspectWebexSsoPage;
    submitWebexEmailLogin: typeof submitWebexEmailLogin;
  };
}

declare global {
  interface Window {
    __PoliAuthAdapters?: InjectedPoliAuthAdapters;
  }
}

if (typeof window !== 'undefined') {
  window.__PoliAuthAdapters = {
    polimi: {
      isPolimiLoginPage,
      isPolimiAuthenticatedSessionPage,
      inspectPolimiPageStage,
      recoverPolimiSessionPage,
      submitPolimiCredentials,
      submitPolimiOtp
    },
    webexSso: {
      isWebexOrPolimiSsoTransitUrl,
      isWebexEmailSsoPage,
      inspectWebexSsoPage,
      submitWebexEmailLogin
    }
  };
}
