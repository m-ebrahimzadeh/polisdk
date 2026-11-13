import {
  isPolimiLoginPage,
  isPolimiAuthenticatedSessionPage,
  inspectPolimiPageStage,
  recoverPolimiSessionPage,
  submitPolimiCredentials,
  submitPolimiOtp,
  isFederatedSsoTransitLocation,
  isFederatedIdentifierPromptPage,
  isFederatedLoginTriggerPage,
  inspectFederatedSsoPageBySpec,
  submitFederatedIdentifierBySpec,
  triggerFederatedLoginBySpec
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
  federatedSso: {
    isFederatedSsoTransitLocation: typeof isFederatedSsoTransitLocation;
    isFederatedIdentifierPromptPage: typeof isFederatedIdentifierPromptPage;
    isFederatedLoginTriggerPage: typeof isFederatedLoginTriggerPage;
    inspectFederatedSsoPageBySpec: typeof inspectFederatedSsoPageBySpec;
    submitFederatedIdentifierBySpec: typeof submitFederatedIdentifierBySpec;
    triggerFederatedLoginBySpec: typeof triggerFederatedLoginBySpec;
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
    federatedSso: {
      isFederatedSsoTransitLocation,
      isFederatedIdentifierPromptPage,
      isFederatedLoginTriggerPage,
      inspectFederatedSsoPageBySpec,
      submitFederatedIdentifierBySpec,
      triggerFederatedLoginBySpec
    }
  };
}
