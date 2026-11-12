declare module 'jsdom' {
  export interface JSDOMOptions {
    url?: string;
    runScripts?: 'dangerously' | 'outside-only';
  }
  export class JSDOM {
    readonly window: Window & typeof globalThis & { eval(code: string): unknown };
    constructor(html?: string, options?: JSDOMOptions);
  }
}
