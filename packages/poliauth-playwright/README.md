# `@polisdk/poliauth-playwright`

Playwright browser driver (`PlaywrightAuthPageDriver`), multi-tenant `BrowserContext` session pool (`PlaywrightBrowserSessionPool`), and precompiled DOM adapter injection bundle for [`@polisdk/poliauth`](../poliauth).

## Key Features

- **`PlaywrightAuthPageDriver`**: Implements `AuthPageDriverPort` over any Playwright `Page`, automatically injecting `window.__PoliAuthAdapters` and guarding against transient execution-context destruction across SAML/JAF redirects.
- **`PlaywrightBrowserSessionPool`**: Implements `SessionContextPoolPort` with per-user cookie isolation, reference-counted locks, LRU capacity eviction, idle TTL cleanup, and encrypted `storageState` persistence.
- **Zero Runtime Build Dependencies**: The browser-injected IIFE bundle is precompiled at build time into `src/generated/injected-bundle-code.ts`, eliminating runtime dependencies on `esbuild` or `node:fs`.
