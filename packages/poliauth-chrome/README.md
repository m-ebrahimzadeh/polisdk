# `@polisdk/poliauth-chrome`

Chrome Extension MV3 adapters (`chrome.storage.local` and `chrome.tabs.sendMessage`) for `@polisdk/poliauth`.

## Features

- **`ChromeLocalVaultStorage`**: Implements `VaultStoragePort` backed by `chrome.storage.local`.
- **`ChromeExtensionTabDriver`**: Implements `AuthPageDriverPort` from a service worker or popup by sending `PoliAuthTabMessage` commands via `chrome.tabs.sendMessage`.
- **`createPoliAuthContentScriptHandler`**: Dispatches incoming `PoliAuthTabMessage` commands in a content script directly to `DomAuthPageDriver`.
