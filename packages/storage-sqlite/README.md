# `@polisdk/storage-sqlite`

SQLite persistence adapter for `@polisdk/poliauth` providing multi-user identity management, encrypted per-user credential vaults, and encrypted session-state persistence.

## Features

- **`PoliAuthSqliteDatabase`**: Implements `UserIdentityRepositoryPort` using a neutral schema (`users` with `user_id TEXT PRIMARY KEY` and `user_vault_kv`).
- **`SqliteVaultStorageBackend` & `SqliteUserVaultStorageFactory`**: Implements `VaultStoragePort` and `UserVaultStorageFactoryPort`.
- **`SqliteSessionStateStore`**: Implements `SessionStateStorePort` with Web Crypto AES-256-GCM encryption.
- **`resolveMasterEncryptionKey`**: Resolves or auto-generates a server-side master encryption key file (`0o600`).
