/**
 * @module @polisdk/storage-sqlite
 * Server-side master encryption key loader and auto-generator for multi-user vaults.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface MasterKeyOptions {
  /** Explicit master key string (minimum 16 characters). */
  explicitKey?: string;
  /** Path to read or auto-generate a persisted master key file. */
  keyFilePath?: string;
  /** Minimum accepted character length (default: 16). */
  minLength?: number;
}

/**
 * Resolve or auto-generate a server-side master encryption key.
 * Enforces file mode `0o600` when persisting on POSIX systems.
 */
export function resolveMasterEncryptionKey(options: MasterKeyOptions): string {
  const minLength = options.minLength ?? 16;
  const trimmedExplicit = (options.explicitKey ?? "").trim();

  if (trimmedExplicit.length >= minLength) {
    return trimmedExplicit;
  }

  if (!options.keyFilePath) {
    throw new Error(
      `Master encryption key must be at least ${minLength} characters or a keyFilePath must be provided.`,
    );
  }

  const keyFile = path.resolve(options.keyFilePath);
  const keyDir = path.dirname(keyFile);
  fs.mkdirSync(keyDir, { recursive: true });

  const generated = crypto.randomBytes(32).toString("base64url");
  try {
    fs.writeFileSync(keyFile, `${generated}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    try {
      fs.chmodSync(keyFile, 0o600);
    } catch {
      // chmodSync may be unsupported or a no-op on some filesystems
    }
    return generated;
  } catch (err) {
    const nodeErr = err as NodeJS.ErrnoException;
    if (nodeErr.code === "EEXIST") {
      const existing = fs.readFileSync(keyFile, "utf8").trim();
      if (existing.length >= minLength) {
        return existing;
      }
      throw new Error(
        `Existing master key file at ${keyFile} is shorter than minimum length (${minLength}). Refusing to overwrite existing key file.`,
      );
    }
    throw err;
  }
}
