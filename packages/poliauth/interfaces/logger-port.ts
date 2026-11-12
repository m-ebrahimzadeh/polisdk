/**
 * @module @polisdk/poliauth/interfaces/logger-port
 * Structured, Secret-Redacting Logger Port.
 */

export interface AuthLoggerPort {
  debug(message: string, ...meta: unknown[]): void;
  info(message: string, ...meta: unknown[]): void;
  warn(message: string, ...meta: unknown[]): void;
  error(message: string, ...meta: unknown[]): void;
}
