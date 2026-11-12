/**
 * @module @polisdk/poliauth/interfaces/maybe-promise
 * Shared utility type for ports that may be implemented synchronously or asynchronously.
 */

/**
 * A value that is either available immediately or via a `Promise`
 * (e.g. synchronous `better-sqlite3` vs. asynchronous remote repositories).
 */
export type MaybePromise<T> = T | Promise<T>;
