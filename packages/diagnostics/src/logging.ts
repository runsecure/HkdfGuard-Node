/**
 * The minimal logging surface every HkdfGuard component accepts optionally, in place of the C#
 * original's `ILogger<T>?`. Any logger exposing `debug`/`error` with this shape works - including
 * `console` itself, or a one-line wrapper around pino/winston/bunyan.
 */
export interface Logger {
  debug(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
}

/**
 * Logs a debug-level message recording that operationName completed for name, mirroring the C#
 * original's source-generated ILogger extension. Only worth calling when
 * ComponentTelemetry.enableSensitiveLogging is set - failures (operationFailed) are always worth
 * logging, but a routine sensitive operation completing is not.
 *
 * logger may be omitted - every HkdfGuard component that accepts one treats it as optional, and a
 * missing logger is silently a no-op here rather than requiring every call site to guard it
 * separately.
 */
export function sensitiveOperationLogged(logger: Logger | undefined, operationName: string, name: string): void {
  logger?.debug(`${operationName} completed for ${name}.`, { operation: operationName, name });
}

/**
 * Logs an error-level message recording that operationName failed with error. Unlike
 * sensitiveOperationLogged, this is unconditional - failures are always worth logging.
 *
 * logger may be omitted (see {@link sensitiveOperationLogged}).
 */
export function operationFailed(logger: Logger | undefined, operationName: string, error: Error): void {
  logger?.error(`${operationName} failed.`, { operation: operationName, error });
}
