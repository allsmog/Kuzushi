/**
 * Structured logger for kuzushi.
 *
 * Provides a pino-compatible interface using console.error as the transport
 * (stderr keeps stdout clean for machine output). Swap the implementation
 * to `pino` when the dependency is added — call sites stay unchanged.
 */

export interface Logger {
  debug(msg: string, ...args: unknown[]): void;
  debug(obj: Record<string, unknown>, msg: string): void;
  info(msg: string, ...args: unknown[]): void;
  info(obj: Record<string, unknown>, msg: string): void;
  warn(msg: string, ...args: unknown[]): void;
  warn(obj: Record<string, unknown>, msg: string): void;
  error(msg: string, ...args: unknown[]): void;
  error(obj: Record<string, unknown>, msg: string): void;
}

interface LoggerOptions {
  stage: string;
}

export function createLogger(opts: LoggerOptions): Logger {
  const prefix = `[${opts.stage}]`;

  function log(level: string, first: unknown, ...rest: unknown[]) {
    if (typeof first === "object" && first !== null && typeof rest[0] === "string") {
      console.error(`${prefix} [${level}] ${rest[0]}`, first);
    } else {
      console.error(`${prefix} [${level}] ${first}`, ...rest);
    }
  }

  return {
    debug: (first: unknown, ...rest: unknown[]) => log("debug", first, ...rest),
    info: (first: unknown, ...rest: unknown[]) => log("info", first, ...rest),
    warn: (first: unknown, ...rest: unknown[]) => log("warn", first, ...rest),
    error: (first: unknown, ...rest: unknown[]) => log("error", first, ...rest),
  } as Logger;
}
