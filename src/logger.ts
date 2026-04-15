/**
 * Structured logger for kuzushi.
 *
 * Provides a pino-compatible interface using console.error as the transport
 * (stderr keeps stdout clean for machine output). Swap the implementation
 * to `pino` when the dependency is added — call sites stay unchanged.
 *
 * Features:
 * - Level filtering (quiet by default, debug only shown with --verbose / KUZUSHI_LOG_LEVEL=debug)
 * - Secret redaction: API key patterns auto-masked (preserves first 6 / last 4 chars)
 * - Logger caching via getLogger() factory
 * - Child loggers with additional context bindings
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

let globalLogLevel: LogLevel = resolveInitialLogLevel();

export interface Logger {
  debug(msg: string, ...args: unknown[]): void;
  debug(obj: Record<string, unknown>, msg: string): void;
  info(msg: string, ...args: unknown[]): void;
  info(obj: Record<string, unknown>, msg: string): void;
  warn(msg: string, ...args: unknown[]): void;
  warn(obj: Record<string, unknown>, msg: string): void;
  error(msg: string, ...args: unknown[]): void;
  error(obj: Record<string, unknown>, msg: string): void;
  child(bindings: Record<string, unknown>): Logger;
}

interface LoggerOptions {
  stage: string;
}

/** Set the global log level. */
export function setGlobalLogLevel(level: LogLevel): void {
  globalLogLevel = level;
}

/** Get the current global log level. */
export function getGlobalLogLevel(): LogLevel {
  return globalLogLevel;
}

const loggerCache = new Map<string, Logger>();

/** Get or create a cached logger by stage name. */
export function getLogger(stage: string): Logger {
  let logger = loggerCache.get(stage);
  if (!logger) {
    logger = createLogger({ stage });
    loggerCache.set(stage, logger);
  }
  return logger;
}

export function createLogger(opts: LoggerOptions): Logger {
  return buildLogger(opts.stage, {});
}

function buildLogger(
  stage: string,
  bindings: Record<string, unknown>,
): Logger {
  const prefix = `[${stage}]`;

  function shouldLog(level: LogLevel): boolean {
    return LEVEL_ORDER[level] >= LEVEL_ORDER[globalLogLevel];
  }

  function log(level: LogLevel, first: unknown, ...rest: unknown[]) {
    if (!shouldLog(level)) return;

    const bindingsStr = Object.keys(bindings).length > 0
      ? " " + JSON.stringify(redactObject(bindings))
      : "";

    if (typeof first === "object" && first !== null && typeof rest[0] === "string") {
      const redacted = redactObject(first as Record<string, unknown>);
      console.error(`${prefix} [${level}]${bindingsStr} ${rest[0]}`, redacted);
    } else {
      const msg = typeof first === "string" ? redactString(first) : first;
      console.error(`${prefix} [${level}]${bindingsStr} ${msg}`, ...rest);
    }
  }

  return {
    debug: (first: unknown, ...rest: unknown[]) => log("debug", first, ...rest),
    info: (first: unknown, ...rest: unknown[]) => log("info", first, ...rest),
    warn: (first: unknown, ...rest: unknown[]) => log("warn", first, ...rest),
    error: (first: unknown, ...rest: unknown[]) => log("error", first, ...rest),
    child: (childBindings: Record<string, unknown>) =>
      buildLogger(stage, { ...bindings, ...childBindings }),
  } as Logger;
}

/**
 * Regex matching common API key patterns.
 * Preserves first 6 and last 4 characters for debugging.
 */
const API_KEY_PATTERNS = [
  /\b(sk-ant-[a-zA-Z0-9_-]{10,})\b/g,
  /\b(sk-[a-zA-Z0-9_-]{20,})\b/g,
  /\b(key-[a-zA-Z0-9_-]{20,})\b/g,
  /\b(AIza[a-zA-Z0-9_-]{30,})\b/g,
];

/** Redact API key patterns in a string, preserving first 6 / last 4 chars. */
export function redactString(str: string): string {
  let result = str;
  for (const pattern of API_KEY_PATTERNS) {
    result = result.replace(pattern, (match) => {
      if (match.length <= 10) return match;
      return match.slice(0, 6) + "..." + match.slice(-4);
    });
  }
  return result;
}

/** Recursively redact secrets in structured metadata. */
function redactObject(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === "string") {
      result[key] = redactString(value);
    } else if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      result[key] = redactObject(value as Record<string, unknown>);
    } else {
      result[key] = value;
    }
  }
  return result;
}

function resolveInitialLogLevel(): LogLevel {
  const env = process.env["KUZUSHI_LOG_LEVEL"]?.toLowerCase();
  if (env && env in LEVEL_ORDER) {
    return env as LogLevel;
  }
  return "warn";
}
