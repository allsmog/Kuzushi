/**
 * In-memory recording implementation of `ToolLogger` for unit tests.
 *
 * All four levels (info/warn/error/debug) record to `.records` in order so
 * tests can assert on diagnostic output without wiring the MessageBus.
 */

import type { ToolLogger } from "../../modules/host-handles.js";

export type LogLevel = keyof ToolLogger;

export interface LogRecord {
  level: LogLevel;
  message: string;
  meta?: Record<string, unknown>;
}

export interface RecordingLogger extends ToolLogger {
  /** Every call made to the logger, in order. */
  readonly records: LogRecord[];
  /** Filter helper: returns only records at the given level. */
  filter(level: LogLevel): LogRecord[];
  /** Drop all recorded entries. */
  clear(): void;
}

/**
 * Build a `ToolLogger` stub that records every call. Useful for asserting
 * a tool emits an expected warning or error without standing up the host
 * MessageBus-backed logger.
 *
 * @example
 *   const logger = createRecordingLogger();
 *   await tool.execute(input, createMockToolContext({ logger }));
 *   assert.equal(logger.filter("warn").length, 1);
 */
export function createRecordingLogger(): RecordingLogger {
  const records: LogRecord[] = [];
  const push = (level: LogLevel, message: string, meta?: Record<string, unknown>): void => {
    const entry: LogRecord = meta !== undefined ? { level, message, meta } : { level, message };
    records.push(entry);
  };
  return {
    records,
    info(message, meta) {
      push("info", message, meta);
    },
    warn(message, meta) {
      push("warn", message, meta);
    },
    error(message, meta) {
      push("error", message, meta);
    },
    debug(message, meta) {
      push("debug", message, meta);
    },
    filter(level) {
      return records.filter((r) => r.level === level);
    },
    clear() {
      records.length = 0;
    },
  };
}
