/**
 * In-memory recording implementation of `PrintSink` for unit tests.
 *
 * Captures every status/good/error/warn/line call for later assertion.
 * `capture()` runs `fn` with no further indirection and returns the
 * concatenated text of every recorded line.
 */

import type { PrintLevel, PrintSink } from "../../copilot/print.js";

export interface PrintRecord {
  level: PrintLevel;
  text: string;
}

export interface RecordingPrintSink extends PrintSink {
  /** Every call made to this sink, in order. */
  readonly records: PrintRecord[];
  /** Filter helper — returns only records at the given level. */
  filter(level: PrintLevel): PrintRecord[];
  /** Drop all recorded entries. */
  clear(): void;
}

/**
 * Build a `PrintSink` stub that records every call. Distinct from the
 * production `createArraySink` in that the records preserve level +
 * un-tagged text (so tests don't have to strip `[*]`/`[+]` prefixes).
 *
 * @example
 *   const print = createRecordingPrintSink();
 *   await tool.execute(input, createMockToolContext({ print }));
 *   assert.ok(print.filter("good").some((r) => r.text.includes("scan complete")));
 */
export function createRecordingPrintSink(): RecordingPrintSink {
  const records: PrintRecord[] = [];
  const push = (level: PrintLevel, text: string): void => {
    records.push({ level, text });
  };
  const sink: RecordingPrintSink = {
    records,
    status(msg) {
      push("status", msg);
    },
    good(msg) {
      push("good", msg);
    },
    error(msg) {
      push("error", msg);
    },
    warn(msg) {
      push("warn", msg);
    },
    line(msg) {
      push("line", msg);
    },
    async capture(fn) {
      const before = records.length;
      await fn();
      const slice = records.slice(before);
      return slice.map((r) => r.text).join("\n");
    },
    filter(level) {
      return records.filter((r) => r.level === level);
    },
    clear() {
      records.length = 0;
    },
  };
  return sink;
}
