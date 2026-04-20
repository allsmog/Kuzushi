/**
 * msfconsole-style print helpers.
 *
 * Four levels — status (cyan [*]), good (green [+]), error (red [-]),
 * warn (yellow [!]) — plus plain `line`. An optional `onPrint` hook lets
 * callers tee every emitted line into the Ink UI, an audit log, or tests.
 *
 * See lib/rex/ui/text/shell.rb in metasploit-framework for the origin.
 */

export type PrintLevel = "status" | "good" | "error" | "warn" | "line";

export interface PrintSink {
  status(msg: string): void;
  good(msg: string): void;
  error(msg: string): void;
  warn(msg: string): void;
  line(msg: string): void;
  /** Capture a section of output and return the joined buffer. */
  capture(fn: () => void | Promise<void>): Promise<string>;
}

export interface PrintOptions {
  /** If false, strip ANSI colors from emitted output. Default: auto-detect TTY. */
  color?: boolean;
  /**
   * Hook invoked for every line (post-formatting, pre-write). Receives the
   * fully-formatted string plus the level tag. Useful for audit logs and
   * UI forwarding.
   */
  onPrint?: (line: string, level: PrintLevel) => void;
  /** Where to write — defaults to process.stdout.write. */
  write?: (s: string) => void;
}

const ANSI = {
  reset: "\u001b[0m",
  cyan: "\u001b[36m",
  green: "\u001b[32m",
  red: "\u001b[31m",
  yellow: "\u001b[33m",
  bold: "\u001b[1m",
  dim: "\u001b[2m",
};

// biome-ignore lint/suspicious/noControlCharactersInRegex: ANSI escape sequences require the ESC control character.
const ANSI_REGEX = /\u001b\[[0-9;]*m/g;

function stripAnsi(s: string): string {
  return s.replace(ANSI_REGEX, "");
}

function shouldColor(opts: PrintOptions): boolean {
  if (opts.color !== undefined) return opts.color;
  if (process.env["NO_COLOR"] !== undefined) return false;
  return Boolean(process.stdout.isTTY);
}

export function createPrintSink(opts: PrintOptions = {}): PrintSink {
  const useColor = shouldColor(opts);
  const write = opts.write ?? ((s: string) => process.stdout.write(s));

  const tag = (prefix: string, color: string): string =>
    useColor ? `${color}${prefix}${ANSI.reset}` : prefix;

  const emit = (level: PrintLevel, formatted: string): void => {
    opts.onPrint?.(formatted, level);
    write(`${formatted}\n`);
  };

  return {
    status(msg) {
      emit("status", `${tag("[*]", ANSI.cyan)} ${msg}`);
    },
    good(msg) {
      emit("good", `${tag("[+]", ANSI.green)} ${msg}`);
    },
    error(msg) {
      emit("error", `${tag("[-]", ANSI.red)} ${msg}`);
    },
    warn(msg) {
      emit("warn", `${tag("[!]", ANSI.yellow)} ${msg}`);
    },
    line(msg) {
      emit("line", msg);
    },
    async capture(fn) {
      const parts: string[] = [];
      const scoped = createPrintSink({
        ...opts,
        color: false,
        write: (s) => {
          parts.push(s);
        },
      });
      const outerScoped = {
        status: scoped.status,
        good: scoped.good,
        error: scoped.error,
        warn: scoped.warn,
        line: scoped.line,
      };
      const saved: Record<keyof typeof outerScoped, unknown> = {} as never;
      for (const key of Object.keys(outerScoped) as Array<keyof typeof outerScoped>) {
        saved[key] = (this as unknown as Record<string, unknown>)[key];
        (this as unknown as Record<string, unknown>)[key] = outerScoped[key];
      }
      try {
        await fn();
      } finally {
        for (const key of Object.keys(outerScoped) as Array<keyof typeof outerScoped>) {
          (this as unknown as Record<string, unknown>)[key] = saved[key];
        }
      }
      return parts.join("");
    },
  };
}

/** Strip ANSI escape codes from a string (test helper). */
export { stripAnsi };

/** A no-op sink that captures lines into an array (test helper). */
export function createArraySink(): PrintSink & {
  lines: Array<{ level: PrintLevel; text: string }>;
} {
  const lines: Array<{ level: PrintLevel; text: string }> = [];
  const sink = createPrintSink({
    color: false,
    write: () => {},
    onPrint: (line, level) => {
      lines.push({ level, text: line });
    },
  });
  return Object.assign(sink, { lines });
}
