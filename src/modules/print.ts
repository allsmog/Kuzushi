/**
 * msfconsole-style print helpers for module authors.
 *
 * Four levels — status (cyan [*]), good (green [+]), error (red [-]),
 * warn (yellow [!]) — plus plain `line`. An optional `onPrint` hook lets
 * callers tee every emitted line into shell output, an audit log, or tests.
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

type PrintMethodKey = "status" | "good" | "error" | "warn" | "line";
type PrintMethods = Pick<PrintSink, PrintMethodKey>;
type TagFormatter = (prefix: string, color: string) => string;
type PrintEmitter = (level: PrintLevel, formatted: string) => void;

const PRINT_METHOD_KEYS: PrintMethodKey[] = ["status", "good", "error", "warn", "line"];

export function createPrintSink(opts: PrintOptions = {}): PrintSink {
  const useColor = shouldColor(opts);
  const write = opts.write ?? ((s: string) => process.stdout.write(s));
  const tag = (prefix: string, color: string): string =>
    useColor ? `${color}${prefix}${ANSI.reset}` : prefix;
  const emit = (level: PrintLevel, formatted: string): void => {
    opts.onPrint?.(formatted, level);
    write(`${formatted}\n`);
  };
  const methods = createPrintMethods(tag, emit);

  return {
    ...methods,
    async capture(this: PrintSink, fn) {
      return capturePrintOutput(this, opts, fn);
    },
  };
}

function createPrintMethods(tag: TagFormatter, emit: PrintEmitter): PrintMethods {
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
  };
}

async function capturePrintOutput(
  sink: PrintSink,
  opts: PrintOptions,
  fn: () => void | Promise<void>,
): Promise<string> {
  const parts: string[] = [];
  const scoped = createPrintSink({
    ...opts,
    color: false,
    write: (s) => {
      parts.push(s);
    },
  });
  const saved = replacePrintMethods(sink, printMethodsFromSink(scoped));
  try {
    await fn();
  } finally {
    restorePrintMethods(sink, saved);
  }
  return parts.join("");
}

function printMethodsFromSink(sink: PrintSink): PrintMethods {
  return {
    status: sink.status,
    good: sink.good,
    error: sink.error,
    warn: sink.warn,
    line: sink.line,
  };
}

function replacePrintMethods(sink: PrintSink, methods: PrintMethods): PrintMethods {
  const saved = printMethodsFromSink(sink);
  for (const key of PRINT_METHOD_KEYS) {
    sink[key] = methods[key];
  }
  return saved;
}

function restorePrintMethods(sink: PrintSink, saved: PrintMethods): void {
  for (const key of PRINT_METHOD_KEYS) {
    sink[key] = saved[key];
  }
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
