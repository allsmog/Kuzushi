import chalk from "chalk";
import { icons } from "./icons.js";
import type { NoticeLevel, UIStore } from "./state.js";

type WriteFn = typeof process.stderr.write;

interface OutputRuntimeState {
  store?: UIStore;
  verbose: boolean;
  quiet: boolean;
  restoreStderr?: () => void;
}

const state: OutputRuntimeState = {
  verbose: false,
  quiet: false,
};

export function configureTerminalOutput(options: {
  store?: UIStore;
  verbose?: boolean;
  quiet?: boolean;
}): void {
  resetTerminalOutput();
  state.store = options.store;
  state.verbose = options.verbose === true;
  state.quiet = options.quiet === true;
  state.restoreStderr = installStderrInterceptor();
}

export function resetTerminalOutput(): void {
  state.restoreStderr?.();
  state.restoreStderr = undefined;
  state.store = undefined;
  state.verbose = false;
  state.quiet = false;
}

export function shouldStreamDiagnostics(): boolean {
  return state.verbose || !state.quiet;
}

export function emitOutputNotice(notice: {
  level: NoticeLevel;
  message: string;
  detail?: string;
  source?: string;
}): void {
  if (state.store) {
    state.store.addNotice(notice);
    return;
  }

  const prefix = formatNoticePrefix(notice.level);
  const detail = notice.detail ? ` ${chalk.dim(notice.detail)}` : "";
  const _line = `${prefix} ${notice.message}${detail}`;
  if (notice.level === "error") {
    return;
  }
}

export function emitDiagnostic(
  source: string,
  message: string,
  level: "info" | "warning" | "error" = "info",
): void {
  const text = `[${source}] ${message}`.replace(/\n+$/u, "");

  if (shouldStreamDiagnostics()) {
    const line = text.endsWith("\n") ? text : `${text}\n`;
    process.stderr.write(line);
    return;
  }

  if (level === "warning" || level === "error") {
    emitOutputNotice({
      level,
      message: source,
      detail: message,
      source,
    });
  }
}

function installStderrInterceptor(): () => void {
  const originalWrite = process.stderr.write.bind(process.stderr) as WriteFn;

  process.stderr.write = ((
    chunk: string | Uint8Array,
    encoding?: BufferEncoding | ((error?: Error | null) => void),
    cb?: (error?: Error | null) => void,
  ) => {
    const text =
      typeof chunk === "string"
        ? chunk
        : Buffer.from(chunk).toString(typeof encoding === "string" ? encoding : "utf-8");
    if (!shouldStreamDiagnostics() && shouldSuppressDiagnosticChunk(text)) {
      if (typeof encoding === "function") {
        encoding();
      } else {
        cb?.();
      }
      return true;
    }

    return originalWrite(chunk as never, encoding as never, cb);
  }) as WriteFn;

  return () => {
    process.stderr.write = originalWrite;
  };
}

function shouldSuppressDiagnosticChunk(text: string): boolean {
  const trimmed = text.trim();
  if (trimmed.length === 0) {
    return false;
  }

  if (/^\[[^\]]+\]\s+\[(info|debug)\]/.test(trimmed)) {
    return true;
  }

  if (!/^\s*\[[a-z0-9-]+/i.test(trimmed)) {
    return false;
  }

  if (/\b(error|failed|fatal|warning)\b/i.test(trimmed)) {
    return false;
  }

  return true;
}

function formatNoticePrefix(level: NoticeLevel): string {
  switch (level) {
    case "success":
      return chalk.green(icons.success);
    case "warning":
      return chalk.yellow(icons.warning);
    case "error":
      return chalk.red(icons.error);
    default:
      return chalk.blue(icons.info);
  }
}
