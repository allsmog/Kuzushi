/**
 * error-format — Ink-free utilities that classify and structure errors for
 * the UI layer. Upgrades `ErrorCard`'s headline + trace rendering and surfaces
 * an actionable "Next Step" per category.
 */

export type ErrorCategory =
  | "rate_limit"
  | "auth"
  | "budget"
  | "transient"
  | "validation"
  | "fatal"
  | "unknown";

export interface FormattedErrorFrame {
  file: string;
  line?: number;
  column?: number;
  source?: string;
}

export interface FormattedError {
  headline: string;
  category: ErrorCategory;
  nextStep?: string;
  frames: ReadonlyArray<FormattedErrorFrame>;
  raw: string;
}

export interface FormatErrorOptions {
  maxFrames?: number;
  includeRaw?: boolean;
}

const HEADLINE_MAX = 200;

function safeMessage(err: unknown): string {
  if (err instanceof Error) return err.message || err.name || "Error";
  if (typeof err === "string") return err;
  if (err == null) return "Unknown error";
  try {
    return JSON.stringify(err);
  } catch {
    return Object.prototype.toString.call(err);
  }
}

function stackOf(err: unknown): string {
  if (err instanceof Error && typeof err.stack === "string") return err.stack;
  return "";
}

const FRAME_RE = /at (?:(?<fn>\S+) \()?(?<file>[^()\s]+?):(?<line>\d+):(?<col>\d+)\)?/;

function parseFrames(stack: string, maxFrames: number): FormattedErrorFrame[] {
  if (!stack) return [];
  const lines = stack.split("\n").slice(1);
  const frames: FormattedErrorFrame[] = [];
  for (const raw of lines) {
    if (frames.length >= maxFrames) break;
    const match = raw.match(FRAME_RE);
    if (!match?.groups) continue;
    const { file, line, col } = match.groups;
    if (!file) continue;
    if (file.startsWith("node:") || file.includes("node_modules/")) continue;
    frames.push({
      file,
      line: line ? Number.parseInt(line, 10) : undefined,
      column: col ? Number.parseInt(col, 10) : undefined,
    });
  }
  return frames;
}

export function classifyError(err: unknown): ErrorCategory {
  const msg = safeMessage(err).toLowerCase();
  const status =
    err && typeof err === "object" && "status" in err
      ? Number((err as { status?: unknown }).status)
      : undefined;
  if (status === 401 || status === 403) return "auth";
  if (status === 429 || /rate ?limit|too many requests/.test(msg)) return "rate_limit";
  if (/budget|spend|quota/.test(msg)) return "budget";
  if (/econnreset|etimedout|enotfound|network|fetch failed/i.test(msg)) return "transient";
  if (/validation|zod|invalid|schema/.test(msg)) return "validation";
  if (err instanceof Error && err.name === "FatalError") return "fatal";
  if (/fatal|panic/.test(msg)) return "fatal";
  return "unknown";
}

export function suggestNextStep(_err: unknown, category: ErrorCategory): string | undefined {
  switch (category) {
    case "auth":
      return "Check ANTHROPIC_API_KEY environment variable or --api-key flag.";
    case "rate_limit":
      return "Wait ~60s and retry, or lower --triage-concurrency.";
    case "budget":
      return "Increase --budget or remove the cap.";
    case "transient":
      return "Network blip — retry the command.";
    case "validation":
      return "Config validation failed — check the field named in the message.";
    default:
      return undefined;
  }
}

export function formatError(err: unknown, options: FormatErrorOptions = {}): FormattedError {
  const { maxFrames = 5, includeRaw = false } = options;
  const message = safeMessage(err);
  const headline = message.split("\n")[0]?.slice(0, HEADLINE_MAX) ?? "Error";
  const category = classifyError(err);
  const frames = parseFrames(stackOf(err), maxFrames);
  const raw = includeRaw ? stackOf(err) || safeMessage(err) : "";
  return {
    headline,
    category,
    nextStep: suggestNextStep(err, category),
    frames,
    raw,
  };
}
