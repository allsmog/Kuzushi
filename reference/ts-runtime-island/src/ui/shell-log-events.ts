import type { ShellHistoryEntry } from "./state.js";
import { formatStoryEventPlain } from "./task-story.js";

export type ShellLogEventKind =
  | "command/input"
  | "command/output"
  | "assistant/text"
  | "tool/use"
  | "tool/result"
  | "progress"
  | "story"
  | "error"
  | "summary";

export interface ShellLogEvent {
  kind: ShellLogEventKind;
  text: string;
  timestamp: number;
  prompt?: string;
  tool?: string;
  displayName?: string;
  inputHint?: string;
  status?: "running" | "ok" | "fail" | "abort";
  elapsedSeconds?: number;
  resultOutput?: string;
}

export interface ShellLogFormatOptions {
  maxOutputLines?: number;
  maxLineLength?: number;
}

const DEFAULT_MAX_OUTPUT_LINES = 8;
const DEFAULT_MAX_LINE_LENGTH = 120;

export function projectShellHistoryEntry(entry: ShellHistoryEntry): ShellLogEvent {
  switch (entry.type) {
    case "input":
      return {
        kind: "command/input",
        text: entry.text,
        timestamp: entry.timestamp,
        prompt: entry.prompt,
      };
    case "output":
      return {
        kind: "command/output",
        text: entry.text,
        timestamp: entry.timestamp,
      };
    case "error":
      return {
        kind: "error",
        text: entry.text,
        timestamp: entry.timestamp,
      };
    case "story":
      return {
        kind: "story",
        text: entry.storyEvent ? formatStoryEventPlain(entry.storyEvent) : entry.text,
        timestamp: entry.timestamp,
      };
    case "tool-progress":
      if (entry.storyEvent) {
        return {
          kind: "story",
          text: formatStoryEventPlain(entry.storyEvent),
          timestamp: entry.timestamp,
        };
      }
      return {
        kind: "progress",
        text: entry.text,
        timestamp: entry.timestamp,
      };
    case "tool-call": {
      const status = entry.status ?? "running";
      return {
        kind: status === "running" ? "tool/use" : "tool/result",
        text: entry.text,
        timestamp: entry.timestamp,
        tool: entry.tool,
        displayName: entry.displayName,
        inputHint: entry.inputHint,
        status,
        elapsedSeconds: entry.elapsedSeconds,
        resultOutput: entry.resultOutput,
      };
    }
    case "hunt-post-mortem":
      return {
        kind: "summary",
        text: entry.text,
        timestamp: entry.timestamp,
      };
  }
}

export function formatShellHistoryEntryPlain(
  entry: ShellHistoryEntry,
  options: ShellLogFormatOptions = {},
): string[] {
  return formatShellLogEventPlain(projectShellHistoryEntry(entry), options);
}

export function formatShellLogEventPlain(
  event: ShellLogEvent,
  options: ShellLogFormatOptions = {},
): string[] {
  switch (event.kind) {
    case "command/input":
      return [`[input] ${event.prompt ?? ""}${event.text}`];
    case "command/output":
    case "assistant/text":
      return formatOutputBlock("output", event.text, options);
    case "error":
      return formatOutputBlock("error", event.text, options);
    case "progress":
      return [`[progress] ${clipLine(event.text, options.maxLineLength)}`];
    case "story":
      return [clipLine(event.text, options.maxLineLength)];
    case "summary":
      return [`[summary] ${clipLine(event.text, options.maxLineLength)}`];
    case "tool/use":
    case "tool/result":
      return [formatToolEvent(event, options)];
  }
}

export function shellHistoryPlainKey(entry: ShellHistoryEntry, index: number): string {
  return entry.id ?? `${index}:${entry.timestamp}:${entry.type}`;
}

export function shellHistoryPlainSignature(entry: ShellHistoryEntry): string {
  if (entry.type === "story" || entry.storyEvent) {
    const event = entry.storyEvent;
    return [
      entry.type,
      event?.id ?? "",
      event?.kind ?? "",
      event?.status ?? "",
      event?.message ?? entry.text,
      event?.timestamp ?? entry.timestamp,
    ].join(":");
  }
  if (entry.type === "tool-call") {
    return [
      entry.type,
      entry.status ?? "running",
      entry.elapsedSeconds ?? "",
      entry.resultOutput ?? "",
    ].join(":");
  }
  return entry.type;
}

function formatToolEvent(event: ShellLogEvent, options: ShellLogFormatOptions): string {
  const label = event.displayName ?? event.tool ?? stripToolGlyph(event.text) ?? "tool";
  const hint = event.inputHint ? `(${clipLine(event.inputHint, 48)})` : "";
  if (event.status === "running" || event.kind === "tool/use") {
    return `[tool] ${label}${hint} started`;
  }

  const status = event.status ?? "ok";
  const result = event.resultOutput
    ? ` · ${clipLine(event.resultOutput, options.maxLineLength)}`
    : "";
  const elapsed =
    event.elapsedSeconds != null && event.elapsedSeconds > 0 ? ` · ${event.elapsedSeconds}s` : "";
  return `[tool:${status}] ${label}${result}${elapsed}`;
}

function formatOutputBlock(
  label: "output" | "error",
  text: string,
  options: ShellLogFormatOptions,
): string[] {
  const maxLines = options.maxOutputLines ?? DEFAULT_MAX_OUTPUT_LINES;
  const maxLineLength = options.maxLineLength ?? DEFAULT_MAX_LINE_LENGTH;
  const lines = normalizeLines(text);
  const preview = lines.slice(0, maxLines).map((line) => clipLine(line, maxLineLength));
  const truncatedByLineCount = lines.length > maxLines;
  const truncatedByWidth = lines.some((line) => line.length > maxLineLength);

  if (!truncatedByLineCount && !truncatedByWidth) {
    return preview.map((line, index) => (index === 0 ? `[${label}] ${line}` : `  ${line}`));
  }

  const omitted = Math.max(0, lines.length - preview.length);
  const header =
    omitted > 0
      ? `[${label}] ${lines.length} lines; showing first ${preview.length}`
      : `[${label}] ${lines.length} line${lines.length === 1 ? "" : "s"}; clipped to ${maxLineLength} cols`;
  return [
    header,
    ...preview.map((line) => `  ${line}`),
    ...(omitted > 0 ? [`  ... ${omitted} more`] : []),
  ];
}

function normalizeLines(text: string): string[] {
  const normalized = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return normalized.length === 0 ? [""] : normalized.split("\n");
}

function clipLine(text: string, maxLineLength = DEFAULT_MAX_LINE_LENGTH): string {
  if (text.length <= maxLineLength) return text;
  if (maxLineLength <= 1) return "…";
  return `${text.slice(0, maxLineLength - 1)}…`;
}

function stripToolGlyph(text: string): string | undefined {
  const stripped = text.replace(/^[⏺●]\s*/, "").trim();
  return stripped.length > 0 ? stripped : undefined;
}
