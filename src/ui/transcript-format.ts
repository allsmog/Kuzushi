/**
 * Transcript formatters for the new TUI surfaces.
 *
 * Two pure functions over `AgentActivityLine`:
 *
 *   - `toCompactRow(line)` — tight one-line projection for the actor cards
 *     in `ModuleRunView` (last completed + currently running).
 *   - `toTranscriptEntry(line)` — Claude-Code-style `● Tool(args)` /
 *     `⎿ result` / `✻ Thinking` / `● prose` rows for the per-actor
 *     `ActorTranscriptView`.
 *
 * Glyph + color decisions are made up-front so the renderer is purely
 * presentational. We intentionally do not depend on Ink / chalk here —
 * the helpers return raw glyphs + plain strings so they're easy to test
 * and the renderer wraps them with `tokens.*` at draw time.
 */
import { truncateMiddle } from "./format.js";
import { BLACK_CIRCLE, FINDING_GLYPH, LOWER_HOOK, THINKING_GLYPH } from "./glyphs.js";
import type { AgentActivityLine } from "./state.js";

/** One-line summary used in the dashboard's per-actor activity card. */
export interface CompactRow {
  /** Single-character glyph used as the row's leading marker. */
  glyph: "→" | "✓" | "•" | "!" | "·" | "…";
  /** Verb or kind label, e.g. "Read" / "thinking" / "finding". */
  action: string;
  /** Inline argument hint, optional, e.g. "src/api/handlers.ts:42". */
  target?: string;
  /** Short summary text, typically the activity detail. */
  summary?: string;
}

/** Rich row for the per-actor full transcript. */
export interface TranscriptEntry {
  /** Leading glyph column ("●", "⎿", "✻", "★"). */
  glyph: typeof BLACK_CIRCLE | typeof LOWER_HOOK | typeof THINKING_GLYPH | typeof FINDING_GLYPH;
  /** Heading line text rendered next to the glyph. */
  head: string;
  /**
   * Optional secondary line rendered indented under `head` — used for
   * tool-call results (`⎿ <body>`) and longer reasoning excerpts.
   */
  body?: string;
  /** True when this row represents an in-flight tool-start. */
  inProgress?: boolean;
}

const MAX_TARGET_WIDTH = 56;
const MAX_SUMMARY_WIDTH = 80;
const MAX_BODY_WIDTH = 160;

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return truncateMiddle(value, max);
}

function cleanDetail(detail: string | undefined): string | undefined {
  if (!detail) return undefined;
  // Activity strings sometimes arrive as `"verb: target"` or `"verb · target"`;
  // we keep them whole but strip leading whitespace + trailing newlines.
  return detail.replace(/\s+$/, "").replace(/^\s+/, "");
}

/**
 * Project an `AgentActivityLine` to the compact row shown in actor
 * cards. The renderer is responsible for color (e.g. running rows in
 * `tokens.warn`, complete rows muted).
 */
export function toCompactRow(line: AgentActivityLine): CompactRow {
  const detail = cleanDetail(line.detail);
  const tool = line.toolName?.trim();

  switch (line.kind) {
    case "tool-start":
      return {
        glyph: "→",
        action: tool ?? "tool",
        ...(detail ? { target: truncate(detail, MAX_TARGET_WIDTH) } : {}),
      };
    case "tool-progress":
      return {
        glyph: "…",
        action: tool ?? "running",
        ...(detail ? { target: truncate(detail, MAX_TARGET_WIDTH) } : {}),
      };
    case "tool-complete":
      return {
        glyph: "✓",
        action: tool ?? "done",
        ...(detail ? { summary: truncate(detail, MAX_SUMMARY_WIDTH) } : {}),
      };
    case "summary":
      return {
        glyph: "·",
        action: "summary",
        ...(detail ? { summary: truncate(detail, MAX_SUMMARY_WIDTH) } : {}),
      };
    case "reasoning":
      return {
        glyph: "•",
        action: "thinking",
        ...(detail ? { summary: truncate(detail, MAX_SUMMARY_WIDTH) } : {}),
      };
    case "finding-preview":
      return {
        glyph: "!",
        action: "finding",
        ...(detail ? { summary: truncate(detail, MAX_SUMMARY_WIDTH) } : {}),
      };
  }
}

function formatToolCallHead(line: AgentActivityLine): string {
  const tool = line.toolName?.trim() ?? "tool";
  const detail = cleanDetail(line.detail);
  if (!detail) return tool;
  return `${tool}(${truncate(detail, MAX_TARGET_WIDTH)})`;
}

/**
 * Project an `AgentActivityLine` to a per-actor transcript entry.
 *
 * The mapping mirrors Claude Code's transcript convention:
 *
 *   tool-start       → ● Tool(args)            (in-flight)
 *   tool-progress    → ● Tool(args)            (in-flight)
 *   tool-complete    → ⎿ <result>              (under the parent ●)
 *   reasoning        → ✻ Thinking — <excerpt>
 *   summary          → ●  <text>               (assistant prose)
 *   finding-preview  → ★  <preview>            (synthesized findings line)
 */
export function toTranscriptEntry(line: AgentActivityLine): TranscriptEntry {
  const detail = cleanDetail(line.detail);

  switch (line.kind) {
    case "tool-start":
      return {
        glyph: BLACK_CIRCLE,
        head: formatToolCallHead(line),
        inProgress: true,
      };
    case "tool-progress":
      return {
        glyph: BLACK_CIRCLE,
        head: formatToolCallHead(line),
        inProgress: true,
      };
    case "tool-complete": {
      const tool = line.toolName?.trim();
      const head = tool ? tool : "result";
      return {
        glyph: LOWER_HOOK,
        head,
        ...(detail ? { body: truncate(detail, MAX_BODY_WIDTH) } : {}),
      };
    }
    case "reasoning":
      return {
        glyph: THINKING_GLYPH,
        head: detail ? `Thinking — ${truncate(detail, MAX_SUMMARY_WIDTH)}` : "Thinking…",
      };
    case "summary":
      return {
        glyph: BLACK_CIRCLE,
        head: detail ? truncate(detail, MAX_SUMMARY_WIDTH) : "(no summary)",
      };
    case "finding-preview":
      return {
        glyph: FINDING_GLYPH,
        head: detail ? `Finding — ${truncate(detail, MAX_SUMMARY_WIDTH)}` : "Finding",
      };
  }
}

/**
 * Strip the actor slug out of a fingerprint produced by
 * `buildActorFingerprint` (`<channel>:<Actor_Name>:<runIndex>`). Returns
 * the original string when it doesn't match the expected shape — the
 * caller should treat that as the actor's display name verbatim.
 */
export function actorLabelFromFingerprint(fingerprint: string): string {
  const parts = fingerprint.split(":");
  if (parts.length < 3) return fingerprint;
  const slug = parts[parts.length - 2] ?? "";
  const runIndex = parts[parts.length - 1] ?? "0";
  const name = slug.replace(/_/g, " ");
  return runIndex === "0" ? name : `${name} (run ${runIndex})`;
}

/**
 * Deterministic short alias for an actor fingerprint, useful for
 * keypress-driven drill-in (1, 2, 3, 4 → AUTH-01, DATA-02, …). Keeps the
 * mapping pure so the same input fingerprints always yield the same id.
 */
export function actorShortId(fingerprint: string, index: number): string {
  const label = actorLabelFromFingerprint(fingerprint);
  const upper = label.toUpperCase();
  // Pull the first run of letters as the prefix; default to "ACTOR".
  const match = upper.match(/[A-Z][A-Z0-9]*/);
  const head = (match?.[0] ?? "ACTOR").slice(0, 4);
  const num = String(index + 1).padStart(2, "0");
  return `${head}-${num}`;
}
