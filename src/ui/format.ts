/**
 * Terminal formatting utilities — progress bars, badges, costs, durations, etc.
 * Uses chalk for coloring and Unicode block characters for smooth visual rendering.
 */

import chalk from "chalk";
import type { Verdict } from "../types.js";
import { BORDER_GLYPHS, type BorderVariant } from "./glyphs.js";
import { icons } from "./icons.js";
import { normalizeSeverity, severityChalk, severityStyle } from "./severity.js";
import { clampTerminalCardWidth, resolveTerminalColumns } from "./terminal.js";
import { tokens } from "./tokens.js";

/**
 * Returns a chalk function appropriate for "secondary" text based on theme.
 * Delegates to `tokens.muted` — kept for backwards compatibility with older
 * call sites. New code should prefer `tokens.muted` directly.
 */
export function secondary(text: string): string {
  return tokens.muted(text);
}

// Partial block characters from thin to full (8 steps)
const PARTIAL_BLOCKS = [" ", "\u258F", "\u258E", "\u258D", "\u258C", "\u258B", "\u258A", "\u2589"];
const FULL_BLOCK = "\u2588"; // █
const EMPTY_BLOCK = "\u2591"; // ░

/**
 * Render a smooth Unicode progress bar.
 *
 * @param current - Current progress count
 * @param total - Total count
 * @param width - Bar width in characters (default 20)
 * @param color - Optional fill color token (defaults to `tokens.accent`).
 *   Pass `tokens.danger` for truly alarming progress; neutral progress
 *   (e.g. triage) should stay on the default accent.
 * @returns Formatted progress bar string with count
 */
export function progressBar(
  current: number,
  total: number,
  width = 20,
  color: (text: string) => string = tokens.accent,
): string {
  if (total <= 0) return `${EMPTY_BLOCK.repeat(width)} 0/0`;
  const ratio = Math.min(current / total, 1);
  const filledFull = Math.floor(ratio * width);
  const partialIndex = Math.floor((ratio * width - filledFull) * 8);
  const emptyCount = width - filledFull - (partialIndex > 0 ? 1 : 0);

  const filled = color(FULL_BLOCK.repeat(filledFull));
  const partial = partialIndex > 0 ? color(PARTIAL_BLOCKS[partialIndex]!) : "";
  const empty = chalk.dim(EMPTY_BLOCK.repeat(Math.max(0, emptyCount)));

  return `${filled}${partial}${empty} ${current}/${total}`;
}

/**
 * Format a USD cost with smart precision.
 *
 * - $0.00 when zero
 * - $0.0042 for sub-cent amounts (4 decimals)
 * - $1.24 for normal amounts (2 decimals)
 * - $142 for large amounts (0 decimals)
 */
export function formatCost(usd: number): string {
  if (usd === 0) return "$0.00";
  if (usd < 0.01) return `$${usd.toFixed(4)}`;
  if (usd < 100) return `$${usd.toFixed(2)}`;
  return `$${Math.round(usd)}`;
}

/**
 * Format milliseconds as a human-readable duration.
 *
 * - <1s: "432ms"
 * - 1s–60s: "12.3s"
 * - 1m–60m: "2m 34s"
 * - >=1h: "1h 12m"
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.round(seconds % 60);
  if (minutes < 60) return `${minutes}m ${remainingSeconds}s`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = Math.round(minutes % 60);
  return `${hours}h ${remainingMinutes}m`;
}

/**
 * Human-friendly relative age for activity timestamps. Used by the shell's
 * tool progress tail to annotate each entry with "just now / 12s ago / 2m ago".
 */
export function formatRelativeAgo(ts: number, now: number = Date.now()): string {
  const deltaMs = Math.max(0, now - ts);
  if (deltaMs < 5_000) return "just now";
  const seconds = Math.floor(deltaMs / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  if (minutes < 60) {
    return remainingSeconds === 0 ? `${minutes}m ago` : `${minutes}m ${remainingSeconds}s ago`;
  }
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return remainingMinutes === 0 ? `${hours}h ago` : `${hours}h ${remainingMinutes}m ago`;
}

/**
 * Create a colored background badge.
 *
 * @returns Chalk-formatted string like " CRITICAL "
 */
export function badge(
  text: string,
  color: "red" | "green" | "yellow" | "cyan" | "magenta" | "blue",
): string {
  const bgMap = {
    red: chalk.bgRed.white.bold,
    green: chalk.bgGreen.black.bold,
    yellow: chalk.bgYellow.black.bold,
    cyan: chalk.bgCyan.black.bold,
    magenta: chalk.bgMagenta.white.bold,
    blue: chalk.bgBlue.white.bold,
  } as const;
  return bgMap[color](` ${text.toUpperCase()} `);
}

/**
 * Format a severity level with icon and color.
 *
 * Pairs a Unicode glyph + uppercase label with the severity color from
 * `severity.ts`, so color-blind / NO_COLOR / screen-reader consumers still
 * read the tier. Unknown tiers fall through to `tokens.muted`.
 */
export function severityLabel(level: string): string {
  if (!level) return tokens.muted("");
  const sev = normalizeSeverity(level);
  const style = severityStyle(sev);
  return severityChalk(sev)(`${style.glyph} ${style.longLabel}`);
}

/**
 * Return icon + color for a verdict.
 */
export function verdictIcon(verdict: Verdict): string {
  switch (verdict) {
    case "tp":
      return tokens.danger(icons.error);
    case "fp":
      return tokens.success(icons.success);
    case "needs_review":
      return tokens.warn(icons.warning);
    case "by_design":
      return tokens.info(icons.info);
  }
}

/** Status values shared across pipeline stages, scanner sub-tasks, and result rows. */
export type StatusKind = "pending" | "active" | "done" | "error";

/** Caller context for `statusBadge` — reserved for future divergence, but today
 *  all three callers share the same glyph/color mapping. */
export type StatusBadgeKind = "stage" | "task" | "result";

/**
 * Canonical status → glyph + color mapping. Single source of truth for
 * `PipelineIndicator`, `ResultLine`, and `MonorepoProgress` — previously each
 * had its own ad-hoc status→icon/color ternary.
 *
 * Semantic choices (preserved from the scattered prior implementation):
 *   - pending → hollow circle, muted (not-yet-started)
 *   - active  → filled circle, `dangerStrong` for the attention-getting
 *               "currently scanning" alarmist vibe used throughout the scan
 *               pipeline today. (Spinner call-sites use `accent` for the
 *               animated frame; this is for the *static* glyph variant.)
 *   - done    → diamond, muted (retired to history)
 *   - error   → cross, `danger`
 */
export function statusBadge(
  _kind: StatusBadgeKind,
  status: StatusKind,
): { icon: string; color: (text: string) => string } {
  switch (status) {
    case "pending":
      return { icon: icons.pending, color: tokens.muted };
    case "active":
      return { icon: icons.active, color: tokens.focus };
    case "done":
      return { icon: icons.complete, color: tokens.success };
    case "error":
      return { icon: icons.error, color: tokens.danger };
  }
}

/**
 * Colored verdict label with icon.
 */
export function colorVerdict(verdict: Verdict): string {
  switch (verdict) {
    case "tp":
      return tokens.dangerStrong(`${icons.error} TRUE POSITIVE`);
    case "fp":
      return tokens.success(`${icons.success} FALSE POSITIVE`);
    case "needs_review":
      return tokens.warn(`${icons.warning} needs review`);
    case "by_design":
      return tokens.info(`${icons.info} BY DESIGN`);
  }
}

/**
 * Render items with tree connectors.
 *
 * @param items - Array of text strings
 * @param indent - Number of spaces to indent (default 4)
 * @returns Array of lines with ├─ / └─ prefixes
 */
export function treeLines(items: string[], indent = 4): string[] {
  const pad = " ".repeat(indent);
  return items.map((item, i) => {
    const connector = i === items.length - 1 ? icons.treeLast : icons.treeMiddle;
    return `${pad}${connector} ${item}`;
  });
}

/**
 * Proportional colored bar chart for labeled values (e.g. verdict distribution).
 *
 * @returns Array of lines like: "tp           ██████░░░░  12 (8%)"
 */
export function miniBarChart(
  entries: Array<{ label: string; value: number; color: (s: string) => string }>,
  barWidth = 20,
): string[] {
  const total = entries.reduce((s, e) => s + e.value, 0);
  if (total === 0) return [];
  const maxLabelLen = Math.max(...entries.map((e) => e.label.length));

  return entries
    .filter((e) => e.value > 0)
    .map((e) => {
      const filled = Math.round((e.value / total) * barWidth);
      const empty = barWidth - filled;
      const pct = ((e.value / total) * 100).toFixed(0);
      const bar = e.color(FULL_BLOCK.repeat(filled)) + chalk.dim(EMPTY_BLOCK.repeat(empty));
      return `${e.label.padEnd(maxLabelLen)} ${bar} ${String(e.value).padStart(3)} (${pct}%)`;
    });
}

interface BoxFrameOptions {
  variant?: BorderVariant;
  width?: number;
}

interface BoxEdgeLineOptions extends BoxFrameOptions {
  left?: string;
  right?: string;
  borderStyle?: (text: string) => string;
}

function borderGlyphs(variant: BorderVariant = "rounded") {
  return BORDER_GLYPHS[variant];
}

function clampBoxWidth(width: number): number {
  return Math.max(4, Math.floor(width));
}

function buildEdgeLine(
  width: number,
  startCorner: string,
  endCorner: string,
  horizontal: string,
  left = "",
  right = "",
  borderStyle: (text: string) => string = tokens.metadata,
): string {
  const safeWidth = clampBoxWidth(width);
  const fill = Math.max(0, safeWidth - 2 - visibleWidth(left) - visibleWidth(right));
  return `${borderStyle(startCorner)}${left}${borderStyle(horizontal.repeat(fill))}${right}${borderStyle(endCorner)}`;
}

export function boxTopLine({
  left = "",
  right = "",
  width = 60,
  variant = "rounded",
  borderStyle = tokens.metadata,
}: BoxEdgeLineOptions = {}): string {
  const glyphs = borderGlyphs(variant);
  return buildEdgeLine(
    width,
    glyphs.topLeft,
    glyphs.topRight,
    glyphs.horizontal,
    left,
    right,
    borderStyle,
  );
}

export function boxBottomLine({
  left = "",
  right = "",
  width = 60,
  variant = "rounded",
  borderStyle = tokens.metadata,
}: BoxEdgeLineOptions = {}): string {
  const glyphs = borderGlyphs(variant);
  return buildEdgeLine(
    width,
    glyphs.bottomLeft,
    glyphs.bottomRight,
    glyphs.horizontal,
    left,
    right,
    borderStyle,
  );
}

/**
 * Build a box header line: ╭─ Title ────────────╮
 */
export function boxHeader(title: string, width = 60, options: BoxFrameOptions = {}): string {
  const glyphs = borderGlyphs(options.variant);
  return boxTopLine({
    width,
    variant: options.variant,
    left: `${tokens.metadata(glyphs.horizontal)}${tokens.label(` ${title} `)}`,
  });
}

/**
 * Build a box footer line: ╰────────────────────╯
 */
export function boxFooter(width = 60, options: BoxFrameOptions = {}): string {
  return boxBottomLine({ width, variant: options.variant });
}

/**
 * Build a box divider line: ├────────────────────┤
 */
export function boxDivider(width = 60, options: BoxFrameOptions = {}): string {
  const glyphs = borderGlyphs(options.variant);
  const safeWidth = clampBoxWidth(width);
  return tokens.metadata(
    `${glyphs.dividerLeft}${glyphs.horizontal.repeat(safeWidth - 2)}${glyphs.dividerRight}`,
  );
}

export function boxRowPrefix(options: BoxFrameOptions = {}): string {
  return tokens.metadata(`${borderGlyphs(options.variant).vertical} `);
}

export function boxInnerWidth(width = 60): number {
  return Math.max(0, clampBoxWidth(width) - 2);
}

/**
 * Build a box content line: │  content  │ (padded to width)
 */
export function boxLine(content: string, width = 60): string {
  // We can't easily measure ANSI string width, so just use the borders
  return `${chalk.dim(borderGlyphs().vertical)}  ${content}`;
}

/**
 * Compute a card width that fits the current terminal while keeping a sensible minimum.
 */
export function terminalCardWidth(maxWidth = 88, minWidth = 56, columns?: number): number {
  return clampTerminalCardWidth(
    columns ?? resolveTerminalColumns(undefined, maxWidth),
    maxWidth,
    minWidth,
  );
}

// ─── Column / path width utilities ────────────────────────────────────────
// Added as part of the Wave 1 responsive-geometry pass (S4).

// biome-ignore lint/suspicious/noControlCharactersInRegex: ESC/CSI bytes are intrinsic to ANSI escape detection
const ANSI_RE = /[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g;

/** Horizontal alignment for `padCell`. */
export type Align = "left" | "right" | "center";

/**
 * Measure the visible width of a string with ANSI escape codes stripped.
 * Tiny ANSI-strip implementation — `string-width` isn't currently a dep.
 */
export function visibleWidth(s: string): number {
  return s.replace(ANSI_RE, "").length;
}

/**
 * Truncate the end of a string with an ellipsis, respecting visible width.
 */
export function truncateEnd(s: string, maxWidth: number, ellipsis = "\u2026"): string {
  if (visibleWidth(s) <= maxWidth) return s;
  if (maxWidth <= ellipsis.length) return ellipsis.slice(0, Math.max(0, maxWidth));
  const plain = s.replace(ANSI_RE, "");
  return plain.slice(0, maxWidth - ellipsis.length) + ellipsis;
}

/**
 * Middle-truncate a path-like string, preserving the trailing basename.
 * `"src/ui/components/CopilotShell.tsx"` at width 22 becomes
 * `"src…/CopilotShell.tsx"`. For non-path strings, truncates in the middle.
 */
export function truncateMiddle(s: string, maxWidth: number, ellipsis = "\u2026"): string {
  const plain = s.replace(ANSI_RE, "");
  if (plain.length <= maxWidth) return s;
  if (maxWidth <= ellipsis.length) return ellipsis.slice(0, Math.max(0, maxWidth));

  const slash = plain.lastIndexOf("/");
  if (slash >= 0) {
    const basename = plain.slice(slash); // includes leading "/"
    const budget = maxWidth - ellipsis.length - basename.length;
    if (budget > 0) {
      return plain.slice(0, budget) + ellipsis + basename;
    }
    // Basename itself is too long — end-truncate basename preserving last chars.
    const kept = Math.max(0, maxWidth - ellipsis.length);
    return ellipsis + basename.slice(-kept);
  }

  const head = Math.ceil((maxWidth - ellipsis.length) / 2);
  const tail = maxWidth - ellipsis.length - head;
  return plain.slice(0, head) + ellipsis + plain.slice(plain.length - tail);
}

/**
 * Render a wall-clock HH:MM:SS for a UNIX-ms timestamp. Used by shell history
 * rows to mark when each event was appended.
 */
export function formatClock(ts: number): string {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

/**
 * Pad a string to exactly `width` columns, ANSI-aware.
 */
export function padCell(s: string, width: number, align: Align = "left"): string {
  const vw = visibleWidth(s);
  if (vw >= width) return s;
  const gap = width - vw;
  if (align === "right") return " ".repeat(gap) + s;
  if (align === "center") {
    const left = Math.floor(gap / 2);
    const right = gap - left;
    return " ".repeat(left) + s + " ".repeat(right);
  }
  return s + " ".repeat(gap);
}
