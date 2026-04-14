/**
 * Terminal formatting utilities — progress bars, badges, costs, durations, etc.
 * Uses chalk for coloring and Unicode block characters for smooth visual rendering.
 */
import chalk from "chalk";
import type { Verdict } from "../types.js";
import { icons } from "./icons.js";

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
 * @returns Formatted progress bar string with count
 */
export function progressBar(current: number, total: number, width = 20): string {
  if (total <= 0) return `${EMPTY_BLOCK.repeat(width)} 0/0`;
  const ratio = Math.min(current / total, 1);
  const filledFull = Math.floor(ratio * width);
  const partialIndex = Math.floor((ratio * width - filledFull) * 8);
  const emptyCount = width - filledFull - (partialIndex > 0 ? 1 : 0);

  const filled = chalk.green(FULL_BLOCK.repeat(filledFull));
  const partial = partialIndex > 0 ? chalk.green(PARTIAL_BLOCKS[partialIndex]!) : "";
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
 */
export function severityLabel(level: string): string {
  const upper = level.toUpperCase();
  switch (upper) {
    case "CRITICAL":
      return chalk.red.bold(`${icons.error} ${upper}`);
    case "ERROR":
    case "HIGH":
      return chalk.red(`${icons.error} ${upper}`);
    case "WARNING":
    case "MEDIUM":
      return chalk.yellow(`${icons.warning} ${upper}`);
    case "INFO":
    case "LOW":
      return chalk.blue(`${icons.info} ${upper}`);
    default:
      return chalk.dim(upper);
  }
}

/**
 * Return icon + color for a verdict.
 */
export function verdictIcon(verdict: Verdict): string {
  switch (verdict) {
    case "tp":
      return chalk.red(icons.error);
    case "fp":
      return chalk.green(icons.success);
    case "needs_review":
      return chalk.yellow(icons.warning);
    case "by_design":
      return chalk.blue(icons.info);
  }
}

/**
 * Colored verdict label with icon.
 */
export function colorVerdict(verdict: Verdict): string {
  switch (verdict) {
    case "tp":
      return chalk.red.bold(`${icons.error} TRUE POSITIVE`);
    case "fp":
      return chalk.green(`${icons.success} false positive`);
    case "needs_review":
      return chalk.yellow(`${icons.warning} needs review`);
    case "by_design":
      return chalk.blue(`${icons.info} BY DESIGN`);
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

/**
 * Build a box header line: ╭─ Title ────────────╮
 */
export function boxHeader(title: string, width = 60): string {
  const titlePart = ` ${title} `;
  const fill = Math.max(0, width - 2 - titlePart.length - 1); // -2 for corners, -1 for dash before title
  return chalk.dim(
    `${icons.boxTopLeft}${icons.boxHorizontal}${chalk.reset.bold(titlePart)}${chalk.dim(icons.boxHorizontal.repeat(fill))}${icons.boxTopRight}`,
  );
}

/**
 * Build a box footer line: ╰────────────────────╯
 */
export function boxFooter(width = 60): string {
  return chalk.dim(
    `${icons.boxBottomLeft}${icons.boxHorizontal.repeat(width - 2)}${icons.boxBottomRight}`,
  );
}

/**
 * Build a box divider line: ├────────────────────┤
 */
export function boxDivider(width = 60): string {
  return chalk.dim(
    `${icons.boxDividerLeft}${icons.boxHorizontal.repeat(width - 2)}${icons.boxDividerRight}`,
  );
}

/**
 * Build a box content line: │  content  │ (padded to width)
 */
export function boxLine(content: string, width = 60): string {
  // We can't easily measure ANSI string width, so just use the borders
  return `${chalk.dim(icons.boxVertical)}  ${content}`;
}
