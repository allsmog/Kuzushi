export interface TerminalLike {
  columns?: number | null;
  rows?: number | null;
}

export const DEFAULT_TERMINAL_COLUMNS = 80;
export const DEFAULT_TERMINAL_ROWS = 24;

function asPositiveInt(value: unknown): number | undefined {
  const parsed =
    typeof value === "number"
      ? value
      : typeof value === "string" && value.trim().length > 0
        ? Number.parseInt(value, 10)
        : Number.NaN;
  if (!Number.isFinite(parsed) || parsed <= 0) return undefined;
  return Math.floor(parsed);
}

export function resolveTerminalColumns(
  source?: TerminalLike | null,
  fallback = DEFAULT_TERMINAL_COLUMNS,
): number {
  return asPositiveInt(source?.columns) ?? asPositiveInt(process.env["COLUMNS"]) ?? fallback;
}

export function resolveTerminalRows(
  source?: TerminalLike | null,
  fallback = DEFAULT_TERMINAL_ROWS,
): number {
  return asPositiveInt(source?.rows) ?? asPositiveInt(process.env["LINES"]) ?? fallback;
}

export function resolveTerminalSize(source?: TerminalLike | null): {
  columns: number;
  rows: number;
} {
  return {
    columns: resolveTerminalColumns(source),
    rows: resolveTerminalRows(source),
  };
}

export function clampTerminalCardWidth(columns: number, maxWidth = 88, minWidth = 56): number {
  return Math.max(minWidth, Math.min(maxWidth, columns - 4));
}
