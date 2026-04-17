/**
 * Table — aligned column grid for dense tabular data.
 *
 * Replaces unaligned `Box+Text` rows in ConfigBanner, ScanSummary,
 * MonorepoProgress, ResultLine, and finding field blocks. Supports fixed or
 * flex-proportional columns, right/center alignment, and middle or end
 * truncation (middle preserves the trailing path basename).
 */
import { Box, Text } from "ink";
import type { ReactNode } from "react";
import { icons } from "../icons.js";
import { tokens } from "../tokens.js";

export type TableAlign = "left" | "right" | "center";
export type TableTruncate = "end" | "middle" | "none";

export interface TableColumn<Row> {
  key: string;
  header?: string;
  width?: number;
  flex?: number;
  align?: TableAlign;
  truncate?: TableTruncate;
  render?: (row: Row) => ReactNode | string;
}

export interface TableProps<Row> {
  columns: ReadonlyArray<TableColumn<Row>>;
  rows: ReadonlyArray<Row>;
  showHeader?: boolean;
  divider?: boolean;
  maxWidth?: number;
  gap?: number;
  emptyMessage?: string;
}

const ANSI_RE = /[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g;

function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, "");
}

function visibleLen(s: string): number {
  return stripAnsi(s).length;
}

function truncateEnd(s: string, width: number, ellipsis = "\u2026"): string {
  if (visibleLen(s) <= width) return s;
  if (width <= ellipsis.length) return ellipsis.slice(0, width);
  const plain = stripAnsi(s);
  return plain.slice(0, width - ellipsis.length) + ellipsis;
}

function truncateMiddle(s: string, width: number, ellipsis = "\u2026"): string {
  const plain = stripAnsi(s);
  if (plain.length <= width) return s;
  const slash = plain.lastIndexOf("/");
  if (slash >= 0 && plain.length - slash <= width - ellipsis.length - 1) {
    const basename = plain.slice(slash);
    const prefixBudget = width - ellipsis.length - basename.length;
    if (prefixBudget > 0) {
      return plain.slice(0, prefixBudget) + ellipsis + basename;
    }
    return ellipsis + basename.slice(-(width - ellipsis.length));
  }
  if (width <= ellipsis.length) return ellipsis.slice(0, width);
  const head = Math.ceil((width - ellipsis.length) / 2);
  const tail = width - ellipsis.length - head;
  return plain.slice(0, head) + ellipsis + plain.slice(plain.length - tail);
}

function padCell(s: string, width: number, align: TableAlign): string {
  const vw = visibleLen(s);
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

function computeWidths<Row>(
  columns: ReadonlyArray<TableColumn<Row>>,
  totalWidth: number,
  gap: number,
): number[] {
  const gaps = gap * Math.max(0, columns.length - 1);
  const fixedSum = columns.reduce((acc, c) => acc + (c.width ?? 0), 0);
  const flexTotal = columns.reduce((acc, c) => acc + (c.flex ?? 0), 0);
  let remaining = Math.max(0, totalWidth - fixedSum - gaps);
  return columns.map((col) => {
    if (typeof col.width === "number") return col.width;
    if (flexTotal <= 0) return 0;
    const share = Math.max(
      0,
      Math.floor(((col.flex ?? 0) / flexTotal) * remaining),
    );
    return share;
  });
}

export function Table<Row>(props: TableProps<Row>): JSX.Element {
  const {
    columns,
    rows,
    showHeader,
    divider = true,
    maxWidth,
    gap = 2,
    emptyMessage,
  } = props;

  const totalWidth = maxWidth ?? process.stdout.columns ?? 80;
  const widths = computeWidths(columns, totalWidth, gap);
  const headerVisible =
    showHeader ?? columns.some((c) => typeof c.header === "string");

  if (rows.length === 0 && emptyMessage) {
    return (
      <Box>
        <Text>{tokens.muted(emptyMessage)}</Text>
      </Box>
    );
  }

  const renderCell = (raw: string, col: TableColumn<Row>, width: number) => {
    const trunc = col.truncate ?? "end";
    let cell = raw;
    if (visibleLen(cell) > width) {
      if (trunc === "middle") cell = truncateMiddle(cell, width);
      else if (trunc === "end") cell = truncateEnd(cell, width);
    }
    return padCell(cell, width, col.align ?? "left");
  };

  const gapStr = " ".repeat(gap);
  const dividerWidth = widths.reduce((a, b) => a + b, 0) + gap * Math.max(0, columns.length - 1);

  return (
    <Box flexDirection="column">
      {headerVisible ? (
        <Box>
          <Text>
            {columns
              .map((col, i) =>
                renderCell(tokens.label(col.header ?? col.key), col, widths[i] ?? 0),
              )
              .join(gapStr)}
          </Text>
        </Box>
      ) : null}
      {headerVisible && divider ? (
        <Box>
          <Text>{tokens.muted(icons.boxHorizontal.repeat(dividerWidth))}</Text>
        </Box>
      ) : null}
      {rows.map((row, rowIdx) => (
        <Box key={`row-${rowIdx}`}>
          <Text>
            {columns
              .map((col, i) => {
                const width = widths[i] ?? 0;
                const rendered = col.render
                  ? col.render(row)
                  : (row as Record<string, unknown>)[col.key];
                if (typeof rendered === "string") {
                  return renderCell(rendered, col, width);
                }
                if (rendered == null) return padCell("", width, col.align ?? "left");
                return renderCell(String(rendered), col, width);
              })
              .join(gapStr)}
          </Text>
        </Box>
      ))}
    </Box>
  );
}
