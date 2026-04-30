/**
 * Table — aligned column grid for dense tabular data.
 *
 * Replaces unaligned `Box+Text` rows in ConfigBanner, ScanSummary,
 * MonorepoProgress, ResultLine, and finding field blocks. Supports fixed or
 * flex-proportional columns, right/center alignment, and middle or end
 * truncation (middle preserves the trailing path basename).
 */
import { Box, Text, useStdout } from "ink";
import type { ReactNode } from "react";
import { type Align, padCell, truncateEnd, truncateMiddle, visibleWidth } from "../format.js";
import { icons } from "../icons.js";
import { resolveTerminalColumns } from "../terminal.js";
import { tokens } from "../tokens.js";

export type TableAlign = Align;
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
  /** Optional cursor row. When set, every row reserves a cursor gutter. */
  selectedIndex?: number;
  /** Defaults to the app selection glyph. */
  selectionGlyph?: string;
}

function computeWidths<Row>(
  columns: ReadonlyArray<TableColumn<Row>>,
  totalWidth: number,
  gap: number,
): number[] {
  const gaps = gap * Math.max(0, columns.length - 1);
  const fixedSum = columns.reduce((acc, c) => acc + (c.width ?? 0), 0);
  const flexTotal = columns.reduce((acc, c) => acc + (c.flex ?? 0), 0);
  const remaining = Math.max(0, totalWidth - fixedSum - gaps);
  return columns.map((col) => {
    if (typeof col.width === "number") return col.width;
    if (flexTotal <= 0) return 0;
    const share = Math.max(0, Math.floor(((col.flex ?? 0) / flexTotal) * remaining));
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
    selectedIndex,
    selectionGlyph = "❯",
  } = props;
  const { stdout } = useStdout();
  const terminalWidth = resolveTerminalColumns(stdout);
  const totalWidth = Math.max(1, Math.min(maxWidth ?? terminalWidth, terminalWidth));
  const widths = computeWidths(columns, totalWidth, gap);
  const headerVisible = showHeader ?? columns.some((c) => typeof c.header === "string");

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
    if (visibleWidth(cell) > width) {
      if (trunc === "middle") cell = truncateMiddle(cell, width);
      else if (trunc === "end") cell = truncateEnd(cell, width);
    }
    return padCell(cell, width, col.align ?? "left");
  };

  const gapStr = " ".repeat(gap);
  const dividerWidth = widths.reduce((a, b) => a + b, 0) + gap * Math.max(0, columns.length - 1);
  const hasSelection = typeof selectedIndex === "number";
  const rowPrefix = (rowIdx: number): string => {
    if (!hasSelection) return "";
    return rowIdx === selectedIndex
      ? `${tokens.focus(selectionGlyph)} `
      : " ".repeat(selectionGlyph.length + 1);
  };
  const headerPrefix = hasSelection ? " ".repeat(selectionGlyph.length + 1) : "";

  function renderRow(row: Row, rowIdx: number): string {
    const cells = columns
      .map((col, i) => {
        const width = widths[i] ?? 0;
        const rendered = col.render ? col.render(row) : (row as Record<string, unknown>)[col.key];
        if (typeof rendered === "string") return renderCell(rendered, col, width);
        if (rendered == null) return padCell("", width, col.align ?? "left");
        return renderCell(String(rendered), col, width);
      })
      .join(gapStr);
    const line = `${rowPrefix(rowIdx)}${cells}`;
    return rowIdx === selectedIndex ? tokens.selection(line) : line;
  }

  return (
    <Box flexDirection="column">
      {headerVisible ? (
        <Box>
          <Text>
            {headerPrefix}
            {columns
              .map((col, i) =>
                renderCell(tokens.metadata(col.header ?? col.key), col, widths[i] ?? 0),
              )
              .join(gapStr)}
          </Text>
        </Box>
      ) : null}
      {headerVisible && divider ? (
        <Box>
          <Text>
            {hasSelection ? " ".repeat(selectionGlyph.length + 1) : ""}
            {tokens.subtle(icons.boxHorizontal.repeat(dividerWidth))}
          </Text>
        </Box>
      ) : null}
      {rows.map((row, rowIdx) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: Table rows are opaque data; no stable id field. Re-renders replace the full set so keys never collide mid-list.
        <Box key={`row-${rowIdx}`}>
          <Text>{renderRow(row, rowIdx)}</Text>
        </Box>
      ))}
    </Box>
  );
}
