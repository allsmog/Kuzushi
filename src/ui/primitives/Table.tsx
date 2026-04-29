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
import { type Align, truncateEnd, truncateMiddle, visibleWidth } from "../format.js";
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
}

function alignToJustify(align: TableAlign | undefined): "flex-start" | "center" | "flex-end" {
  if (align === "right") return "flex-end";
  if (align === "center") return "center";
  return "flex-start";
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
  const { columns, rows, showHeader, divider = true, maxWidth, gap = 2, emptyMessage } = props;
  const { stdout } = useStdout();
  const totalWidth = maxWidth ?? resolveTerminalColumns(stdout);
  const widths = computeWidths(columns, totalWidth, gap);
  const headerVisible = showHeader ?? columns.some((c) => typeof c.header === "string");

  if (rows.length === 0 && emptyMessage) {
    return (
      <Box>
        <Text>{tokens.muted(emptyMessage)}</Text>
      </Box>
    );
  }

  const renderCellText = (raw: string, col: TableColumn<Row>, width: number) => {
    const trunc = col.truncate ?? "end";
    let cell = raw;
    if (visibleWidth(cell) > width) {
      if (trunc === "middle") cell = truncateMiddle(cell, width);
      else if (trunc === "end") cell = truncateEnd(cell, width);
    }
    return cell;
  };

  const renderRow = (cells: ReadonlyArray<ReactNode | string>, key?: string) => (
    <Box key={key} flexDirection="row">
      {columns.map((col, i) => {
        const width = widths[i] ?? 0;
        const raw = cells[i];
        const content =
          typeof raw === "string" ? renderCellText(raw, col, width) : raw == null ? "" : raw;
        return (
          <Box
            key={col.key}
            width={width}
            marginRight={i < columns.length - 1 ? gap : 0}
            justifyContent={alignToJustify(col.align)}
            flexShrink={0}
          >
            <Text wrap="truncate-end">{content}</Text>
          </Box>
        );
      })}
    </Box>
  );

  return (
    <Box flexDirection="column">
      {headerVisible
        ? renderRow(
            columns.map((col) => tokens.metadata(col.header ?? col.key)),
            "header",
          )
        : null}
      {headerVisible && divider ? (
        <Box flexDirection="row">
          {columns.map((col, i) => {
            const width = widths[i] ?? 0;
            return (
              <Box
                key={`${col.key}:divider`}
                width={width}
                marginRight={i < columns.length - 1 ? gap : 0}
                flexShrink={0}
              >
                <Text>{tokens.subtle(icons.boxHorizontal.repeat(width))}</Text>
              </Box>
            );
          })}
        </Box>
      ) : null}
      {rows.map((row, rowIdx) =>
        renderRow(
          columns.map<ReactNode>((col) => {
            const rendered = col.render
              ? col.render(row)
              : (row as Record<string, unknown>)[col.key];
            if (typeof rendered === "string") return rendered;
            if (rendered == null) return "";
            if (
              typeof rendered === "number" ||
              typeof rendered === "bigint" ||
              typeof rendered === "boolean"
            ) {
              return String(rendered);
            }
            return rendered as ReactNode;
          }),
          `row-${rowIdx}`,
        ),
      )}
    </Box>
  );
}
