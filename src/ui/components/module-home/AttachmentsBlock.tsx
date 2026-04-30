/**
 * AttachmentsBlock — reusable home-view section that renders a module's
 * knowledge-base attachments in the same shape across modules. Reads from
 * the slice produced by `src/modules/_shared/attachments/tools.ts:
 * buildHomeSlice`.
 */

import { Box, Text, useStdout } from "ink";
import type React from "react";
import type { AttachmentsHomeSlice } from "../../../modules/_shared/attachments/index.js";
import { truncateEnd, visibleWidth } from "../../format.js";
import { Table } from "../../primitives/Table.js";
import { SPACING, tokens } from "../../tokens.js";

interface AttachmentsBlockProps {
  /** Per-module slice; falsy/empty means render the empty state. */
  slice: AttachmentsHomeSlice | null | undefined;
  /** Owning module id — used for the empty-state hint and the actions block. */
  moduleId: string;
  /** When true, render the actions row beneath the table. Default: true. */
  showActions?: boolean;
}

export function AttachmentsBlock({
  slice,
  moduleId,
  showActions = true,
}: AttachmentsBlockProps): React.ReactElement {
  const { stdout } = useStdout();
  const titleWidth = Math.max(20, (stdout?.columns ?? 100) - SPACING.md * 4);
  const docs = slice?.documents ?? [];
  const title = `${tokens.label("attachments")}  ${tokens.hint(formatTotals(slice))}`;
  const titleLine =
    docs.length === 0
      ? `${title}  ${tokens.muted("(none attached) — attach <path-or-url>")}`
      : title;
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{padSectionLine(titleLine, titleWidth)}</Text>
      {docs.length > 0 ? (
        <Box paddingLeft={SPACING.md} marginTop={SPACING.xs} flexDirection="column">
          <Table
            showHeader={false}
            divider={false}
            gap={2}
            columns={[
              { key: "status", flex: 1, truncate: "end" },
              { key: "title", flex: 4, truncate: "middle" },
              { key: "kind", flex: 2, truncate: "end" },
              { key: "detail", flex: 3, truncate: "end" },
            ]}
            rows={docs.map((doc) => ({
              status: statusGlyph(doc.status),
              title: doc.title,
              kind: doc.kindLabel,
              detail: doc.detail,
            }))}
          />
        </Box>
      ) : null}
      {showActions ? (
        <Box flexDirection="column" marginTop={SPACING.xs} paddingLeft={SPACING.md}>
          <Text>
            {padSectionLine(
              tokens.muted(
                "actions: attach <path-or-url>  /kb (browse)  detach <id>  reparse <id>",
              ),
              titleWidth,
            )}
          </Text>
          {slice?.scopePath ? (
            <Text>
              {padSectionLine(tokens.muted(`scope: ${shortPath(slice.scopePath)}`), titleWidth)}
            </Text>
          ) : null}
        </Box>
      ) : null}
      {/* Placeholder for module-specific hooks (missing-artifact hints, etc.) */}
      {/* The moduleId is reserved here so consumers can pin the slice key in tests. */}
      <Box display={moduleId ? "none" : "flex"} />
    </Box>
  );
}

function padSectionLine(text: string, width: number): string {
  const clipped = truncateEnd(text, width);
  return clipped + " ".repeat(Math.max(0, width - visibleWidth(clipped)));
}

function formatTotals(slice: AttachmentsHomeSlice | null | undefined): string {
  if (!slice || slice.totals.total === 0) return "0 attached";
  const parts: string[] = [];
  parts.push(`${slice.totals.total} attached`);
  const sub: string[] = [];
  if (slice.totals.parsed) sub.push(`${slice.totals.parsed} parsed`);
  if (slice.totals.needsReview) sub.push(`${slice.totals.needsReview} review`);
  if (slice.totals.metadata) sub.push(`${slice.totals.metadata} metadata`);
  if (slice.totals.error) sub.push(`${slice.totals.error} error`);
  if (sub.length > 0) parts.push(`(${sub.join(" · ")})`);
  return parts.join(" ");
}

function statusGlyph(status: AttachmentsHomeSlice["documents"][number]["status"]): string {
  switch (status) {
    case "parsed":
      return "[x]";
    case "needs-human-review":
      return "[ ]";
    case "metadata-only":
      return "[~]";
    case "error":
      return "[!]";
    default:
      return "[?]";
  }
}

function shortPath(absolute: string): string {
  const home = process.env["HOME"] ?? "";
  if (home && absolute.startsWith(home)) return `~${absolute.slice(home.length)}`;
  return absolute;
}
