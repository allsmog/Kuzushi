/**
 * KbView — the focused module's knowledge base (`/kb` and bare
 * `attachments`). Two panes stacked vertically: a list of attachments at
 * top with a row cursor, and a preview pane at the bottom showing the
 * selected document's source / status / parse warnings / first lines of
 * extracted text.
 *
 * Reads from `shell.kbState[shell.kb.moduleId]` (populated by
 * `handleKbCommand` on view entry and by the shared attach/detach/reparse
 * tools on every mutation). Stays presentational — no I/O, no LLM dispatch.
 */

import { Box, Text } from "ink";
import type React from "react";
import type {
  AttachmentHomeRow,
  AttachmentsHomeSlice,
} from "../../modules/_shared/attachments/index.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import type { ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { RuleHeader } from "./RuleHeader.js";
import { ScreenContent } from "./ScreenContent.js";

const PREVIEW_LINES = 12;

interface KbViewProps {
  shell: ShellState;
}

export function KbView({ shell }: KbViewProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "j/k", label: "move" },
    { keys: "d", label: "detach", secondary: true },
    { keys: "r", label: "reparse", secondary: true },
    { keys: "attach <path>", label: "attach", secondary: true },
    { keys: "b", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);

  const moduleId = shell.kb?.moduleId ?? shell.focusedModule ?? "kb";
  const slice = shell.kbState?.[moduleId] ?? null;
  const docs = slice?.documents ?? [];
  // Clamp the cursor to a valid row index here so the list pane and the
  // preview pane stay in sync when state.kb.cursor is stale (e.g. after a
  // detach removes the selected row).
  const cursor =
    docs.length === 0 ? 0 : Math.min(Math.max(0, shell.kb?.cursor ?? 0), docs.length - 1);
  const selected = docs.length > 0 ? (docs[cursor] ?? null) : null;

  return (
    <ScreenContent>
      <RuleHeader breadcrumb={`kuzushi/${moduleId} · kb`} status={summary(slice)} />
      {docs.length === 0 ? (
        <EmptyState moduleId={moduleId} />
      ) : (
        <>
          <ListPane docs={docs} cursor={cursor} />
          {selected ? <PreviewPane row={selected} /> : null}
        </>
      )}
    </ScreenContent>
  );
}

function summary(slice: AttachmentsHomeSlice | null): string {
  if (!slice || slice.totals.total === 0) return "no attachments";
  const total = `${slice.totals.total} attachment${slice.totals.total === 1 ? "" : "s"}`;
  const sub: string[] = [];
  if (slice.totals.parsed) sub.push(`${slice.totals.parsed} parsed`);
  if (slice.totals.needsReview) sub.push(`${slice.totals.needsReview} review`);
  if (slice.totals.error) sub.push(`${slice.totals.error} error`);
  return sub.length > 0 ? `${total} · ${sub.join(" · ")}` : total;
}

function EmptyState({ moduleId }: { moduleId: string }): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.md} paddingLeft={SPACING.md}>
      <Text>{tokens.muted("(no attachments yet)")}</Text>
      <Box marginTop={SPACING.sm} flexDirection="column">
        <Text>
          {tokens.label("how to attach")}
          {"  "}
          {tokens.muted(`stage reference material for ${moduleId}`)}
        </Text>
        <Box paddingLeft={SPACING.md} marginTop={SPACING.xs} flexDirection="column">
          <Text>{tokens.value("attach ./docs/architecture.md")}</Text>
          <Text>{tokens.value("attach https://example.com/runbook")}</Text>
          <Text>{tokens.value("attach ./reports/soc2.pdf kind=audit-report")}</Text>
        </Box>
      </Box>
    </Box>
  );
}

function ListPane({
  docs,
  cursor,
}: {
  docs: ReadonlyArray<AttachmentHomeRow>;
  cursor: number;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Box paddingLeft={SPACING.md} flexDirection="column">
        <Text>
          {tokens.hint(`(${cursor + 1} of ${docs.length})`)}
          {cursor > 0 ? tokens.hint(" ▲") : ""}
          {cursor < docs.length - 1 ? tokens.hint(" ▼") : ""}
        </Text>
        <Text>
          {tokens.muted(
            `${pad("#", 3)} ${pad("STATUS", 7)} ${pad("TITLE", 36)} ${pad("KIND", 18)} ${pad("SIZE", 10)} AGE`,
          )}
        </Text>
        {docs.map((doc, idx) => {
          const isSelected = idx === cursor;
          const indicator = isSelected ? "▶" : " ";
          const num = `${pad(String(idx + 1), 2)} `;
          const status = pad(statusGlyph(doc.status), 7);
          const title = pad(doc.title, 36);
          const kind = pad(doc.kindLabel, 18);
          const size = pad(formatSize(doc), 10);
          const age = doc.detail.split("·").slice(-1)[0]?.trim() ?? "";
          const line = `${indicator} ${num}${status} ${title} ${kind} ${size} ${age}`;
          return <Text key={doc.id}>{isSelected ? tokens.strong(line) : tokens.value(line)}</Text>;
        })}
      </Box>
    </Box>
  );
}

function PreviewPane({ row }: { row: AttachmentHomeRow }): React.ReactElement {
  const previewLines = previewBody(row);
  return (
    <Box flexDirection="column" marginTop={SPACING.md}>
      <Text>{tokens.muted("─".repeat(78))}</Text>
      <Text>
        {tokens.label("preview")}
        {" · "}
        {tokens.value(row.title)}
      </Text>
      <Box paddingLeft={SPACING.md} marginTop={SPACING.xs} flexDirection="column">
        <Text>
          {tokens.muted("source   ")}
          {tokens.value(row.source)}
        </Text>
        <Text>
          {tokens.muted("kind     ")}
          {tokens.value(row.kindLabel)}
          {tokens.muted("    status   ")}
          {tokens.value(row.status)}
        </Text>
        {row.charCount !== undefined ? (
          <Text>
            {tokens.muted("parsed   ")}
            {tokens.value(`${row.charCount} chars`)}
            {row.sizeBytes !== undefined
              ? tokens.muted(`    size     ${formatBytes(row.sizeBytes)}`)
              : ""}
          </Text>
        ) : row.sizeBytes !== undefined ? (
          <Text>
            {tokens.muted("size     ")}
            {tokens.value(formatBytes(row.sizeBytes))}
          </Text>
        ) : null}
        {row.parseWarnings.length > 0 ? (
          <Box flexDirection="column" marginTop={SPACING.xs}>
            <Text>{tokens.muted("warnings")}</Text>
            {row.parseWarnings.map((warning) => (
              <Text key={warning}>
                {tokens.muted("  · ")}
                {tokens.value(warning)}
              </Text>
            ))}
          </Box>
        ) : null}
        {previewLines.length > 0 ? (
          <Box flexDirection="column" marginTop={SPACING.sm}>
            <Text>{tokens.muted(`extracted (first ${PREVIEW_LINES} lines)`)}</Text>
            {previewLines.map((line, i) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: preview lines are render-order-only and may be empty/duplicate
              <Text key={`pl-${i}`}>
                {tokens.muted("  ")}
                {tokens.value(line || " ")}
              </Text>
            ))}
          </Box>
        ) : (
          <Box marginTop={SPACING.sm}>
            <Text>{tokens.muted("[no extractable text — open externally to inspect]")}</Text>
          </Box>
        )}
      </Box>
    </Box>
  );
}

function previewBody(row: AttachmentHomeRow): string[] {
  if (row.charCount === undefined) return [];
  // The slice doesn't carry the full extracted text (it would bloat the
  // shell state); the preview pane shows metadata only. Future work: fetch
  // the first N chars from the source file on demand.
  return [];
}

function statusGlyph(status: AttachmentHomeRow["status"]): string {
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

function formatSize(row: AttachmentHomeRow): string {
  if (row.charCount !== undefined) {
    if (row.charCount < 1000) return `${row.charCount}c`;
    if (row.charCount < 1_000_000) return `${(row.charCount / 1000).toFixed(1)}kc`;
    return `${(row.charCount / 1_000_000).toFixed(1)}Mc`;
  }
  if (row.sizeBytes !== undefined) return formatBytes(row.sizeBytes);
  return "—";
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

function pad(value: string, width: number): string {
  if (value.length >= width) return `${value.slice(0, width - 1)}…`;
  return value.padEnd(width);
}
