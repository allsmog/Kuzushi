/**
 * PromptsEditorView — list every prompt key the focused module exposes,
 * plus the verbs that mutate them. The actual edit/show/diff/reset/set
 * verbs route through the slash-command handlers in `shell.ts`; this
 * component is purely presentational.
 *
 * After-vim card: when `shell.promptsEditor.lastSavedAt` is fresh
 * (within ~5s), the "Saved prompt override" card is rendered above the
 * list so operators see a confirmation block on return from $EDITOR.
 */

import { Box, Text } from "ink";
import type React from "react";
import type { PromptAuditRow } from "../../copilot/prompt-edit.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { Table } from "../primitives/Table.js";
import type { ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { RuleHeader } from "./RuleHeader.js";
import { ScreenContent } from "./ScreenContent.js";

type CompactAuditRow = NonNullable<ShellState["promptsEditor"]>["audit"] extends
  | ReadonlyArray<infer R>
  | undefined
  ? R
  : never;

interface PromptsEditorViewProps {
  shell: ShellState;
  /**
   * Pre-computed audit rows for the focused module, produced by the
   * shell calling `readPromptAudit()`. Pre-computing keeps the
   * component free of `CopilotCore` and easy to snapshot-test.
   *
   * Falls back to `shell.promptsEditor?.audit` when omitted.
   */
  rows?: ReadonlyArray<PromptAuditRow | CompactAuditRow>;
  /** Optional now override for tests. */
  nowMs?: number;
}

const SAVED_TTL_MS = 5_000;

function shortPath(path: string | undefined): string {
  if (!path) return "";
  const home = process.env["HOME"];
  if (home && path.startsWith(home)) return `~${path.slice(home.length)}`;
  return path;
}

type AnyRow = PromptAuditRow | CompactAuditRow;

function sourceLabel(row: AnyRow): string {
  switch (row.effective.source) {
    case "default":
      return "default";
    case "file":
      return "local edit";
    case "inline":
      return "inline";
    case "unset":
      return "missing";
  }
}

export function PromptsEditorView({
  shell,
  rows: rowsProp,
  nowMs,
}: PromptsEditorViewProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "Enter", label: "type verb (edit/show/diff/reset/set)" },
    { keys: "b", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);

  const moduleId = shell.focusedModule ?? "module";
  const breadcrumb = `kuzushi/${moduleId}/prompts`;
  const rows: ReadonlyArray<AnyRow> = rowsProp ?? shell.promptsEditor?.audit ?? [];
  const localEdits = rows.filter((r) => r.effective.source === "file").length;
  const status = `${rows.length} prompt${rows.length === 1 ? "" : "s"} · ${localEdits} local edit${localEdits === 1 ? "" : "s"}`;

  return (
    <ScreenContent>
      <RuleHeader breadcrumb={breadcrumb} status={status} />
      <SavedConfirmation editor={shell.promptsEditor} nowMs={nowMs ?? Date.now()} />
      <Box marginTop={SPACING.sm}>
        <Text>
          {tokens.label("Prompts")}
          {tokens.muted("                  layered: builtin → local → inline")}
        </Text>
      </Box>
      <Box paddingLeft={SPACING.md} marginTop={SPACING.xs}>
        <Table
          showHeader
          divider={false}
          gap={2}
          columns={[
            { key: "name", header: "NAME", flex: 2, truncate: "end" },
            { key: "source", header: "SOURCE", flex: 1, truncate: "end" },
            { key: "where", header: "PATH OR BUILTIN", flex: 5, truncate: "middle" },
          ]}
          rows={rows.map((r) => ({
            name: r.verb,
            source: sourceLabel(r),
            where:
              r.effective.source === "file"
                ? shortPath(r.effective.filePath)
                : r.effective.source === "inline"
                  ? "(inline)"
                  : r.effective.source === "unset"
                    ? `(missing: ${shortPath(r.effective.filePath)})`
                    : "(compiled default)",
          }))}
          emptyMessage="No prompt overrides for this module."
        />
      </Box>
      <ActionsBlock />
    </ScreenContent>
  );
}

function ActionsBlock(): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("actions")}</Text>
      <Box paddingLeft={SPACING.md} marginTop={SPACING.xs} flexDirection="column">
        <Text>
          {tokens.muted("edit <name>     ")}
          {tokens.value("open the override in $EDITOR")}
        </Text>
        <Text>
          {tokens.muted("show <name>     ")}
          {tokens.value("print the effective prompt + source")}
        </Text>
        <Text>
          {tokens.muted("diff <name>     ")}
          {tokens.value("unified diff vs the builtin")}
        </Text>
        <Text>
          {tokens.muted("reset <name>    ")}
          {tokens.value("delete the override file")}
        </Text>
        <Text>
          {tokens.muted("set <name> ...  ")}
          {tokens.value("inline override (text or path)")}
        </Text>
      </Box>
    </Box>
  );
}

function SavedConfirmation({
  editor,
  nowMs,
}: {
  editor: ShellState["promptsEditor"];
  nowMs: number;
}): React.ReactElement | null {
  const last = editor?.lastSaved;
  if (!last || !editor?.lastSavedAt) return null;
  if (nowMs - editor.lastSavedAt > SAVED_TTL_MS) return null;
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("Saved prompt override")}</Text>
      <Box paddingLeft={SPACING.md} marginTop={SPACING.xs} flexDirection="column">
        <Text>
          {tokens.muted("prompt  ")}
          {tokens.value(last.name)}
        </Text>
        <Text>
          {tokens.muted("path    ")}
          {tokens.value(shortPath(last.path))}
        </Text>
        <Text>
          {tokens.muted("size    ")}
          {tokens.value(`${last.size} bytes`)}
        </Text>
        <Text>
          {tokens.muted("active  ")}
          {tokens.success("yes")}
        </Text>
      </Box>
    </Box>
  );
}
