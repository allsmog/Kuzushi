/**
 * Context module home — Status / Actions / Last run.
 *
 * Restrained "two-column key/value" layout described in the v3 mocks.
 * Reads from `shell.contextSnapshot` plus the catalog's last-run summary
 * for the focused module.
 */

import { Box, Text } from "ink";
import type React from "react";
import { useRegisterKeybindings } from "../../hooks/useKeybindings.js";
import { Table } from "../../primitives/Table.js";
import type { ContextSnapshot } from "../../state.js";
import { SPACING, tokens } from "../../tokens.js";
import { RuleHeader } from "../RuleHeader.js";
import { ScreenContent } from "../ScreenContent.js";
import { AttachmentsBlock } from "./AttachmentsBlock.js";
import type { ModuleHomeProps } from "./types.js";

const MODULE_ID = "context";

interface Row {
  key: string;
  value: string;
}

function formatAge(ms: number, now: number = Date.now()): string {
  const delta = Math.max(0, now - ms);
  if (delta < 60_000) return "just now";
  const minutes = Math.floor(delta / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function statusRowsForContext(snapshot: ContextSnapshot | null | undefined): Row[] {
  if (!snapshot) {
    return [
      { key: "snapshot", value: "(none yet) — run /context build" },
      { key: "generated", value: "—" },
      { key: "stale", value: "—" },
    ];
  }
  const generated = snapshot.generatedSlices?.length ?? 0;
  const stale = snapshot.staleSlices?.length ?? 0;
  const generatedLabel =
    generated > 0
      ? `${generated} slice${generated === 1 ? "" : "s"}: ${(snapshot.generatedSlices ?? []).join(", ")}`
      : "—";
  const staleLabel =
    stale > 0
      ? `${stale} slice${stale === 1 ? "" : "s"}: ${(snapshot.staleSlices ?? []).join(", ")}`
      : "(none)";
  return [
    {
      key: "snapshot",
      value: `${formatAge(snapshot.timestamp)} · target ${snapshot.target}`,
    },
    { key: "generated", value: generatedLabel },
    { key: "stale", value: staleLabel },
  ];
}

function StatusBlock({ shell }: ModuleHomeProps): React.ReactElement {
  const snapshot = shell.contextSnapshot ?? null;
  const repo = shell.workspace ?? shell.target ?? "(no target set)";
  const promptCount = shell.moduleOptions?.[`${MODULE_ID}:build`]
    ? Object.keys(shell.moduleOptions[`${MODULE_ID}:build`] ?? {}).filter((k) =>
        k.endsWith("_PROMPT"),
      ).length
    : 0;
  const rows: Row[] = [
    { key: "repo", value: repo },
    ...statusRowsForContext(snapshot),
    { key: "prompts", value: promptCount > 0 ? `${promptCount} local edit(s)` : "(default)" },
  ];
  return <KeyValueSection title="status" rows={rows} />;
}

function ActionsBlock({ shell }: ModuleHomeProps): React.ReactElement {
  // The action labels mirror the verbs the slash router accepts. Operators
  // type the verb at the prompt; this block just lists what's available.
  const rows: Row[] = [
    { key: "run .", value: "build full context for the current target" },
    { key: "regen <slice>", value: "regenerate one of: repo · enrichment · app-model" },
    { key: "prompts", value: "edit per-tool system prompts" },
    { key: "/use threat-model", value: "open dedicated threat-model workflows" },
  ];
  if (shell.contextSnapshot?.staleSlices?.length) {
    rows.unshift({
      key: "regen stale",
      value: `${shell.contextSnapshot.staleSlices.length} stale slice(s)`,
    });
  }
  return <KeyValueSection title="actions" rows={rows} />;
}

function LastRunBlock({ shell }: ModuleHomeProps): React.ReactElement {
  const card = shell.moduleCatalog?.find((c) => c.id === MODULE_ID);
  const summary = card?.lastRunSummary;
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("last run")}</Text>
      <Box paddingLeft={SPACING.md} marginTop={SPACING.xs}>
        <Text>
          {summary ? tokens.value(summary) : tokens.muted("never run for this workspace")}
        </Text>
      </Box>
    </Box>
  );
}

export function ContextHome({ shell }: ModuleHomeProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "Enter", label: "type tool verb" },
    { keys: "a", label: "attachments", secondary: true },
    { keys: "t", label: "tune", secondary: true },
    { keys: "f", label: "findings", secondary: true },
    { keys: "b", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);
  const slice = shell.kbState?.[MODULE_ID] ?? null;
  return (
    <ScreenContent>
      <RuleHeader breadcrumb={`kuzushi/${MODULE_ID}`} />
      <StatusBlock shell={shell} />
      <AttachmentsBlock slice={slice} moduleId={MODULE_ID} />
      <ActionsBlock shell={shell} />
      <LastRunBlock shell={shell} />
    </ScreenContent>
  );
}

export function KeyValueSection({
  title,
  rows,
}: {
  title: string;
  rows: ReadonlyArray<Row>;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label(title)}</Text>
      <Box paddingLeft={SPACING.md} marginTop={SPACING.xs}>
        <Table
          showHeader={false}
          divider={false}
          gap={2}
          columns={[
            { key: "key", flex: 2, truncate: "end" },
            { key: "value", flex: 5, truncate: "end" },
          ]}
          rows={rows}
        />
      </Box>
    </Box>
  );
}
