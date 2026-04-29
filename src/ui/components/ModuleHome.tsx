/**
 * ModuleHome — the per-module landing page (D2, Ink UI v2 screen 02).
 *
 * Renders when `shell.focusedModule` is set and `shell.shellView === "module"`.
 * Four-band layout: header breadcrumb, tools table, last-run card, and a hint
 * footer. Everything is keyboard-driven through the existing shell prompt
 * (`scan`, `tune`, `findings`, `back`, etc.) — this component is purely
 * presentational.
 */

import { Box, Text, useStdout } from "ink";
import type React from "react";
import {
  buildSastTaskSelectionSummary,
  formatSastTaskStateLine,
  readDisabledSastTasks,
  SAST_SCAN_TOOL_NAME,
} from "../../copilot/sast-task-selection.js";
import { truncateEnd } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { Table } from "../primitives/Table.js";
import type { ShellModuleToolSummary, ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { ContextStrip } from "./ContextStrip.js";
import { EmptyState } from "./EmptyState.js";
import { getModuleHomeRenderer } from "./module-home/registry.js";
import { ScreenContent } from "./ScreenContent.js";

interface ModuleHomeProps {
  shell: ShellState;
}

export function ModuleHome({ shell }: ModuleHomeProps): React.ReactElement {
  // Modules can opt into the v3 "Status / Actions / Last run" home by
  // registering a renderer in `module-home/registry.ts`. The lookup is
  // resolved up-front so the legacy keybind registration below stays at
  // the top of the function (rules-of-hooks: same hooks, every render).
  const CustomHome = getModuleHomeRenderer(shell.focusedModule ?? null)?.render;
  const useCustom = CustomHome != null && shell.processing !== true;
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 120;
  const tableMaxWidth = Math.max(44, Math.min(96, columns - SPACING.md * 3));
  const narrow = columns < 96;
  const moduleId = shell.focusedModule;
  const isSastModule = moduleId === "sast";

  useRegisterKeybindings([
    { keys: "Enter", label: "type tool verb" },
    ...(isSastModule ? [{ keys: "tasks", label: "select tasks", secondary: true }] : []),
    { keys: "t", label: "tune", secondary: true },
    { keys: "f", label: "findings", secondary: true },
    { keys: "b", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);
  if (useCustom && CustomHome) return <CustomHome shell={shell} />;
  if (!moduleId) {
    return (
      <Box paddingLeft={2}>
        <EmptyState kind="module-none-focused" />
      </Box>
    );
  }

  const card = shell.moduleCatalog?.find((c) => c.id === moduleId);
  const allTools: ReadonlyArray<ShellModuleToolSummary> = card?.toolSummaries ?? [];
  const visibleTools = allTools.filter((t) => !t.hidden);
  const hiddenCount = allTools.length - visibleTools.length;
  const tableRows = visibleTools.map((tool) => ({
    ...tool,
    name:
      narrow && tool.name.startsWith(`${moduleId}:`)
        ? tool.name.slice(moduleId.length + 1)
        : tool.name,
    description: narrow ? truncateEnd(tool.description, 44) : tool.description,
  }));
  // While a tool is actively running, the tools table + last-run card are
  // clutter — the operator has already picked a verb. Collapse to just the
  // header strip so the progress bar dominates the viewport.
  const busy = shell.processing === true;

  return (
    <ScreenContent>
      <ContextStrip
        status={
          card ? [card.category, `${visibleTools.length} tools`] : [`${visibleTools.length} tools`]
        }
        subtitle={card?.description}
      />

      {busy ? null : (
        <>
          <Section label="tools">
            {visibleTools.length === 0 ? (
              <Box paddingLeft={3}>
                <EmptyState kind="module-no-tools" context={{ moduleId }} />
              </Box>
            ) : (
              <>
                <Table
                  showHeader
                  gap={1}
                  maxWidth={tableMaxWidth}
                  columns={[
                    { key: "verb", header: "VERB", flex: 2, truncate: "end" },
                    {
                      key: "name",
                      header: narrow ? "NAME" : "TOOL NAME",
                      flex: 3,
                      truncate: "middle",
                    },
                    {
                      key: "description",
                      header: narrow ? "DESC" : "DESCRIPTION",
                      flex: 5,
                      truncate: "end",
                    },
                  ]}
                  divider={false}
                  rows={tableRows}
                />
                {hiddenCount > 0 ? (
                  <Box paddingLeft={3} marginTop={SPACING.sm}>
                    <Text>
                      {tokens.muted(
                        `+ ${hiddenCount} advanced pipeline step${hiddenCount === 1 ? "" : "s"} — run \`/tools --all\` to list`,
                      )}
                    </Text>
                  </Box>
                ) : null}
              </>
            )}
          </Section>

          {isSastModule ? <SastTaskSelectionSummary shell={shell} /> : null}

          <Section label="last run">
            <Box flexDirection="column" paddingLeft={3}>
              <Text>
                {card?.lastRunSummary
                  ? tokens.value(card.lastRunSummary)
                  : tokens.muted("never run for this workspace")}
              </Text>
              {card?.runState ? (
                <Text>{tokens.muted(`actions: ${card.runState.actions.join(" · ")}`)}</Text>
              ) : null}
            </Box>
          </Section>
        </>
      )}
    </ScreenContent>
  );
}

function SastTaskSelectionSummary({ shell }: { shell: ShellState }): React.ReactElement {
  const options = shell.moduleOptions[SAST_SCAN_TOOL_NAME] ?? {};
  const summary = buildSastTaskSelectionSummary({ options, tune: shell.tuneSnapshot });
  const disabled = readDisabledSastTasks(options);
  const blockedLabel = disabled.length > 0 ? disabled.join(", ") : "none";

  return (
    <Section label="task selection">
      <Box flexDirection="column" paddingLeft={3}>
        <Text>{tokens.value(formatSastTaskStateLine(summary))}</Text>
        <Text>
          {tokens.muted("blocked: ")}
          {blockedLabel === "none" ? tokens.muted(blockedLabel) : tokens.value(blockedLabel)}
        </Text>
        <Text>{tokens.muted("commands: tasks · show options · scan .")}</Text>
      </Box>
    </Section>
  );
}

function Section({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>
        {tokens.label(label)}
        {hint ? tokens.muted(`   ${hint}`) : ""}
      </Text>
      <Box flexDirection="column" marginTop={SPACING.sm}>
        {children}
      </Box>
    </Box>
  );
}
