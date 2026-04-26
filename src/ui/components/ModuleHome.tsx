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
  const customRenderer = getModuleHomeRenderer(shell.focusedModule ?? null);
  const useCustom = customRenderer != null && shell.processing !== true;
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 120;
  const tableMaxWidth = Math.max(44, Math.min(96, columns - SPACING.md * 3));
  const narrow = columns < 96;

  useRegisterKeybindings([
    { keys: "Enter", label: "type tool verb" },
    { keys: "t", label: "tune", secondary: true },
    { keys: "f", label: "findings", secondary: true },
    { keys: "b", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);
  if (useCustom) return customRenderer!.render({ shell });
  const moduleId = shell.focusedModule;
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
          <Section
            label="tools"
            hint={
              narrow ? undefined : "(invoke from this shell as verb, or headless via kuzushi run)"
            }
          >
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

          <Section label="last run">
            <Text>
              {"   "}
              {card?.lastRunSummary
                ? tokens.value(card.lastRunSummary)
                : tokens.muted("never run for this workspace")}
            </Text>
          </Section>
        </>
      )}
    </ScreenContent>
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
