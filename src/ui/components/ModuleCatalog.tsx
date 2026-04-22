/**
 * ModuleCatalog — shell home screen (D1, Ink UI v2 screen 01).
 *
 * Renders when the shell is at the top level (shellView === "catalog" and
 * no focused module). Groups the loaded modules by the real README
 * categories — offense · intel · governance · defense — plus an optional
 * EXTERNAL section for `pkg:*` modules. The roadmap footer lists
 * not-yet-shipped modules as italic muted text so operators see the future
 * shape without it crowding today's work.
 *
 * Each row shows: `id · one-liner · last-run summary`. Selection is purely
 * visual — the user types `/use <id>` in the shell prompt below the catalog
 * to focus a module, just like today's command flow.
 */

import { Box, Text, useStdout } from "ink";
import type React from "react";
import { icons } from "../icons.js";
import { Table } from "../primitives/Table.js";
import type { ShellModuleCard, ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { ContextStrip } from "./ContextStrip.js";

/** Roadmap modules — kept in sync with the VISION.md one-liner in the README. */
const ROADMAP_MODULES = ["blackbox", "pwn", "pentest", "honeypot", "yokai", "revgraph"] as const;

const CATEGORY_ORDER = ["offense", "intel", "governance", "defense"] as const;
const CATEGORY_LABEL: Record<(typeof CATEGORY_ORDER)[number], string> = {
  offense: "OFFENSE",
  intel: "INTEL",
  governance: "GOVERNANCE",
  defense: "DEFENSE",
};

interface ModuleCatalogProps {
  shell: ShellState;
}

export function ModuleCatalog({ shell }: ModuleCatalogProps): React.ReactElement {
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 120;
  const narrow = columns < 110;
  useRegisterKeybindings([
    { keys: "/use <id>", label: "focus module" },
    { keys: "/findings", label: "findings", secondary: true },
    { keys: "/tune", label: "tune", secondary: true },
    { keys: "?", label: "help", secondary: true },
    { keys: "Ctrl+C", label: "exit", secondary: true },
  ]);
  const cards = shell.moduleCatalog ?? [];
  const builtIns = cards.filter((c) => !c.external);
  const externals = cards.filter((c) => c.external);

  const byCategory: Record<string, ShellModuleCard[]> = {};
  for (const card of builtIns) {
    const bucket = byCategory[card.category] ?? [];
    bucket.push(card);
    byCategory[card.category] = bucket;
  }

  const cardWidth = 61;
  return (
    <Box flexDirection="column" paddingLeft={SPACING.md} marginBottom={SPACING.sm}>
      <ContextStrip
        status={[
          `workspace:${shell.workspace ?? "none"}`,
          `target:${shell.target ?? "none"}`,
          `${(shell.moduleCatalog ?? []).length} modules`,
        ]}
      />
      <Box marginTop={SPACING.sm}>
        <Text>
          {tokens.strong("Primary next step: ")}
          {tokens.accent("/use <module-id>")}
          {tokens.muted(" to enter one module workflow.")}
        </Text>
      </Box>

      {CATEGORY_ORDER.map((cat) => {
        const rows = byCategory[cat];
        if (!rows || rows.length === 0) return null;
        return (
          <Box key={cat} flexDirection="column" marginTop={SPACING.sm}>
            <Text>{tokens.label(CATEGORY_LABEL[cat])}</Text>
            <Box marginTop={SPACING.sm}>
              <ModuleRows rows={rows} />
            </Box>
          </Box>
        );
      })}

      {externals.length > 0 && (
        <Box flexDirection="column" marginTop={SPACING.sm}>
          <Text>
            {tokens.label("EXTERNAL")}
            {"  "}
            {tokens.muted("(loaded via --load package:<name>)")}
          </Text>
          <Box marginTop={SPACING.sm}>
            <ModuleRows rows={externals} />
          </Box>
        </Box>
      )}

      <Box marginTop={SPACING.sm}>
        <Text>{tokens.metadata(icons.boxHorizontal.repeat(cardWidth - 2))}</Text>
      </Box>
      <Box>
        <Text>
          {tokens.hint(`coming · ${ROADMAP_MODULES.join(" · ")} — `)}
          {tokens.accent("see VISION.md")}
        </Text>
      </Box>

    </Box>
  );
}

function ModuleRows({ rows }: { rows: ShellModuleCard[] }): React.ReactElement {
  return (
    <Table
      showHeader
      gap={1}
      columns={[
        { key: "id", header: "MODULE", width: 14, truncate: "end", render: (c) => c.id },
        {
          key: "description",
          header: "DESCRIPTION",
          flex: 4,
          truncate: "end",
          render: (c) => c.description,
        },
        {
          key: "last",
          header: "LAST RUN",
          flex: 2,
          truncate: "end",
          render: (c) => c.lastRunSummary ?? "never run",
        },
      ]}
      rows={rows}
    />
  );
}
