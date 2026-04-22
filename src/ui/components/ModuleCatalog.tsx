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

import { Box, Text } from "ink";
import type React from "react";
import { Table } from "../primitives/Table.js";
import type { ShellModuleCard, ShellState } from "../state.js";
import { tokens } from "../tokens.js";

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
  const cards = shell.moduleCatalog ?? [];
  const builtIns = cards.filter((c) => !c.external);
  const externals = cards.filter((c) => c.external);

  const byCategory: Record<string, ShellModuleCard[]> = {};
  for (const card of builtIns) {
    const bucket = byCategory[card.category] ?? [];
    bucket.push(card);
    byCategory[card.category] = bucket;
  }

  return (
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <CatalogHeader shell={shell} />

      {CATEGORY_ORDER.map((cat) => {
        const rows = byCategory[cat];
        if (!rows || rows.length === 0) return null;
        return (
          <Box key={cat} flexDirection="column" marginTop={1}>
            <Text>{tokens.label(CATEGORY_LABEL[cat])}</Text>
            <Box marginTop={1}>
              <ModuleRows rows={rows} />
            </Box>
          </Box>
        );
      })}

      {externals.length > 0 && (
        <Box flexDirection="column" marginTop={1}>
          <Text>
            {tokens.label("EXTERNAL")}
            {"  "}
            {tokens.muted("(loaded via --load package:<name>)")}
          </Text>
          <Box marginTop={1}>
            <ModuleRows rows={externals} />
          </Box>
        </Box>
      )}

      <Box marginTop={1}>
        <Text>{tokens.muted("─".repeat(74))}</Text>
      </Box>
      <Box>
        <Text>
          {tokens.hint(`coming · ${ROADMAP_MODULES.join(" · ")} — `)}
          {tokens.accent("see VISION.md")}
        </Text>
      </Box>

      <Box marginTop={1}>
        <Text>
          {tokens.hint("/use <id> open   /findings list   /tune adjust   /help more   /exit quit")}
        </Text>
      </Box>
    </Box>
  );
}

function CatalogHeader({ shell }: { shell: ShellState }): React.ReactElement {
  const workspace = shell.workspace ?? "(no workspace)";
  const target = shell.target ?? "(no target)";
  const modList = (shell.moduleCatalog ?? [])
    .filter((c) => !c.external)
    .slice(0, 5)
    .map((c) => c.id)
    .join(", ");

  return (
    <Box flexDirection="column">
      <Text>{tokens.muted("╭─────────────────────────────────────────────────────────────╮")}</Text>
      <Text>
        {tokens.muted("│  ")}
        {tokens.strong("kuzushi shell")}
        {"                      "}
        {tokens.muted("workspace ")}
        {tokens.value(workspace)}
        {tokens.muted("  │")}
      </Text>
      <Text>
        {tokens.muted("│  modules ")}
        {tokens.value(modList || "(none)")}
        {tokens.muted("  │")}
      </Text>
      <Text>
        {tokens.muted("│  target ")}
        {tokens.value(target)}
        {tokens.muted("  │")}
      </Text>
      <Text>{tokens.muted("╰─────────────────────────────────────────────────────────────╯")}</Text>
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
