/**
 * ModuleCatalog — shell home screen (D1, Ink UI v2 screen 01).
 *
 * Renders when the shell is at the top level (shellView === "catalog" and
 * no focused module). Groups the loaded modules by the real README
 * categories — offense · intel · governance · defense — plus an optional
 * EXTERNAL section for `pkg:*` modules.
 *
 * Each row shows: `id · one-liner · last-run summary`. Selection is purely
 * visual — the user types `/use <id>` in the shell prompt below the catalog
 * to focus a module, just like today's command flow.
 */

import { Box, Text } from "ink";
import type React from "react";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { Table } from "../primitives/Table.js";
import type { ShellModuleCard, ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { ContextStrip } from "./ContextStrip.js";
import { ScreenContent } from "./ScreenContent.js";

const CATEGORY_ORDER = ["offense", "intel", "governance", "defense"] as const;
const CATEGORY_META: Record<(typeof CATEGORY_ORDER)[number], { label: string; blurb: string }> = {
  offense: { label: "OFFENSE", blurb: "hunt vulnerabilities and prove exploitability" },
  intel: { label: "INTEL", blurb: "research targets, map attack surface, gather context" },
  governance: { label: "GOVERNANCE", blurb: "policy, compliance, and audit-ready evidence" },
  defense: { label: "DEFENSE", blurb: "detect, prioritize, and remediate findings" },
};

interface ModuleCatalogProps {
  shell: ShellState;
}

export function ModuleCatalog({ shell }: ModuleCatalogProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "use <id>", label: "focus module" },
    { keys: "findings", label: "findings", secondary: true },
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
  const workspace = shell.workspace ?? "none";
  const targetLabel = compactTarget(shell.target);
  const moduleCount = (shell.moduleCatalog ?? []).length;
  const status =
    workspace === targetLabel
      ? [`scope:${workspace}`, `${moduleCount} modules`]
      : [`workspace:${workspace}`, `target:${targetLabel}`, `${moduleCount} modules`];
  return (
    <ScreenContent>
      <ContextStrip status={status} />
      <Box marginTop={SPACING.sm}>
        <Text>
          {tokens.strong("Primary next step: ")}
          {tokens.accent("use <module-id>")}
          {tokens.muted(" to enter one module workflow.")}
        </Text>
      </Box>

      {CATEGORY_ORDER.map((cat) => {
        const rows = byCategory[cat];
        if (!rows || rows.length === 0) return null;
        const meta = CATEGORY_META[cat];
        return (
          <Box key={cat} flexDirection="column" marginTop={SPACING.sm}>
            <Text>
              {tokens.label(meta.label)}
              {"  "}
              {tokens.muted(meta.blurb)}
            </Text>
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
    </ScreenContent>
  );
}

function compactTarget(target: string | null | undefined): string {
  if (!target) return "none";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) return target;
  const trimmed = target.replace(/\/+$/, "");
  const parts = trimmed.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? target;
}

function ModuleRows({ rows }: { rows: ShellModuleCard[] }): React.ReactElement {
  return (
    <Table
      showHeader
      gap={1}
      columns={[
        // U3: Widened from 14 → 22 so `carlini-threat-hunt` (19 chars) fits
        // without truncation. Operators previously saw `carlini-threa…` and
        // had to /modules to get the full id, breaking flow.
        { key: "id", header: "MODULE", width: 22, truncate: "end", render: (c) => c.id },
        {
          key: "description",
          header: "DESCRIPTION",
          flex: 6,
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
