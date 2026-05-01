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

import { Box, Text, useStdout } from "ink";
import type React from "react";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { Divider } from "../primitives/Divider.js";
import { Table } from "../primitives/Table.js";
import { severitySparkline } from "../sparkline.js";
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
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 120;
  const rows = stdout?.rows ?? 40;
  // Lifted from 112 → 160 so the description column has room to breathe
  // on modern terminals; `…` truncation in the column already handles
  // narrow panes. The chrome is full-width, so the table sitting at 112
  // cols inside a 200-col chrome read like two different layouts.
  const tableWidth = Math.max(48, Math.min(160, columns - SPACING.md * 4));
  useRegisterKeybindings([
    { keys: "use <id>", label: "focus module" },
    { keys: "findings", label: "findings", secondary: true },
    { keys: "?", label: "help", secondary: true },
    { keys: "Ctrl+C", label: "exit", secondary: true },
  ]);
  const cards = shell.moduleCatalog ?? [];
  const compact = rows < 44 && cards.length > 8;
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

  if (compact) {
    const orderedRows = [...CATEGORY_ORDER.flatMap((cat) => byCategory[cat] ?? []), ...externals];
    return (
      <ScreenContent>
        <ContextStrip status={status} />
        <Box marginTop={SPACING.sm}>
          <ModuleRows rows={orderedRows} maxWidth={tableWidth} compact />
        </Box>
      </ScreenContent>
    );
  }

  return (
    <ScreenContent>
      <ContextStrip status={status} />

      {(() => {
        const recommended = pickRecommendedFirst(builtIns);
        if (!recommended) return null;
        return (
          <Box marginTop={SPACING.sm} flexDirection="column">
            <Text>
              {tokens.strong("Recommended first: ")}
              {tokens.accent(`use ${recommended.id}`)}
              {tokens.muted(` — ${shortDescription(recommended.description)}`)}
            </Text>
            <Text>
              {tokens.muted("  New to Kuzushi? Type ")}
              {tokens.accent("/quickstart")}
              {tokens.muted(" for a 3-step guided tour.")}
            </Text>
          </Box>
        );
      })()}

      {CATEGORY_ORDER.map((cat) => {
        const rows = byCategory[cat];
        if (!rows || rows.length === 0) return null;
        const meta = CATEGORY_META[cat];
        return (
          <Box key={cat} flexDirection="column" marginTop={SPACING.sm}>
            {/* `Divider title=` inset gives a single rule + label, replacing
                the stand-alone label line + table-divider stack. The blurb
                lives directly below the rule so the section reads as one
                visual unit. */}
            <Divider width={tableWidth} title={meta.label} />
            <Box paddingLeft={SPACING.md}>
              <Text>{tokens.muted(meta.blurb)}</Text>
            </Box>
            <ModuleRows rows={rows} maxWidth={tableWidth} />
          </Box>
        );
      })}

      {externals.length > 0 && (
        <Box flexDirection="column" marginTop={SPACING.sm}>
          <Divider width={tableWidth} title="EXTERNAL" />
          <Box paddingLeft={SPACING.md}>
            <Text>{tokens.muted("(loaded via --load package:<name>)")}</Text>
          </Box>
          <ModuleRows rows={externals} maxWidth={tableWidth} />
        </Box>
      )}
    </ScreenContent>
  );
}

/**
 * Pick the highest-signal "first module" for new operators. Preference order:
 *   1. `sast` if loaded — it's the only module that scans code by default and
 *      most operators come to Kuzushi for SAST.
 *   2. The first offense-category module otherwise.
 *   3. The first module of any category as a last resort.
 *
 * Returning null means the catalog is empty; callers gate the hint on that.
 */
export function pickRecommendedFirst(
  cards: ReadonlyArray<ShellModuleCard>,
): ShellModuleCard | null {
  if (cards.length === 0) return null;
  const sast = cards.find((c) => c.id === "sast");
  if (sast) return sast;
  const offense = cards.find((c) => c.category === "offense");
  if (offense) return offense;
  return cards[0] ?? null;
}

/**
 * Trim a module's description to one short sentence so the hint line stays
 * single-row even on narrow terminals. Mirrors `formatModuleDescription`
 * in the shell text path so the two surfaces stay visually aligned.
 */
function shortDescription(description: string): string {
  const first = description.split(".")[0]?.trim() ?? description;
  if (first.length <= 80) return first;
  return `${first.slice(0, 79)}…`;
}

function compactTarget(target: string | null | undefined): string {
  if (!target) return "none";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) return target;
  const trimmed = target.replace(/\/+$/, "");
  const parts = trimmed.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? target;
}

function ModuleRows({
  rows,
  maxWidth,
  compact = false,
}: {
  rows: ShellModuleCard[];
  maxWidth: number;
  compact?: boolean;
}): React.ReactElement {
  // Hide LAST RUN entirely when no module has ever run for this workspace.
  // Eighteen "never run" cells × 20 cols was the single noisiest visual on
  // the catalog. Once any module has run, the column re-appears and the
  // un-run rows render as `—`.
  const showLastRun = rows.some((r) => !!r.lastRunSummary);
  return (
    <Table
      showHeader
      gap={1}
      columns={[
        // U3: Widened from 14 → 22 so `carlini-threat-hunt` (19 chars) fits
        // without truncation. Operators previously saw `carlini-threa…` and
        // had to /modules to get the full id, breaking flow.
        { key: "id", header: "MODULE", width: 22, truncate: "end", render: (c) => c.id },
        ...(compact
          ? [
              {
                key: "category",
                header: "TYPE",
                width: 10,
                truncate: "end" as const,
                render: (c: ShellModuleCard) => (c.external ? "external" : c.category),
              },
            ]
          : []),
        {
          key: "description",
          header: "DESCRIPTION",
          flex: 6,
          truncate: "end",
          render: (c) => c.description,
        },
        ...(showLastRun
          ? [
              {
                // Width 28 fits a 5-glyph sparkline + 2-space gap + a typical
                // summary like `error · scan · 2m · $0.07`. The description
                // column gives a few cols back; the catalog cap of 160 still
                // leaves the description plenty of breathing room.
                key: "last",
                header: "LAST RUN",
                width: 28,
                truncate: "end" as const,
                render: (c: ShellModuleCard) => {
                  const monorepo = severitySparkline(c.lastRunSeverityCounts);
                  const summary = c.lastRunSummary ?? "—";
                  return monorepo ? `${monorepo}  ${summary}` : summary;
                },
              },
            ]
          : []),
      ]}
      rows={rows}
      maxWidth={maxWidth}
    />
  );
}
