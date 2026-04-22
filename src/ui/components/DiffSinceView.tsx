/**
 * DiffSinceView — Phase D.3 diff-aware view.
 *
 * Reads `shell.diffSince` (populated by the `/since <ref>` shell command
 * via `computeDiffScope`) and renders:
 *
 *   1. A header row with the git ref + changed-file count.
 *   2. The list of changed files, truncated to 40 rows with a
 *      `(+N more)` tail so a huge diff doesn't blow out the view.
 *   3. Findings scoped to the changed files — reuses `state.summary
 *      .actionableFindings` and filters by `filePath`.
 *   4. Threat-model elements whose `affectedFiles` overlap the changed
 *      set (when a threat model is loaded). Uses `StrideThreat
 *      .affectedFiles[].filePath` for the intersection.
 *   5. An error banner when `git diff` failed so the operator sees why.
 *
 * Pure presentation — the actual diff computation and state updates live
 * in `src/copilot/diff-scope.ts` and the shell verb handler.
 */

import { Box, Text } from "ink";
import type React from "react";
import type { StrideThreat } from "../../agents/tasks/threat-modeling/types.js";
import { Table } from "../primitives/Table.js";
import type { ActionableFinding, ShellState, UIState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";

interface DiffSinceViewProps {
  state: UIState;
  shell: ShellState;
}

export function DiffSinceView({ state, shell }: DiffSinceViewProps): React.ReactElement {
  const diff = shell.diffSince;
  if (!diff) return <EmptyState />;

  const changedSet = new Set(diff.changedFiles);
  const allFindings = state.summary?.actionableFindings ?? [];
  const scopedFindings = allFindings.filter((f) => changedSet.has(f.filePath));

  const threats = shell.threatModel?.threats ?? [];
  const scopedThreats = threats.filter((t) =>
    (t.affectedFiles ?? []).some((af) => af.filePath && changedSet.has(af.filePath)),
  );

  return (
    <Box flexDirection="column" paddingLeft={SPACING.md} marginBottom={SPACING.sm}>
      <Header
        diff={diff}
        scopedFindings={scopedFindings.length}
        scopedThreats={scopedThreats.length}
      />

      {diff.error ? (
        <Box marginTop={SPACING.sm}>
          <Text>
            {tokens.warn("git diff failed: ")}
            {tokens.muted(diff.error)}
          </Text>
        </Box>
      ) : null}

      <ChangedFiles files={diff.changedFiles} />

      {allFindings.length > 0 ? (
        <ScopedFindings scopedFindings={scopedFindings} total={allFindings.length} />
      ) : null}

      {threats.length > 0 ? (
        <ScopedThreats scopedThreats={scopedThreats} total={threats.length} />
      ) : null}

      <HintFooter />
    </Box>
  );
}

function EmptyState(): React.ReactElement {
  return (
    <Box flexDirection="column" paddingLeft={SPACING.md} marginBottom={SPACING.sm}>
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("diff since \u2026")}
      </Text>
      <Box marginTop={SPACING.sm}>
        <Text>
          {tokens.warn("No diff computed yet. ")}
          {tokens.muted("Type ")}
          {tokens.strong("/since <git-ref>")}
          {tokens.muted(" to scope.")}
        </Text>
      </Box>
    </Box>
  );
}

function Header({
  diff,
  scopedFindings,
  scopedThreats,
}: {
  diff: NonNullable<ShellState["diffSince"]>;
  scopedFindings: number;
  scopedThreats: number;
}): React.ReactElement {
  return (
    <Box flexDirection="column">
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("diff since ")}
        {tokens.accent(diff.ref)}
        {tokens.muted("   \u2502   ")}
        {tokens.value(
          `${diff.changedFiles.length} file${diff.changedFiles.length === 1 ? "" : "s"}`,
        )}
        {tokens.muted("  \u00B7  ")}
        {tokens.value(`${scopedFindings} finding${scopedFindings === 1 ? "" : "s"}`)}
        {tokens.muted("  \u00B7  ")}
        {tokens.value(`${scopedThreats} threat${scopedThreats === 1 ? "" : "s"}`)}
      </Text>
      <Text>{tokens.muted(`scope: changed files only · /since reset for full workspace`)}</Text>
    </Box>
  );
}

function ChangedFiles({ files }: { files: string[] }): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("changed files")}</Text>
      <Box marginTop={SPACING.sm}>
        {files.length === 0 ? (
          <Text>{tokens.muted("   (no files changed)")}</Text>
        ) : (
          <Table
            showHeader
            gap={1}
            columns={[
              { key: "idx", header: "#", width: 4, align: "right" },
              { key: "file", header: "FILE", flex: 1, truncate: "middle" },
            ]}
            rows={files.slice(0, 40).map((file, idx) => ({ idx: idx + 1, file }))}
          />
        )}
      </Box>
    </Box>
  );
}

function ScopedFindings({
  scopedFindings,
  total,
}: {
  scopedFindings: ActionableFinding[];
  total: number;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>
        {tokens.label("findings in changed files")}
        {tokens.muted(`  (${scopedFindings.length} of ${total})`)}
      </Text>
      <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.lg}>
        {scopedFindings.length === 0 ? (
          <Text>{tokens.muted("(no findings touch the changed files)")}</Text>
        ) : (
          <Table
            showHeader
            gap={1}
            columns={[
              {
                key: "sev",
                header: "SEV",
                width: 5,
                render: (f: ActionableFinding) => severityBadge(f),
              },
              {
                key: "title",
                header: "TITLE",
                flex: 4,
                truncate: "end",
                render: (f) => f.title ?? f.ruleId,
              },
              {
                key: "loc",
                header: "LOCATION",
                flex: 3,
                truncate: "middle",
                render: (f) => `${f.filePath}:${f.startLine}`,
              },
            ]}
            rows={scopedFindings.slice(0, 15)}
          />
        )}
        {scopedFindings.length > 15 ? (
          <Text>{tokens.hint(`(+${scopedFindings.length - 15} more)`)}</Text>
        ) : null}
      </Box>
    </Box>
  );
}

function ScopedThreats({
  scopedThreats,
  total,
}: {
  scopedThreats: StrideThreat[];
  total: number;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>
        {tokens.label("threats touching changed files")}
        {tokens.muted(`  (${scopedThreats.length} of ${total})`)}
      </Text>
      <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.lg}>
        {scopedThreats.length === 0 ? (
          <Text>{tokens.muted("(no STRIDE threats target the changed files)")}</Text>
        ) : (
          <Table
            showHeader
            gap={1}
            columns={[
              { key: "id", header: "ID", width: 8, truncate: "end" },
              {
                key: "impact",
                header: "IMP",
                width: 5,
                render: (t: StrideThreat) => impactBadge(t.impact),
              },
              { key: "title", header: "TITLE", flex: 4, truncate: "end" },
              { key: "category", header: "CAT", width: 16, truncate: "end" },
            ]}
            rows={scopedThreats.slice(0, 10)}
          />
        )}
        {scopedThreats.length > 10 ? (
          <Text>{tokens.hint(`(+${scopedThreats.length - 10} more)`)}</Text>
        ) : null}
      </Box>
    </Box>
  );
}

function severityBadge(f: ActionableFinding): string {
  const sev = (f.displaySeverity ?? f.severity ?? "").toLowerCase();
  if (sev.includes("crit")) return tokens.dangerStrong("CRIT");
  if (sev.includes("high")) return tokens.danger("HIGH");
  if (sev.includes("med")) return tokens.warn("MED ");
  return tokens.info("LOW ");
}

function impactBadge(impact: StrideThreat["impact"]): string {
  switch (impact) {
    case "critical":
      return tokens.dangerStrong("CRIT");
    case "high":
      return tokens.danger("HIGH");
    case "medium":
      return tokens.warn("MED ");
    default:
      return tokens.info("LOW ");
  }
}

function HintFooter(): React.ReactElement {
  return (
    <Box marginTop={SPACING.sm}>
      <Text>
        {tokens.hint("/since <ref> to rescope   ")}
        {tokens.muted("/findings for the full list")}
        {tokens.hint("   q back")}
      </Text>
    </Box>
  );
}
