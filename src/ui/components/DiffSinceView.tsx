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
import { type Severity, severityChalk, severityStyle } from "../severity.js";
import type { ActionableFinding, ShellState, UIState } from "../state.js";
import { tokens } from "../tokens.js";

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
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Header
        diff={diff}
        scopedFindings={scopedFindings.length}
        scopedThreats={scopedThreats.length}
      />

      {diff.error ? (
        <Box marginTop={1}>
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
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("diff since \u2026")}
      </Text>
      <Box marginTop={1}>
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
    </Box>
  );
}

function ChangedFiles({ files }: { files: string[] }): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text>{tokens.label("changed files")}</Text>
      <Box flexDirection="column" marginTop={1} paddingLeft={3}>
        {files.length === 0 ? (
          <Text>{tokens.muted("(no files changed)")}</Text>
        ) : (
          <>
            {files.slice(0, 40).map((f) => (
              <Text key={f}>
                {tokens.muted("\u00B7  ")}
                {tokens.value(f)}
              </Text>
            ))}
            {files.length > 40 ? (
              <Text>{tokens.hint(`\u00B7  (+${files.length - 40} more)`)}</Text>
            ) : null}
          </>
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
    <Box flexDirection="column" marginTop={1}>
      <Text>
        {tokens.label("findings in changed files")}
        {tokens.muted(`  (${scopedFindings.length} of ${total})`)}
      </Text>
      <Box flexDirection="column" marginTop={1} paddingLeft={3}>
        {scopedFindings.length === 0 ? (
          <Text>{tokens.muted("(no findings touch the changed files)")}</Text>
        ) : (
          scopedFindings.slice(0, 15).map((f) => (
            <Text key={f.fingerprint}>
              {severityBadge(f)}
              {"  "}
              {tokens.strong(truncate(f.title ?? f.ruleId, 50))}
              {tokens.muted(`  ${f.filePath}:${f.startLine}`)}
            </Text>
          ))
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
    <Box flexDirection="column" marginTop={1}>
      <Text>
        {tokens.label("threats touching changed files")}
        {tokens.muted(`  (${scopedThreats.length} of ${total})`)}
      </Text>
      <Box flexDirection="column" marginTop={1} paddingLeft={3}>
        {scopedThreats.length === 0 ? (
          <Text>{tokens.muted("(no STRIDE threats target the changed files)")}</Text>
        ) : (
          scopedThreats.slice(0, 10).map((t) => (
            <Text key={t.id}>
              {tokens.muted(`[${t.id}]`.padEnd(8))}
              {impactBadge(t.impact)}
              {"  "}
              {tokens.strong(truncate(t.title, 54))}
              {tokens.muted(`  ${t.category}`)}
            </Text>
          ))
        )}
        {scopedThreats.length > 10 ? (
          <Text>{tokens.hint(`(+${scopedThreats.length - 10} more)`)}</Text>
        ) : null}
      </Box>
    </Box>
  );
}

function severityBadge(f: ActionableFinding): string {
  const raw = (f.displaySeverity ?? f.severity ?? "").toLowerCase();
  let sev: Severity = "info";
  if (raw.includes("crit")) sev = "critical";
  else if (raw.includes("high")) sev = "high";
  else if (raw.includes("med")) sev = "medium";
  else if (raw.includes("low")) sev = "low";
  const style = severityStyle(sev);
  return severityChalk(sev)(`${style.glyph} ${style.label}`);
}

function impactBadge(impact: StrideThreat["impact"]): string {
  const sev: Severity =
    impact === "critical"
      ? "critical"
      : impact === "high"
        ? "high"
        : impact === "medium"
          ? "medium"
          : "low";
  const style = severityStyle(sev);
  return severityChalk(sev)(`${style.glyph} ${style.label}`);
}

function HintFooter(): React.ReactElement {
  return (
    <Box marginTop={1}>
      <Text>
        {tokens.hint("/since <ref> to rescope   ")}
        {tokens.muted("/findings for the full list")}
        {tokens.hint("   q back")}
      </Text>
    </Box>
  );
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}\u2026`;
}
