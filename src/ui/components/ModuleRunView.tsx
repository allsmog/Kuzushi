/**
 * ModuleRunView — live transcript for the focused module's running tool.
 *
 * Layout (top → bottom):
 *
 *   kuzushi/<module>/run                         <elapsed> · running
 *   ─────────────────────────────────────────────────────────────────
 *   ⏺ <DisplayName>(<formattedInput>)
 *
 *   steps
 *     ✓ ...
 *     → ...
 *     ○ ...
 *
 *   actors                          (threat-hunt only)
 *     AUTH-01  active  Unauthenticated User · turn 4/12 · $0.18
 *       ✓ Read src/api/...
 *       → grep "auth"
 *
 *   evidence
 *     ...
 *
 *   findings · cost · prompts · artifacts
 *
 * The component is purely presentational — it reads from
 * `shell.moduleRun` (steps, evidenceTail, cost, artifacts) and from
 * `shell.agentActivity` (per-actor live rows). When `moduleRun` is null,
 * the component renders an empty placeholder so it can be safely keyed
 * into the view dispatcher even before the report-worker writes the slice.
 */

import { Box, Text } from "ink";
import type React from "react";
import type { Finding } from "../../scanners/types.js";
import { formatCost, formatDuration, truncateEnd } from "../format.js";
import { BLACK_CIRCLE, STEP_GLYPH } from "../glyphs.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { Table } from "../primitives/Table.js";
import type { AgentActivityLine, ModuleRunArtifact, ModuleRunStep, ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { actorLabelFromFingerprint, actorShortId, toCompactRow } from "../transcript-format.js";
import { RuleHeader } from "./RuleHeader.js";
import { ScreenContent } from "./ScreenContent.js";

interface ModuleRunViewProps {
  shell: ShellState;
  /** Project-level findings, used to render the "Findings" tail. */
  findings?: ReadonlyArray<Finding>;
  /**
   * Live agent activity map (per-actor fingerprints → last-N activity
   * lines). Threaded from the UIStore — `ShellState` doesn't own it
   * because the same store powers both shell and scan modes.
   */
  agentActivity?: ReadonlyMap<string, ReadonlyArray<import("../state.js").AgentActivityLine>>;
  /** Live elapsed override — primarily for tests / snapshots. */
  nowMs?: number;
}

const MAX_EVIDENCE_ROWS = 8;
const MAX_FINDING_ROWS = 5;

export function ModuleRunView({
  shell,
  findings = [],
  agentActivity,
  nowMs,
}: ModuleRunViewProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "1–4", label: "drill into actor" },
    { keys: "b", label: "back", secondary: true },
    { keys: "Ctrl+C", label: "interrupt", secondary: true },
  ]);

  const run = shell.moduleRun;
  const moduleId = run?.moduleId ?? shell.focusedModule ?? "module";
  const breadcrumb = `kuzushi/${moduleId}/run`;

  const elapsed = run ? formatDuration(Math.max(0, (nowMs ?? Date.now()) - run.startedAtMs)) : "0s";
  const status = run
    ? run.status === "running"
      ? `${elapsed} · running`
      : run.status === "done"
        ? `${elapsed} · done`
        : run.status === "aborted"
          ? `${elapsed} · aborted`
          : `${elapsed} · error`
    : "idle";

  return (
    <ScreenContent>
      <RuleHeader breadcrumb={breadcrumb} status={status} />
      {run ? (
        <>
          <ToolHeader run={run} />
          <StepsBlock steps={run.steps} />
          {run.moduleId === "threat-hunt" ? (
            <ActorsBlock agentActivity={agentActivity} run={run} />
          ) : null}
          <EvidenceBlock evidence={run.evidenceTail} />
          <FindingsBlock run={run} findings={findings} />
          <MetaRow run={run} />
          <ArtifactsBlock artifacts={run.artifacts} />
        </>
      ) : (
        <Box marginTop={SPACING.sm}>
          <Text>{tokens.muted("No active run for this module yet.")}</Text>
        </Box>
      )}
    </ScreenContent>
  );
}

function ToolHeader({ run }: { run: NonNullable<ShellState["moduleRun"]> }): React.ReactElement {
  const label = run.displayName ?? run.toolName ?? `${run.moduleId}:run`;
  const args = run.inputSummary ? `(${truncateEnd(run.inputSummary, 56)})` : "";
  return (
    <Box marginBottom={SPACING.sm}>
      <Text>
        {tokens.accent(BLACK_CIRCLE)} {tokens.label(label)}
        {args ? tokens.muted(args) : null}
      </Text>
    </Box>
  );
}

function StepsBlock({
  steps,
}: {
  steps: NonNullable<ShellState["moduleRun"]>["steps"];
}): React.ReactElement {
  if (!steps || steps.length === 0) return <Box />;
  return (
    <Section title="steps">
      <Box flexDirection="column" paddingLeft={SPACING.md}>
        {steps.map((step) => (
          <StepRow key={step.id} step={step} />
        ))}
      </Box>
    </Section>
  );
}

function StepRow({ step }: { step: ModuleRunStep }): React.ReactElement {
  const glyph =
    step.status === "done"
      ? tokens.success(STEP_GLYPH.done)
      : step.status === "running"
        ? tokens.warn(STEP_GLYPH.running)
        : step.status === "error"
          ? tokens.danger("✗")
          : tokens.muted(STEP_GLYPH.pending);
  const trail = [step.count, step.elapsedSeconds ? `${step.elapsedSeconds}s` : null]
    .filter(Boolean)
    .join(" · ");
  const titleColor =
    step.status === "running"
      ? tokens.value
      : step.status === "done"
        ? tokens.muted
        : step.status === "error"
          ? tokens.danger
          : tokens.muted;
  return (
    <Box justifyContent="space-between">
      <Text>
        {glyph} {titleColor(step.title)}
      </Text>
      {trail ? <Text>{tokens.muted(trail)}</Text> : null}
    </Box>
  );
}

interface ActorRow {
  fingerprint: string;
  shortId: string;
  label: string;
  status: "active" | "queued";
  lastCompleted?: AgentActivityLine;
  running?: AgentActivityLine;
}

function actorRowsFromActivity(
  activity: ReadonlyMap<string, ReadonlyArray<AgentActivityLine>> | undefined,
): ActorRow[] {
  if (!activity) return [];
  const fingerprints: string[] = [];
  for (const fp of activity.keys()) {
    if (fp.startsWith("threat-hunt:")) fingerprints.push(fp);
  }
  fingerprints.sort();
  return fingerprints.map((fp, i) => {
    const lines = activity.get(fp) ?? [];
    const running = [...lines]
      .reverse()
      .find((l) => l.kind === "tool-start" || l.kind === "tool-progress");
    const lastCompleted = [...lines]
      .reverse()
      .find((l) => l.kind === "tool-complete" || l.kind === "summary");
    return {
      fingerprint: fp,
      shortId: actorShortId(fp, i),
      label: actorLabelFromFingerprint(fp),
      status: running ? "active" : "queued",
      ...(running ? { running } : {}),
      ...(lastCompleted ? { lastCompleted } : {}),
    };
  });
}

function ActorsBlock({
  agentActivity,
  run,
}: {
  agentActivity?: ReadonlyMap<string, ReadonlyArray<AgentActivityLine>>;
  run: NonNullable<ShellState["moduleRun"]>;
}): React.ReactElement {
  const rows = actorRowsFromActivity(agentActivity);
  if (rows.length === 0) return <Box />;
  void run; // reserved for future per-run counters
  return (
    <Section title="actors" hint="1–4 drill into actor">
      <Box flexDirection="column" paddingLeft={SPACING.md}>
        {rows.map((row) => (
          <ActorCard key={row.fingerprint} row={row} />
        ))}
      </Box>
    </Section>
  );
}

function ActorCard({ row }: { row: ActorRow }): React.ReactElement {
  const heading = (
    <Text>
      {tokens.accent(row.shortId.padEnd(8))} {tokens.value(row.label.padEnd(30))}
      {tokens.muted(row.status)}
    </Text>
  );
  return (
    <Box flexDirection="column" marginBottom={SPACING.xs}>
      {heading}
      {row.lastCompleted ? <ActivityChip line={row.lastCompleted} /> : null}
      {row.running ? <ActivityChip line={row.running} /> : null}
    </Box>
  );
}

function ActivityChip({ line }: { line: AgentActivityLine }): React.ReactElement {
  const compact = toCompactRow(line);
  const color =
    line.kind === "tool-complete"
      ? tokens.success
      : line.kind === "tool-start" || line.kind === "tool-progress"
        ? tokens.warn
        : tokens.muted;
  const trail = [compact.action, compact.target ?? compact.summary].filter(Boolean).join(" ");
  return (
    <Box paddingLeft={SPACING.md}>
      <Text>
        {color(compact.glyph)} {tokens.muted(truncateEnd(trail, 80))}
      </Text>
    </Box>
  );
}

function EvidenceBlock({
  evidence,
}: {
  evidence: ReadonlyArray<AgentActivityLine>;
}): React.ReactElement {
  if (!evidence || evidence.length === 0) return <Box />;
  const tail = evidence.slice(-MAX_EVIDENCE_ROWS);
  const rows = tail.map((line, i) => {
    const compact = toCompactRow(line);
    return {
      glyph: compact.glyph,
      action: compact.action,
      target: compact.target ?? compact.summary ?? "",
      idx: i,
    };
  });
  return (
    <Section title="evidence">
      <Box paddingLeft={SPACING.md}>
        <Table
          showHeader={false}
          divider={false}
          gap={2}
          columns={[
            { key: "glyph", width: 1 },
            { key: "action", flex: 2, truncate: "end" },
            { key: "target", flex: 5, truncate: "middle" },
          ]}
          rows={rows}
        />
      </Box>
    </Section>
  );
}

function FindingsBlock({
  run,
  findings,
}: {
  run: NonNullable<ShellState["moduleRun"]>;
  findings: ReadonlyArray<Finding>;
}): React.ReactElement {
  if (!findings || findings.length === 0) return <Box />;
  // Filter to this run's findings when we can tell — fall back to "all".
  const scoped =
    run.runId != null
      ? findings.filter(
          (f) => (f.taskId ?? "") === run.moduleId || (f.taskId ?? "") === run.toolName,
        )
      : findings;
  const slice = scoped.slice(0, MAX_FINDING_ROWS).map((f) => ({
    severity: f.severity,
    id: f.fingerprint.slice(0, 8),
    path: `${f.filePath}:${f.startLine}`,
    title: f.message,
  }));
  if (slice.length === 0) return <Box />;
  return (
    <Section title="findings">
      <Box paddingLeft={SPACING.md}>
        <Table
          showHeader={false}
          divider={false}
          gap={2}
          columns={[
            { key: "severity", width: 8 },
            { key: "id", width: 9 },
            { key: "path", flex: 4, truncate: "middle" },
            { key: "title", flex: 5, truncate: "end" },
          ]}
          rows={slice}
        />
      </Box>
    </Section>
  );
}

function MetaRow({ run }: { run: NonNullable<ShellState["moduleRun"]> }): React.ReactElement {
  const cost = run.costUsd != null ? formatCost(run.costUsd) : "—";
  return (
    <Section title="cost · prompts">
      <Box paddingLeft={SPACING.md}>
        <Text>
          {tokens.muted("cost     ")}
          {tokens.value(cost)}
          {tokens.muted("    prompts ")}
          {tokens.value("kuzushi/<module>/prompts")}
        </Text>
      </Box>
    </Section>
  );
}

function ArtifactsBlock({
  artifacts,
}: {
  artifacts?: ReadonlyArray<ModuleRunArtifact>;
}): React.ReactElement {
  if (!artifacts || artifacts.length === 0) return <Box />;
  const rows = artifacts.map((a, i) => ({
    label: a.label,
    path: a.path,
    size: a.size ?? "",
    idx: i,
  }));
  return (
    <Section title="artifacts">
      <Box paddingLeft={SPACING.md}>
        <Table
          showHeader={false}
          divider={false}
          gap={2}
          columns={[
            { key: "label", flex: 2, truncate: "end" },
            { key: "path", flex: 5, truncate: "middle" },
            { key: "size", flex: 1, align: "right", truncate: "end" },
          ]}
          rows={rows}
        />
      </Box>
    </Section>
  );
}

function Section({
  title,
  hint,
  children,
}: {
  title: string;
  hint?: string;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Box>
        <Text>{tokens.label(title)}</Text>
        {hint ? <Text> {tokens.muted(hint)}</Text> : null}
      </Box>
      {children}
    </Box>
  );
}
