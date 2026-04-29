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
 *   actors                          (carlini-threat-hunt only)
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
import { useEffect, useRef } from "react";
import { formatCost, formatDuration, truncateEnd } from "../format.js";
import { BLACK_CIRCLE, STEP_GLYPH } from "../glyphs.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { useElapsed } from "../hooks.js";
import { Table } from "../primitives/Table.js";
import { normalizeSeverity, type Severity, severityChalk, severityStyle } from "../severity.js";
import type { AgentActivityLine, ModuleRunArtifact, ModuleRunStep, ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { actorLabelFromFingerprint, actorShortId, toCompactRow } from "../transcript-format.js";
import type { ActorViewFinding } from "./ActorTranscriptView.js";
import { RuleHeader } from "./RuleHeader.js";
import { ScreenContent } from "./ScreenContent.js";

interface ModuleRunViewProps {
  shell: ShellState;
  /** Project-level findings, used to render the "Findings" tail. */
  findings?: ReadonlyArray<ActorViewFinding>;
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
const MAX_LIVE_FINDING_ROWS = 5;
const MAX_COMPLETED_FINDING_ROWS = 8;

export function ModuleRunView({
  shell,
  findings = [],
  agentActivity,
  nowMs,
}: ModuleRunViewProps): React.ReactElement {
  const run = shell.moduleRun;
  const liveControls = run?.status === "running" && run.liveControl === "pause-resume";
  useRegisterKeybindings([
    { keys: "1–4", label: "drill into actor" },
    ...(liveControls
      ? [
          { keys: "p", label: "pause queued work", secondary: true },
          { keys: "r", label: "resume queued work", secondary: true },
        ]
      : []),
    { keys: "b", label: "back", secondary: true },
    { keys: "Ctrl+C", label: "interrupt", secondary: true },
  ]);

  const moduleId = run?.moduleId ?? shell.focusedModule ?? "module";
  const breadcrumb = `kuzushi/${moduleId}/run`;
  const liveElapsedMs = useElapsed(
    run?.status === "running" && nowMs == null ? run.startedAtMs : undefined,
    1000,
  );

  // O6: Notify the operator when a long run completes — terminal bell +
  // macOS notification + stderr badge. Fires once per run via a ref so
  // re-renders don't spam. Silence with KUZUSHI_QUIET_RUN_NOTIFICATIONS=1.
  const notifiedRunIdRef = useRef<string | null>(null);
  useEffect(() => {
    if (!run) return;
    const isTerminal = run.status === "done" || run.status === "aborted" || run.status === "error";
    if (!isTerminal) return;
    const runId = run.runId ?? `${run.moduleId ?? "module"}:${run.startedAtMs}`;
    if (notifiedRunIdRef.current === runId) return;
    notifiedRunIdRef.current = runId;
    if (process.env.KUZUSHI_QUIET_RUN_NOTIFICATIONS) return;
    notifyRunComplete({
      moduleId: run.moduleId ?? shell.focusedModule ?? "module",
      toolName: run.toolName ?? "tool",
      status: run.status,
      elapsedMs: Math.max(0, (run.completedAtMs ?? Date.now()) - run.startedAtMs),
    });
  }, [run, shell.focusedModule]);

  const now = nowMs ?? (run?.status === "running" ? run.startedAtMs + liveElapsedMs : Date.now());
  const elapsedMs = run ? Math.max(0, (run.completedAtMs ?? now) - run.startedAtMs) : 0;
  const elapsed = formatDuration(elapsedMs);
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
          {liveControls ? <LiveControlsHint /> : null}
          <ToolHeader run={run} />
          <TerminalRunBanner run={run} findings={findings} elapsed={elapsed} />
          <StepsBlock steps={run.steps} />
          {run.moduleId === "carlini-threat-hunt" ? (
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

function LiveControlsHint(): React.ReactElement {
  return (
    <Box marginTop={SPACING.xs} marginBottom={SPACING.xs}>
      <Text>{tokens.muted("p pause · r resume · Ctrl+C abort")}</Text>
    </Box>
  );
}

function ToolHeader({ run }: { run: NonNullable<ShellState["moduleRun"]> }): React.ReactElement {
  const label = run.displayName ?? run.toolName ?? `${run.moduleId}:run`;
  const args = run.inputSummary ? `(${truncateEnd(run.inputSummary, 56)})` : "";
  const glyph =
    run.status === "running"
      ? tokens.accent(BLACK_CIRCLE)
      : run.status === "done"
        ? tokens.success(STEP_GLYPH.done)
        : run.status === "aborted"
          ? tokens.muted("·")
          : tokens.danger("✗");
  return (
    <Box flexDirection="column" marginBottom={SPACING.sm}>
      <Text>
        {glyph} {tokens.label(label)}
        {args ? tokens.muted(args) : null}
      </Text>
      {run.status === "running" && (run.activeTaskLabel || run.findingCount != null) ? (
        <Text>
          {tokens.muted("  ")}
          {run.activeTaskLabel ? tokens.muted(`task ${run.activeTaskLabel}`) : null}
          {run.activeTaskLabel && run.findingCount != null ? tokens.muted(" · ") : null}
          {run.findingCount != null
            ? tokens.value(`${run.findingCount} finding${run.findingCount === 1 ? "" : "s"}`)
            : null}
        </Text>
      ) : null}
    </Box>
  );
}

function TerminalRunBanner({
  run,
  findings,
  elapsed,
}: {
  run: NonNullable<ShellState["moduleRun"]>;
  findings: ReadonlyArray<ActorViewFinding>;
  elapsed: string;
}): React.ReactElement {
  if (run.status === "running") return <Box />;
  const label = run.displayName ?? run.toolName ?? `${run.moduleId}:run`;
  const findingCount = run.findingCount ?? scopedFindings(run, findings).length;
  const findingText = `${findingCount} finding${findingCount === 1 ? "" : "s"}`;
  const cost = run.costUsd != null ? formatCost(run.costUsd) : "—";
  const outcome =
    run.status === "done" ? "complete" : run.status === "aborted" ? "aborted" : "failed";
  const color =
    run.status === "done" ? tokens.success : run.status === "aborted" ? tokens.warn : tokens.danger;
  const scanOnlyNote =
    run.postProcessMode === "scan-only" && run.status === "done" && findingCount > 0
      ? "scan-only: saved as needs_review; triage pending"
      : null;

  return (
    <Box flexDirection="column" marginBottom={SPACING.sm}>
      <Text>
        {color(`${label} ${outcome}`)} {tokens.muted("·")} {tokens.value(findingText)}
        {tokens.muted(" · ")}
        {tokens.value(cost)}
        {tokens.muted(" · ")}
        {tokens.value(elapsed)}
      </Text>
      {scanOnlyNote ? <Text>{tokens.muted(`  ${scanOnlyNote}`)}</Text> : null}
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

export interface ActorRow {
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
    if (fp.startsWith("carlini-threat-hunt:")) fingerprints.push(fp);
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

/** O3: surface a "waiting on actor N of M" pause line when activity stalls. */
const STALLED_ACTOR_THRESHOLD_MS = 30_000;

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
  const pauseHint = computePauseHint(rows);
  return (
    <Section title="actors" hint="1–4 drill into actor">
      <Box flexDirection="column" paddingLeft={SPACING.md}>
        {pauseHint ? <Text>{tokens.muted(pauseHint)}</Text> : null}
        {rows.map((row) => (
          <ActorCard key={row.fingerprint} row={row} />
        ))}
      </Box>
    </Section>
  );
}

/**
 * O3: build the optional "Currently waiting on actor N of M — last activity Ys ago"
 * hint. Returns null when no actor is meaningfully stalled (latest activity is
 * fresh, or no `tsMs` was stamped on any line). Exported for unit tests.
 */
export function computePauseHint(rows: ReadonlyArray<ActorRow>): string | null {
  const total = rows.length;
  if (total === 0) return null;
  const now = Date.now();
  let stalledIndex = -1;
  let stalledMs = 0;
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i]!;
    const latest = row.running ?? row.lastCompleted;
    const ts = latest?.tsMs;
    if (typeof ts !== "number") continue;
    const age = now - ts;
    if (age >= STALLED_ACTOR_THRESHOLD_MS && age > stalledMs) {
      stalledIndex = i;
      stalledMs = age;
    }
  }
  if (stalledIndex === -1) return null;
  const seconds = Math.round(stalledMs / 1000);
  return `Currently waiting on actor ${stalledIndex + 1} of ${total} — last activity ${seconds}s ago`;
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
  findings: ReadonlyArray<ActorViewFinding>;
}): React.ReactElement {
  if (!findings || findings.length === 0) return <Box />;
  const scoped = scopedFindings(run, findings);
  const maxRows = run.status === "running" ? MAX_LIVE_FINDING_ROWS : MAX_COMPLETED_FINDING_ROWS;
  const ordered = aliasedFindingRows(scoped);
  const slice = ordered.slice(0, maxRows).map(({ alias, finding }) => ({
    severity: severityTokenForFinding(finding),
    id: alias,
    path: `${finding.filePath}:${finding.startLine}`,
    title: findingHeadline(finding),
  }));
  if (slice.length === 0) return <Box />;
  const hidden = Math.max(0, ordered.length - slice.length);
  return (
    <Section title="findings">
      <Box flexDirection="column" paddingLeft={SPACING.md}>
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
        {hidden > 0 ? <Text>{tokens.muted(`+${hidden} more`)}</Text> : null}
      </Box>
    </Section>
  );
}

function scopedFindings(
  run: NonNullable<ShellState["moduleRun"]>,
  findings: ReadonlyArray<ActorViewFinding>,
): ActorViewFinding[] {
  if (run.moduleId !== "carlini-threat-hunt") return [...findings];
  return findings.filter((f) => f.actorFingerprint?.startsWith("carlini-threat-hunt:"));
}

function aliasedFindingRows(
  findings: ReadonlyArray<ActorViewFinding>,
): Array<{ alias: string; finding: ActorViewFinding }> {
  return [...findings].sort(compareFindingsForDisplay).map((finding, index) => ({
    alias: `F-${String(index + 1).padStart(4, "0")}`,
    finding,
  }));
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function compareFindingsForDisplay(a: ActorViewFinding, b: ActorViewFinding): number {
  const severityDelta = SEVERITY_RANK[displaySeverity(a)] - SEVERITY_RANK[displaySeverity(b)];
  if (severityDelta !== 0) return severityDelta;
  return a.fingerprint.localeCompare(b.fingerprint);
}

function displaySeverity(finding: ActorViewFinding): Severity {
  return normalizeSeverity(finding.displaySeverity ?? finding.severity);
}

function severityTokenForFinding(finding: ActorViewFinding): string {
  const severity = displaySeverity(finding);
  const style = severityStyle(severity);
  return severityChalk(severity)(`${style.glyph} ${style.label}`);
}

const SCAN_ONLY_PLACEHOLDER_RE = /captured in scan-only mode/i;

function findingHeadline(finding: ActorViewFinding): string {
  const raw = finding.title ?? finding.message ?? finding.rationale;
  if (raw && !SCAN_ONLY_PLACEHOLDER_RE.test(raw)) return raw;
  return finding.ruleId ?? finding.taskId ?? "scan-only finding";
}

function MetaRow({ run }: { run: NonNullable<ShellState["moduleRun"]> }): React.ReactElement {
  const cost = run.costUsd != null ? formatCost(run.costUsd) : "—";
  const model = run.model ? truncateEnd(run.model, 44) : "default";
  // O4: Surface effort + thinking state alongside model. Operators
  // pinning Opus 4.7 with effort=max care that the run actually inherited
  // the override; "model default" alone gave no signal whether
  // /set effort max actually took effect.
  const effort = run.effort ?? "default";
  const thinking = run.thinkingDisabled ? "disabled" : "enabled";
  return (
    <Section title="run facts">
      <Box paddingLeft={SPACING.md}>
        <Text>
          {tokens.muted("cost     ")}
          {tokens.value(cost)}
          {tokens.muted("    model ")}
          {tokens.value(model)}
          {tokens.muted("    effort ")}
          {tokens.value(effort)}
          {tokens.muted("    thinking ")}
          {tokens.value(thinking)}
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

/**
 * Surface a long-run completion to the operator via three independent
 * channels — terminal bell (BEL byte), one-line stderr badge, and a macOS
 * NotificationCenter ping (osascript) on darwin. Each channel is best-effort
 * and silent on failure. Operators can disable with KUZUSHI_QUIET_RUN_NOTIFICATIONS=1.
 */
export function notifyRunComplete(opts: {
  moduleId: string;
  toolName: string;
  status: "done" | "aborted" | "error" | string;
  elapsedMs: number;
}): void {
  // Skip notifications for short runs — under 30s the operator was almost
  // certainly watching the terminal already, and the bell becomes noise.
  if (opts.elapsedMs < 30_000) return;
  const verb = opts.status === "done" ? "complete" : opts.status;
  const seconds = Math.round(opts.elapsedMs / 1000);
  const elapsed = seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  // Terminal bell. Most terminals flash + sound; many operators will have
  // the bell muted, in which case the stderr badge is the actionable signal.
  try {
    process.stderr.write("\x07");
  } catch {
    /* best-effort */
  }
  // Stderr badge — survives the Ink stdout takeover.
  try {
    process.stderr.write(
      `\n[kuzushi] ${opts.moduleId}:${opts.toolName.split(":").slice(-1)[0]} ${verb} after ${elapsed}.\n`,
    );
  } catch {
    /* best-effort */
  }
  // macOS NotificationCenter via osascript. Keeps the operator informed
  // when they've switched to a different app during a 20-minute hunt.
  if (process.platform === "darwin") {
    try {
      const { spawn } = require("node:child_process") as typeof import("node:child_process");
      const title = `Kuzushi ${verb}`;
      const message = `${opts.moduleId}:${opts.toolName.split(":").slice(-1)[0]} (${elapsed})`;
      // Detached so we don't hold up the shell exit. stdio:ignore so a
      // missing osascript (e.g. CI containers) is silent.
      const child = spawn(
        "osascript",
        [
          "-e",
          `display notification "${escapeAppleScript(message)}" with title "${escapeAppleScript(title)}"`,
        ],
        { stdio: "ignore", detached: true },
      );
      child.unref();
    } catch {
      /* best-effort — osascript might be missing or sandboxed */
    }
  }
}

/** Minimal AppleScript string-escape — strips double quotes and backslashes. */
function escapeAppleScript(s: string): string {
  return s.replace(/[\\"']/g, "");
}
