/**
 * ActorTranscriptView — full per-actor transcript drilled into from
 * `ModuleRunView`. Mirrors Claude Code / opencode's transcript shape
 * with `● Tool(args)` headers, `⎿ result` body lines, `✻ Thinking`
 * excerpts, and `★ Finding` synthesized rows.
 *
 * Reads from `shell.agentActivity[shell.focusedActor]` (live activity
 * stream) and from a `findings` prop the parent threads in (filtered
 * via `actorFingerprint`).
 */

import { Box, Text } from "ink";
import type React from "react";
import { formatCost, truncateEnd } from "../format.js";
import { BLACK_CIRCLE, FINDING_GLYPH, LOWER_HOOK, THINKING_GLYPH } from "../glyphs.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { useTerminalSize } from "../hooks/useTerminalSize.js";
import type { AgentActivityLine, ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import {
  actorLabelFromFingerprint,
  actorShortId,
  toTranscriptEntry,
} from "../transcript-format.js";
import { RuleHeader } from "./RuleHeader.js";
import { ScreenContent } from "./ScreenContent.js";

/**
 * Narrow shape that both `Finding` (scanner output) and
 * `ActionableFinding` (post-summary) satisfy. The view only needs the
 * fields below; accepting either shape lets `CopilotShell` pass through
 * `summary.actionableFindings` for completed runs without a translation.
 */
export interface ActorViewFinding {
  fingerprint: string;
  severity: string;
  displaySeverity?: "critical" | "high" | "medium" | "low";
  taskId?: string;
  filePath: string;
  startLine: number;
  ruleId?: string;
  verdict?: string;
  /** Live findings expose `message`; ActionableFinding uses `rationale`/`title`. */
  message?: string;
  rationale?: string;
  title?: string;
  actorFingerprint?: string;
}

interface ActorTranscriptViewProps {
  shell: ShellState;
  findings?: ReadonlyArray<ActorViewFinding>;
  /**
   * Live agent activity map (per-actor fingerprints → last-N lines).
   * Threaded from the UIStore — the same map is read by ModuleRunView.
   */
  agentActivity?: ReadonlyMap<string, ReadonlyArray<AgentActivityLine>>;
  /** Visible-rows cap derived from terminal height — falls back to 24. */
  maxRows?: number;
}

export function ActorTranscriptView({
  shell,
  findings = [],
  agentActivity,
  maxRows = 24,
}: ActorTranscriptViewProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "b", label: "back" },
    { keys: "q", label: "back", secondary: true },
    { keys: "Ctrl+C", label: "interrupt", secondary: true },
  ]);

  const { columns } = useTerminalSize();
  // Body lines previously truncated at a fixed 160 chars - overflowed an
  // 80-col terminal hard. Heads at 80 wasted half the pane at 200 cols.
  const headClipWidth = Math.max(40, Math.min(columns - 6, 160));
  const bodyClipWidth = Math.max(40, Math.min(columns - 8, 200));

  const fingerprint = shell.focusedActor ?? null;
  const allFingerprints = collectThreatHuntFingerprints(agentActivity);
  const index = fingerprint ? allFingerprints.indexOf(fingerprint) : -1;
  const shortId = fingerprint && index >= 0 ? actorShortId(fingerprint, index) : "—";
  const breadcrumb = `kuzushi/${shell.moduleRun?.moduleId ?? shell.focusedModule ?? "module"}/run/${shortId}`;

  const lines = fingerprint ? (agentActivity?.get(fingerprint) ?? []) : [];
  const actorFindings = fingerprint
    ? findings.filter((f) => f.actorFingerprint === fingerprint)
    : [];
  const turnTotal = lines.length;

  const cost = shell.moduleRun?.costUsd ?? 0;
  const subtitle = fingerprint
    ? `turn ${turnTotal}/${turnTotal} · ${formatCost(cost)} · ${FINDING_GLYPH} ${actorFindings.length} findings`
    : "(no actor focused)";

  return (
    <ScreenContent>
      <RuleHeader breadcrumb={breadcrumb} status={subtitle} />
      {fingerprint ? (
        <Header label={actorLabelFromFingerprint(fingerprint)} subtitle={subtitle} />
      ) : null}
      <Transcript
        lines={lines}
        findings={actorFindings}
        maxRows={maxRows}
        headClipWidth={headClipWidth}
        bodyClipWidth={bodyClipWidth}
      />
      <OtherActors current={fingerprint} fingerprints={allFingerprints} findings={findings} />
    </ScreenContent>
  );
}

function Header({ label, subtitle }: { label: string; subtitle: string }): React.ReactElement {
  return (
    <Box flexDirection="column" marginBottom={SPACING.sm}>
      <Text>
        {tokens.accent(BLACK_CIRCLE)} {tokens.label(`Threat Hunt(. as <${label}>)`)}
      </Text>
      <Box paddingLeft={SPACING.md}>
        <Text>{tokens.muted(subtitle)}</Text>
      </Box>
    </Box>
  );
}

function findingHeadline(f: ActorViewFinding): string {
  return f.title ?? f.message ?? f.rationale ?? "(no title)";
}

function Transcript({
  lines,
  findings,
  maxRows,
  headClipWidth,
  bodyClipWidth,
}: {
  lines: ReadonlyArray<AgentActivityLine>;
  findings: ReadonlyArray<ActorViewFinding>;
  maxRows: number;
  headClipWidth: number;
  bodyClipWidth: number;
}): React.ReactElement {
  const tail = lines.slice(-maxRows);
  const entries = tail.map((line, idx) => ({
    entry: toTranscriptEntry(line),
    // Combine kind + tool + position in the *original* lines array so the
    // key stays stable across re-renders even when the head text shifts.
    key: `${line.kind}:${line.toolName ?? "_"}:${lines.length - tail.length + idx}`,
  }));

  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      {entries.length === 0 ? (
        <Text>{tokens.muted("(no activity yet)")}</Text>
      ) : (
        entries.map(({ entry, key }) => (
          <EntryRow
            key={key}
            glyph={entry.glyph}
            head={entry.head}
            body={entry.body}
            inProgress={entry.inProgress}
            headClipWidth={headClipWidth}
            bodyClipWidth={bodyClipWidth}
          />
        ))
      )}
      {findings.map((f) => (
        <EntryRow
          key={`f:${f.fingerprint}`}
          glyph={FINDING_GLYPH}
          head={`Finding — ${truncateEnd(findingHeadline(f), Math.max(20, headClipWidth - 11))}`}
          body={`${f.severity} · ${f.filePath}:${f.startLine}`}
          headClipWidth={headClipWidth}
          bodyClipWidth={bodyClipWidth}
        />
      ))}
    </Box>
  );
}

function EntryRow({
  glyph,
  head,
  body,
  inProgress,
  headClipWidth,
  bodyClipWidth,
}: {
  glyph: string;
  head: string;
  body?: string;
  inProgress?: boolean;
  headClipWidth: number;
  bodyClipWidth: number;
}): React.ReactElement {
  const glyphColor =
    glyph === LOWER_HOOK
      ? tokens.muted
      : glyph === FINDING_GLYPH
        ? tokens.warn
        : glyph === THINKING_GLYPH
          ? tokens.tertiary
          : inProgress
            ? tokens.warn
            : tokens.accent;
  const headColor = glyph === FINDING_GLYPH ? tokens.warn : tokens.value;
  return (
    <Box flexDirection="column">
      <Text>
        {glyphColor(glyph)} {headColor(truncateEnd(head, headClipWidth))}
      </Text>
      {body ? (
        <Box paddingLeft={SPACING.md}>
          <Text>{tokens.muted(truncateEnd(body, bodyClipWidth))}</Text>
        </Box>
      ) : null}
    </Box>
  );
}

function collectThreatHuntFingerprints(
  activity: ReadonlyMap<string, ReadonlyArray<AgentActivityLine>> | undefined,
): string[] {
  const out: string[] = [];
  if (!activity) return out;
  for (const fp of activity.keys()) {
    if (fp.startsWith("threat-hunt:")) out.push(fp);
  }
  out.sort();
  return out;
}

function OtherActors({
  current,
  fingerprints,
  findings,
}: {
  current: string | null;
  fingerprints: ReadonlyArray<string>;
  findings: ReadonlyArray<ActorViewFinding>;
}): React.ReactElement | null {
  const others = fingerprints.filter((fp) => fp !== current);
  if (others.length === 0) return null;
  const cells = others.map((fp, i) => {
    const idx = fingerprints.indexOf(fp);
    const shortId = actorShortId(fp, idx >= 0 ? idx : i);
    const count = findings.filter((f) => f.actorFingerprint === fp).length;
    return count > 0 ? `${shortId} ${FINDING_GLYPH}${count}` : `${shortId} queued`;
  });
  return (
    <Box marginTop={SPACING.md}>
      <Text>
        {tokens.muted("Other actors    ")}
        {tokens.value(cells.join(" · "))}
      </Text>
    </Box>
  );
}
