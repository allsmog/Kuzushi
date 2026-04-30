/**
 * Findings view — two modes:
 *
 * - `compact`  (default · running scan): the original triage table with
 *   verdict/conf/cost/fingerprint columns, live-updated as results land.
 * - `unified` (Ink UI v2 screen 04): severity-sorted, chain-aware list for
 *   the post-scan / shell `findings` surface. Renders filter chips at the
 *   top, chain-grouped entries, and an action-hint footer.
 *
 * The unified mode virtualizes its row list: only `pageSize` loose-finding
 * rows render at once, with cursor-driven window following. On a 2000-
 * finding list this takes the per-render row count from O(N) to O(pageSize)
 * (~50 by default), which is the difference between a visibly laggy `j/k`
 * and an instant one.
 */

import { Box, Text } from "ink";
import React from "react";
import { colorVerdict } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { computeVisibleSlice } from "../hooks/useVisibleSlice.js";
import { icons } from "../icons.js";
import { useRenderCounter } from "../perf.js";
import { Divider } from "../primitives/Divider.js";
import { normalizeSeverity, severityChalk, severityStyle } from "../severity.js";
import type { ActionableFinding, ResultLine } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { ChainGroup } from "./ChainGroup.js";
import { EmptyState } from "./EmptyState.js";
import { type FilterChip, FilterChips } from "./FilterChips.js";
import { ScreenContent } from "./ScreenContent.js";

interface CompactProps {
  mode?: "compact";
  results: ResultLine[];
}

interface UnifiedProps {
  mode: "unified";
  /** Full actionable findings (post-scan). */
  findings: ReadonlyArray<ActionableFinding>;
  /**
   * Exploit chains to group by. Findings belonging to a chain render
   * inside the chain's ChainGroup; the rest render as flat rows beneath.
   */
  chains?: ReadonlyArray<{
    id: string;
    name?: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM";
    verified?: boolean;
    findingFingerprints: string[];
  }>;
  /** Read-only filter chips (wiring keyboard is a follow-up). */
  filters?: ReadonlyArray<FilterChip>;
  /**
   * Cursor index into the (severity-sorted) loose-finding list. Used only
   * for windowed rendering — if the caller doesn't pass one, the visible
   * window is anchored at the top. Kept as a prop rather than internal
   * state so the eventual j/k keybinds can drive it from shell-level state.
   */
  findingCursor?: number;
  /**
   * How many loose findings to render at once. Defaults to 50 — enough to
   * fill every standard terminal height, small enough to kill the 2000-row
   * render bill. Virtualization is a no-op when `findings.length <= pageSize`.
   */
  pageSize?: number;
}

type FindingsViewProps = CompactProps | UnifiedProps;

export const FindingsView = React.memo(FindingsViewImpl);

function FindingsViewImpl(props: FindingsViewProps): React.ReactElement {
  useRenderCounter("FindingsView");
  if (props.mode === "unified") {
    return <UnifiedFindings {...props} />;
  }
  return <CompactFindings results={props.results} />;
}

function CompactFindings({ results }: { results: ResultLine[] }): React.ReactElement {
  const triageResults = results.filter((r) => r.kind === "triage" && r.verdict);

  if (triageResults.length === 0) {
    // Infer "in progress" from the source ResultLines: any non-triage row
    // (progress tick, stage event) means the pipeline is doing work, just
    // not finished triaging. The compact view is the running-scan view.
    const total = results[0]?.total;
    const current = results.filter((r) => r.kind === "triage").length;
    const scanInProgress = results.length > 0;
    return (
      <Box paddingLeft={SPACING.md} marginTop={SPACING.sm}>
        <EmptyState
          kind="findings-compact-idle"
          context={
            scanInProgress && typeof total === "number"
              ? { scanInProgress: true, progress: { current, total } }
              : undefined
          }
        />
      </Box>
    );
  }

  return (
    <Box flexDirection="column" paddingLeft={SPACING.md} marginTop={SPACING.sm}>
      {/* Header */}
      <Text>
        {tokens.muted(pad("#", 4))}
        {tokens.muted(pad("Verdict", 20))}
        {tokens.muted(pad("Conf", 7))}
        {tokens.muted(pad("Cost", 8))}
        {tokens.muted("Fingerprint")}
      </Text>

      {/* Rows */}
      {triageResults.map((r) => {
        const idx = pad(String(r.index), 4);
        const verdict = r.verdict ? colorVerdict(r.verdict) : tokens.muted("—");
        const conf = r.confidence != null ? `${(r.confidence * 100).toFixed(0)}%` : "—";
        const cost = r.costUsd != null ? `$${r.costUsd.toFixed(3)}` : "—";
        const fp = tokens.muted(r.fingerprint.slice(0, 12));

        return (
          <Text key={r.fingerprint}>
            {tokens.muted(idx)}
            {pad(verdict, 20)}
            {pad(conf, 7)}
            {pad(cost, 8)}
            {fp}
          </Text>
        );
      })}

      {/* Summary line */}
      <Text>{""}</Text>
      <Text>
        {tokens.muted(`${triageResults.length} of ${results[0]?.total ?? "?"} triaged`)}
        {"  "}
        {tokens.dangerStrong(
          `${icons.error} ${triageResults.filter((r) => r.verdict === "tp").length} tp`,
        )}
        {"  "}
        {tokens.success(
          `${icons.success} ${triageResults.filter((r) => r.verdict === "fp").length} fp`,
        )}
        {"  "}
        {tokens.warn(
          `${icons.warning} ${triageResults.filter((r) => r.verdict === "needs_review").length} review`,
        )}
      </Text>
    </Box>
  );
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: intentionally strips ANSI escape codes to measure visible width
const ANSI_ESCAPE_RE = /\[[0-9;]*[a-zA-Z]/g;

function pad(text: string, width: number): string {
  // Strip ANSI to measure visible length, then pad
  const visible = text.replace(ANSI_ESCAPE_RE, "");
  const padding = Math.max(0, width - visible.length);
  return text + " ".repeat(padding);
}

// ---------------------------------------------------------------------------
// Unified mode — Ink UI v2 screen 04
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** Default window size for the unified findings list. See {@link UnifiedProps.pageSize}. */
const DEFAULT_PAGE_SIZE = 50;

function UnifiedFindings({
  findings,
  chains,
  filters,
  findingCursor,
  pageSize,
}: UnifiedProps): React.ReactElement {
  useRenderCounter("UnifiedFindings");
  useRegisterKeybindings([
    { keys: "/open <F-NNNN>", label: "open finding" },
    { keys: "j/k", label: "move cursor", secondary: true },
    { keys: "b", label: "back", secondary: true },
  ]);

  // Fingerprint lookup + chain-membership set are both O(findings) today;
  // memoizing on input identity lets the sort/filter chain skip when the
  // parent re-renders without changing findings (e.g. throttle tick).
  const byFingerprint = React.useMemo(() => {
    const map = new Map<string, ActionableFinding>();
    for (const f of findings) map.set(f.fingerprint, f);
    return map;
  }, [findings]);

  const chainFingerprints = React.useMemo(
    () => new Set<string>((chains ?? []).flatMap((c) => c.findingFingerprints)),
    [chains],
  );

  const loose = React.useMemo(() => {
    const out: ActionableFinding[] = [];
    for (const f of findings) {
      if (!chainFingerprints.has(f.fingerprint)) out.push(f);
    }
    // Stable sort; O(n log n) runs only when findings/chains change. The
    // virtualized renderer below stays O(pageSize) per render.
    out.sort((a, b) => severityRank(a) - severityRank(b));
    return out;
  }, [findings, chainFingerprints]);

  const counts = React.useMemo(() => tallyCounts(findings), [findings]);

  const resolvedPageSize = pageSize ?? DEFAULT_PAGE_SIZE;
  const slice = React.useMemo(
    () =>
      computeVisibleSlice({
        total: loose.length,
        cursor: findingCursor ?? 0,
        pageSize: resolvedPageSize,
      }),
    [loose.length, findingCursor, resolvedPageSize],
  );

  const resolvedChains = React.useMemo(
    () =>
      (chains ?? []).map((chain) => {
        const members: ActionableFinding[] = [];
        for (const fp of chain.findingFingerprints) {
          const match = byFingerprint.get(fp);
          if (match) members.push(match);
        }
        return { chain, members };
      }),
    [chains, byFingerprint],
  );

  const visibleLoose = React.useMemo(
    () => loose.slice(slice.top, slice.bottom),
    [loose, slice.top, slice.bottom],
  );
  const hiddenAbove = slice.top;
  const hiddenBelow = Math.max(0, loose.length - slice.bottom);

  return (
    <ScreenContent>
      <Box>
        <Text>
          {tokens.muted("◂ back   ")}
          {tokens.strong("findings")}
          {tokens.muted("   │   ")}
          <SeverityCounts counts={counts} />
          {tokens.muted(`   ${findings.length} open`)}
        </Text>
      </Box>

      <Box marginTop={SPACING.sm} flexDirection="column">
        <Text>{tokens.value("Primary action: /open F-NNNN to inspect one finding deeply.")}</Text>
        <FilterChips chips={filters ?? defaultFilters()} />
      </Box>

      <Box marginTop={SPACING.sm}>
        <Divider />
      </Box>

      {resolvedChains.map(({ chain, members }) => {
        if (members.length === 0) return null;
        return (
          <ChainGroup
            key={chain.id}
            chainId={chain.id}
            title={chain.name}
            severity={chain.severity}
            verified={chain.verified}
            findings={members}
          />
        );
      })}

      {loose.length > 0 && (
        <Box flexDirection="column" marginTop={SPACING.sm}>
          <Text>{tokens.label("ungrouped findings")}</Text>
          {hiddenAbove > 0 && (
            <Text>
              {"  "}
              {tokens.muted(`↑ ${hiddenAbove} more above`)}
            </Text>
          )}
          {visibleLoose.map((f) => (
            <LooseRow key={f.fingerprint} finding={f} />
          ))}
          {hiddenBelow > 0 && (
            <Text>
              {"  "}
              {tokens.muted(`↓ ${hiddenBelow} more below`)}
            </Text>
          )}
        </Box>
      )}

      {findings.length === 0 && <EmptyState kind="findings-never-scanned" />}

      <Box marginTop={SPACING.sm}>
        <Divider />
      </Box>
      <Box>
        <Text>{tokens.hint("j/k move   /open F-NNNN inspect   b back")}</Text>
      </Box>
    </ScreenContent>
  );
}

/**
 * Memoized per-row component. `finding` identity equality is sufficient
 * because findings are immutable snapshots in the store — if any field
 * changed, the whole object would have been replaced upstream.
 *
 * Without this memo, every parent re-render walks every visible row; with
 * it, unchanged rows short-circuit before the function body runs.
 */
const LooseRow = React.memo(
  function LooseRow({ finding }: { finding: ActionableFinding }): React.ReactElement {
    useRenderCounter("LooseRow");
    const title = finding.title ?? finding.ruleId;
    const sev = finding.displaySeverity ?? mapSeverity(finding.severity);
    const sevTag = severityInline(sev);
    return (
      <Box flexDirection="column">
        <Text>
          {"  "}
          {sevTag}
          {"  "}
          {tokens.strong(clip(title, 56))}
          {"  "}
          {tokens.muted(`[${finding.taskId || "sast"}]`)}
        </Text>
        <Text>
          {"           "}
          {tokens.muted(`${finding.filePath}:${finding.startLine}`)}
          {"  "}
          {tokens.muted(`· ${finding.verdict?.toUpperCase() ?? "—"}`)}
        </Text>
      </Box>
    );
  },
  (prev, next) => prev.finding === next.finding,
);

function SeverityCounts({
  counts,
}: {
  counts: { crit: number; high: number; med: number; low: number };
}): React.ReactElement {
  // Render with glyph+label pairs so NO_COLOR / grayscale readers still
  // see the severity tier. See src/ui/severity.ts.
  const critGlyph = severityStyle("critical").glyph;
  const highGlyph = severityStyle("high").glyph;
  const medGlyph = severityStyle("medium").glyph;
  const lowGlyph = severityStyle("low").glyph;
  return (
    <Text>
      {counts.crit > 0 ? `${severityChalk("critical")(`${critGlyph} ${counts.crit} crit`)}  ` : ""}
      {counts.high > 0 ? `${severityChalk("high")(`${highGlyph} ${counts.high} high`)}  ` : ""}
      {counts.med > 0 ? `${severityChalk("medium")(`${medGlyph} ${counts.med} med`)}  ` : ""}
      {counts.low > 0 ? `${severityChalk("low")(`${lowGlyph} ${counts.low} low`)}` : ""}
    </Text>
  );
}

function defaultFilters(): FilterChip[] {
  return [
    { key: "sev", value: "all", explicit: true },
    { key: "state", value: "open", explicit: true },
    { key: "module", value: "any" },
    { key: "since", value: "any" },
    { key: "assignee", value: "any" },
  ];
}

function tallyCounts(findings: ReadonlyArray<ActionableFinding>): {
  crit: number;
  high: number;
  med: number;
  low: number;
} {
  const counts = { crit: 0, high: 0, med: 0, low: 0 };
  for (const f of findings) {
    const sev = f.displaySeverity ?? mapSeverity(f.severity);
    if (sev === "critical") counts.crit += 1;
    else if (sev === "high") counts.high += 1;
    else if (sev === "medium") counts.med += 1;
    else counts.low += 1;
  }
  return counts;
}

function severityRank(finding: ActionableFinding): number {
  const sev = finding.displaySeverity ?? mapSeverity(finding.severity);
  return SEVERITY_ORDER[sev] ?? 99;
}

function mapSeverity(severity: string): "critical" | "high" | "medium" | "low" {
  const sev = normalizeSeverity(severity);
  return sev === "info" ? "low" : sev;
}

function severityInline(sev: "critical" | "high" | "medium" | "low"): string {
  // Glyph + label pairing so color-blind / NO_COLOR / SR users still read the tier.
  const style = severityStyle(sev);
  return severityChalk(sev)(`${style.glyph} ${style.label}`);
}

function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}…`;
}
