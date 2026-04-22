/**
 * Findings view — two modes:
 *
 * - `compact`  (default · running scan): the original triage table with
 *   verdict/conf/cost/fingerprint columns, live-updated as results land.
 * - `unified` (Ink UI v2 screen 04): severity-sorted, chain-aware list for
 *   the post-scan / shell `findings` surface. Renders filter chips at the
 *   top, chain-grouped entries, and an action-hint footer.
 */

import { Box, Text, useStdout } from "ink";
import React from "react";
import { colorVerdict } from "../format.js";
import { icons } from "../icons.js";
import type { ActionableFinding, ResultLine } from "../state.js";
import { tokens } from "../tokens.js";
import { ChainGroup } from "./ChainGroup.js";
import { type FilterChip, FilterChips } from "./FilterChips.js";

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
}

type FindingsViewProps = CompactProps | UnifiedProps;

export const FindingsView = React.memo(_FindingsView);

function _FindingsView(props: FindingsViewProps): React.ReactElement {
  if (props.mode === "unified") {
    return <UnifiedFindings {...props} />;
  }
  return <CompactFindings results={props.results} />;
}

function CompactFindings({ results }: { results: ResultLine[] }): React.ReactElement {
  const triageResults = results.filter((r) => r.kind === "triage" && r.verdict);

  if (triageResults.length === 0) {
    return (
      <Box paddingLeft={2} marginTop={1}>
        <Text>{tokens.muted("No findings triaged yet...")}</Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column" paddingLeft={2} marginTop={1}>
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
const ANSI_ESCAPE_RE = /\u001b\[[0-9;]*[a-zA-Z]/g;

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

function UnifiedFindings({ findings, chains, filters }: UnifiedProps): React.ReactElement {
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 120;
  const narrow = columns < 110;
  const chainFingerprints = new Set<string>((chains ?? []).flatMap((c) => c.findingFingerprints));
  const looseAll = findings
    .filter((f) => !chainFingerprints.has(f.fingerprint))
    .sort((a, b) => severityRank(a) - severityRank(b));
  const loose = looseAll.slice(0, narrow ? 6 : 10);

  const counts = tallyCounts(findings);

  return (
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Box>
        <Text>
          {tokens.muted("\u25C2 back   ")}
          {tokens.strong("findings")}
          {tokens.muted("   \u2502   ")}
          <SeverityCounts counts={counts} />
          {tokens.muted(`   ${findings.length} open`)}
        </Text>
      </Box>

      <Box marginTop={1} flexDirection="column">
        <Text>{tokens.strong("Primary action: /open F-NNNN to inspect one finding deeply.")}</Text>
        <FilterChips chips={filters ?? defaultFilters()} />
      </Box>

      <Box marginTop={1}>
        <Text>{tokens.tertiary("\u2500".repeat(78))}</Text>
      </Box>

      {(chains ?? []).map((chain) => {
        const members = chain.findingFingerprints
          .map((fp) => findings.find((f) => f.fingerprint === fp))
          .filter((f): f is ActionableFinding => Boolean(f));
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
        <Box flexDirection="column" marginTop={1}>
          {loose.map((f) => (
            <LooseRow key={f.fingerprint} finding={f} />
          ))}
        </Box>
      )}
      {looseAll.length > loose.length ? (
        <Box marginTop={1}>
          <Text>
            {tokens.muted(
              `${looseAll.length - loose.length} additional loose findings hidden to reduce noise.`,
            )}
          </Text>
        </Box>
      ) : null}

      {findings.length === 0 && (
        <Box flexDirection="column" marginTop={1} paddingLeft={2}>
          <Text>{tokens.muted("No actionable findings yet.")}</Text>
          <Text>
            {tokens.hint("Try /use <module>, run a scan tool, then return with /findings.")}
          </Text>
        </Box>
      )}

      <Box marginTop={1}>
        <Text>{tokens.tertiary("\u2500".repeat(78))}</Text>
      </Box>
      <Box>
        <Text>
          {tokens.hint("Primary: /open <alias>")}
          {"   "}
          {tokens.muted("Secondary: /filter · e export · a assign · s suppress")}
        </Text>
      </Box>
    </Box>
  );
}

function LooseRow({ finding }: { finding: ActionableFinding }): React.ReactElement {
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
}

function SeverityCounts({
  counts,
}: {
  counts: { crit: number; high: number; med: number; low: number };
}): React.ReactElement {
  return (
    <Text>
      {counts.crit > 0 ? `${tokens.dangerStrong(`${counts.crit} crit`)}  ` : ""}
      {counts.high > 0 ? `${tokens.danger(`${counts.high} high`)}  ` : ""}
      {counts.med > 0 ? `${tokens.warn(`${counts.med} med`)}  ` : ""}
      {counts.low > 0 ? `${tokens.muted(`${counts.low} low`)}` : ""}
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
  const norm = severity.toLowerCase();
  if (norm.includes("crit")) return "critical";
  if (norm.includes("high")) return "high";
  if (norm.includes("med")) return "medium";
  return "low";
}

function severityInline(sev: "critical" | "high" | "medium" | "low"): string {
  switch (sev) {
    case "critical":
      return tokens.dangerStrong("CRIT");
    case "high":
      return tokens.danger("HIGH");
    case "medium":
      return tokens.warn("MED ");
    default:
      return tokens.muted("LOW ");
  }
}

function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}\u2026`;
}
