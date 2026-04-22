/**
 * ThreatSummaryExport — Phase C.5 summary + drives + export paths.
 *
 * The "end of the stack" view in the Phase C cycle. Three blocks:
 *
 *   1. Counts — the randori-emitted `summary.total`, severity bar chart,
 *      and STRIDE-category bar chart. Bars are proportional within each
 *      chart so a lopsided distribution reads at a glance.
 *
 *   2. Drives — a static panel naming the downstream consumers of this
 *      threat model (threat-hunt, sast/taint-iris, variant-hunter,
 *      report). Each gets a one-line "what it consumes" description so
 *      operators see why the model is worth maintaining.
 *
 *   3. Artifact paths — real on-disk locations where the model lives so
 *      operators can version-control / diff them: `.kuzushi/threat-model.json`
 *      (the persistent operator-editable one), and the per-run pasta-*
 *      intermediates under `.kuzushi/runs/<runId>/` when available.
 */

import { Box, Text } from "ink";
import type React from "react";
import type { StrideCategory } from "../../agents/tasks/threat-modeling/types.js";
import { formatThreatModelSource } from "../../copilot/threat-model-loader.js";
import type { ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { ContextStrip } from "./ContextStrip.js";

const STRIDE_ORDER: ReadonlyArray<{ category: StrideCategory; label: string }> = [
  { category: "spoofing", label: "Spoofing" },
  { category: "tampering", label: "Tampering" },
  { category: "repudiation", label: "Repudiation" },
  { category: "information-disclosure", label: "Info-disclosure" },
  { category: "denial-of-service", label: "Denial-of-service" },
  { category: "elevation-of-privilege", label: "Elevation" },
];

const SEVERITY_ORDER: ReadonlyArray<string> = ["critical", "high", "medium", "low"];

const DRIVES: ReadonlyArray<{ module: string; consumes: string }> = [
  {
    module: "threat-hunt",
    consumes: "attacker stories + DFD elements → per-actor hunt budgets",
  },
  {
    module: "sast/taint-iris",
    consumes: "trust boundaries → taint source/sink grounding",
  },
  {
    module: "variant-hunter",
    consumes: "STRIDE threats → signature templates for lifted findings",
  },
  {
    module: "report",
    consumes: "narrative overview + criticality buckets → executive summary",
  },
];

interface ThreatSummaryExportProps {
  shell: ShellState;
}

export function ThreatSummaryExport({ shell }: ThreatSummaryExportProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "1", label: "dfd", secondary: true },
    { keys: "2", label: "stride", secondary: true },
    { keys: "3", label: "stories", secondary: true },
    { keys: "4", label: "scope", secondary: true },
    { keys: "5", label: "summary" },
    { keys: "q", label: "back", secondary: true },
  ]);
  const tm = shell.threatModel;
  if (!tm) return <EmptyState />;

  const totalThreats = tm.summary?.total ?? tm.threats.length;

  return (
    <Box flexDirection="column" paddingLeft={SPACING.md} marginBottom={SPACING.sm}>
      <ContextStrip
        status={[`${totalThreats} threats`, `${tm.dfd.elements.length} elements`]}
        subtitle={
          shell.threatModelSource
            ? formatThreatModelSource({
                sourcePath: shell.threatModelSource.path,
                mtimeMs: shell.threatModelSource.mtimeMs,
              })
            : undefined
        }
      />

      <Counts
        total={totalThreats}
        bySeverity={tm.summary?.bySeverity ?? {}}
        byCategory={tm.summary?.byCategory}
      />

      <Drives />

      <Artifacts shell={shell} />
    </Box>
  );
}

function EmptyState(): React.ReactElement {
  return (
    <Box flexDirection="column" paddingLeft={SPACING.md} marginBottom={SPACING.sm}>
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("threat summary")}
      </Text>
      <Box marginTop={SPACING.sm}>
        <Text>
          {tokens.warn("No threat model loaded. Run a scan with threat modelling enabled first.")}
        </Text>
      </Box>
    </Box>
  );
}


function Counts({
  total,
  bySeverity,
  byCategory,
}: {
  total: number;
  bySeverity: Record<string, number>;
  byCategory: Record<StrideCategory, number> | undefined;
}): React.ReactElement {
  const maxSev = Math.max(1, ...SEVERITY_ORDER.map((k) => bySeverity[k] ?? 0));
  const maxCat = Math.max(1, ...STRIDE_ORDER.map((s) => byCategory?.[s.category] ?? 0));
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label(`counts · ${total} threats total`)}</Text>

      <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.lg}>
        <Text>{tokens.muted("severity")}</Text>
        {SEVERITY_ORDER.map((tier) => {
          const n = bySeverity[tier] ?? 0;
          return (
            <Text key={tier}>
              {"   "}
              {severityBadge(tier)}
              {"  "}
              {tokens.muted(`${n}`.padStart(3))}
              {"  "}
              {bar(n, maxSev, tier)}
            </Text>
          );
        })}
      </Box>

      <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.lg}>
        <Text>{tokens.muted("STRIDE category")}</Text>
        {STRIDE_ORDER.map((s) => {
          const n = byCategory?.[s.category] ?? 0;
          return (
            <Text key={s.category}>
              {"   "}
              {tokens.value(s.label.padEnd(18))}
              {tokens.muted(`${n}`.padStart(3))}
              {"  "}
              {bar(n, maxCat, "info")}
            </Text>
          );
        })}
      </Box>
    </Box>
  );
}

function severityBadge(tier: string): string {
  switch (tier) {
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

function bar(n: number, max: number, colorKey: string): string {
  if (n === 0) return tokens.muted("·");
  const width = 24;
  const filled = Math.max(1, Math.round((n / max) * width));
  const segment = "\u2588".repeat(filled);
  switch (colorKey) {
    case "critical":
      return tokens.dangerStrong(segment);
    case "high":
      return tokens.danger(segment);
    case "medium":
      return tokens.warn(segment);
    case "low":
      return tokens.info(segment);
    default:
      return tokens.accent(segment);
  }
}

function Drives(): React.ReactElement {
  const moduleWidth = Math.max(...DRIVES.map((d) => d.module.length));
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("drives")}</Text>
      <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.lg}>
        {DRIVES.map((d) => (
          <Text key={d.module}>
            {tokens.accent(d.module.padEnd(moduleWidth + 2))}
            {tokens.muted(d.consumes)}
          </Text>
        ))}
      </Box>
    </Box>
  );
}

function Artifacts({ shell }: { shell: ShellState }): React.ReactElement {
  const paths: Array<{ label: string; path: string; note?: string }> = [];
  if (shell.threatModelSource) {
    paths.push({
      label: "persistent",
      path: shell.threatModelSource.path,
      note: "operator-editable · loaded by randori + threat-hunt",
    });
  } else {
    paths.push({
      label: "persistent",
      path: ".kuzushi/threat-model.json",
      note: "(not yet written — will be created on first randori run)",
    });
  }
  paths.push({
    label: "per-run",
    path: ".kuzushi/runs/<runId>/threat-model.json",
    note: "fallback when persistent doesn't exist",
  });
  paths.push({
    label: "stages",
    path: ".kuzushi/<artifactDir>/pasta-s1..s4.json",
    note: "randori S1..S4 intermediates",
  });
  paths.push({
    label: "narrative",
    path: ".kuzushi/<artifactDir>/pasta-narrative.json",
    note: "overview / attacker stories / criticality calibration",
  });

  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("artifact paths")}</Text>
      <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.lg}>
        {paths.map((p) => (
          <Box key={p.path} flexDirection="column" marginBottom={SPACING.sm}>
            <Text>
              {tokens.muted(p.label.padEnd(12))}
              {tokens.value(shortPath(p.path))}
            </Text>
            {p.note ? (
              <Text>
                {tokens.muted(" ".repeat(12))}
                {tokens.hint(p.note)}
              </Text>
            ) : null}
          </Box>
        ))}
      </Box>
    </Box>
  );
}


function shortPath(abs: string): string {
  const home = process.env["HOME"];
  if (home && abs.startsWith(home)) return `~${abs.slice(home.length)}`;
  return abs;
}
