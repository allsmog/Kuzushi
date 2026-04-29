/**
 * ThreatStrideMatrix — Phase C.2 STRIDE × element heat matrix.
 *
 * Rows are DFD elements; columns are the six STRIDE categories (S / T / R /
 * I / D / E). Each cell renders the worst impact among threats targeting
 * `(element, category)` as a shaded block. Below the matrix: an impact ×
 * likelihood pivot so operators can see where "crit / high" concentrates.
 *
 * The cell math is factored out as pure helpers so it's unit-testable
 * (`computeStrideCell` / `computeImpactLikelihoodPivot`).
 */

import { Box, Text } from "ink";
import type React from "react";
import type {
  DfdNode,
  StrideCategory,
  StrideThreat,
} from "../../agents/tasks/threat-modeling/types.js";
import { formatThreatModelSource } from "../../copilot/threat-model-loader.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import type { ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { ContextStrip } from "./ContextStrip.js";
import { EmptyState as EmptyStateCard } from "./EmptyState.js";
import { ScreenContent } from "./ScreenContent.js";

// ---------------------------------------------------------------------------
// Constants + types exported for the test file
// ---------------------------------------------------------------------------

export const STRIDE_COLUMNS: ReadonlyArray<{
  category: StrideCategory;
  letter: string;
  label: string;
}> = [
  { category: "spoofing", letter: "S", label: "Spoofing" },
  { category: "tampering", letter: "T", label: "Tampering" },
  { category: "repudiation", letter: "R", label: "Repudiation" },
  { category: "information-disclosure", letter: "I", label: "Info-disclosure" },
  { category: "denial-of-service", letter: "D", label: "Denial-of-service" },
  { category: "elevation-of-privilege", letter: "E", label: "Elevation" },
];

type ThreatImpact = StrideThreat["impact"];
type ThreatLikelihood = StrideThreat["likelihood"];

export type CellImpact = ThreatImpact | null;

const IMPACT_RANK: Record<ThreatImpact, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Worst impact across the threats matching an (elementId, category) cell.
 * Returns null when no threats target that intersection.
 */
export function computeStrideCell(
  threats: ReadonlyArray<StrideThreat>,
  elementId: string,
  category: StrideCategory,
): CellImpact {
  let best: CellImpact = null;
  for (const t of threats) {
    const targets = t.targetElementIds ?? (t.elementId ? [t.elementId] : []);
    if (!targets.includes(elementId) || t.category !== category) continue;
    if (best === null || IMPACT_RANK[t.impact] > IMPACT_RANK[best]) {
      best = t.impact;
    }
  }
  return best;
}

/**
 * Impact × likelihood pivot: counts per (impact, likelihood) pair. Useful
 * as the "where does crit / high sit?" side-read below the main matrix.
 */
export function computeImpactLikelihoodPivot(
  threats: ReadonlyArray<StrideThreat>,
): Record<ThreatImpact, Record<ThreatLikelihood, number>> {
  const pivot: ReturnType<typeof computeImpactLikelihoodPivot> = {
    critical: { high: 0, medium: 0, low: 0 },
    high: { high: 0, medium: 0, low: 0 },
    medium: { high: 0, medium: 0, low: 0 },
    low: { high: 0, medium: 0, low: 0 },
  };
  for (const t of threats) pivot[t.impact][t.likelihood] += 1;
  return pivot;
}

/** ASCII shade glyph for a cell impact. Empty when no threat. */
export function cellGlyph(impact: CellImpact): string {
  switch (impact) {
    case "critical":
      return "\u2588"; // █
    case "high":
      return "\u2593"; // ▓
    case "medium":
      return "\u2592"; // ▒
    case "low":
      return "\u2591"; // ░
    default:
      return "\u00B7"; // ·
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface ThreatStrideMatrixProps {
  shell: ShellState;
}

export function ThreatStrideMatrix({ shell }: ThreatStrideMatrixProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "1", label: "dfd", secondary: true },
    { keys: "2", label: "stride" },
    { keys: "3", label: "stories", secondary: true },
    { keys: "4", label: "scope", secondary: true },
    { keys: "5", label: "summary", secondary: true },
    { keys: "q", label: "back", secondary: true },
  ]);
  const tm = shell.threatModel;
  if (!tm) return <EmptyState />;

  const elements = tm.dfd.nodes ?? [];
  const threats = tm.threats ?? [];
  // Stable but operator-useful ordering: elements that actually have at least
  // one threat come first (sorted by threat count desc), then the rest.
  const elementThreatCount = new Map<string, number>();
  for (const t of threats) {
    for (const targetId of t.targetElementIds ?? (t.elementId ? [t.elementId] : [])) {
      elementThreatCount.set(targetId, (elementThreatCount.get(targetId) ?? 0) + 1);
    }
  }
  const sortedElements = [...elements].sort((a, b) => {
    const ca = elementThreatCount.get(a.id) ?? 0;
    const cb = elementThreatCount.get(b.id) ?? 0;
    if (ca !== cb) return cb - ca;
    return a.id.localeCompare(b.id);
  });

  const pivot = computeImpactLikelihoodPivot(threats);
  const idWidth = Math.max(3, ...sortedElements.map((e) => e.id.length));
  const nameWidth = Math.max(4, ...sortedElements.map((e) => Math.min(24, e.name.length)));

  return (
    <ScreenContent>
      <ContextStrip
        status={[`${elements.length} nodes`, `${threats.length} threats`]}
        subtitle={
          shell.threatModelSource
            ? formatThreatModelSource({
                sourcePath: shell.threatModelSource.path,
                mtimeMs: shell.threatModelSource.mtimeMs,
              })
            : undefined
        }
      />

      <Box flexDirection="column" marginTop={SPACING.sm}>
        <MatrixHeaderRow idWidth={idWidth} nameWidth={nameWidth} />
        {sortedElements.map((el) => (
          <MatrixRow
            key={el.id}
            element={el}
            threats={threats}
            idWidth={idWidth}
            nameWidth={nameWidth}
          />
        ))}
      </Box>

      <Legend />

      <Box flexDirection="column" marginTop={SPACING.sm}>
        <Text>{tokens.label("impact × likelihood")}</Text>
        <PivotTable pivot={pivot} />
      </Box>
    </ScreenContent>
  );
}

function EmptyState(): React.ReactElement {
  return (
    <ScreenContent>
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("STRIDE matrix")}
      </Text>
      <Box marginTop={SPACING.sm}>
        <EmptyStateCard kind="threat-model-missing" context={{ threatView: "stride" }} />
      </Box>
    </ScreenContent>
  );
}

function MatrixHeaderRow({
  idWidth,
  nameWidth,
}: {
  idWidth: number;
  nameWidth: number;
}): React.ReactElement {
  return (
    <Box flexDirection="row">
      <Box width={idWidth} marginRight={2}>
        <Text>{tokens.muted("id")}</Text>
      </Box>
      <Box width={nameWidth} marginRight={2}>
        <Text>{tokens.muted("element")}</Text>
      </Box>
      {STRIDE_COLUMNS.map((col) => (
        <Box key={col.category} width={3}>
          <Text>{tokens.label(col.letter)}</Text>
        </Box>
      ))}
    </Box>
  );
}

function MatrixRow({
  element,
  threats,
  idWidth,
  nameWidth,
}: {
  element: DfdNode;
  threats: ReadonlyArray<StrideThreat>;
  idWidth: number;
  nameWidth: number;
}): React.ReactElement {
  const name =
    element.name.length > nameWidth
      ? `${element.name.slice(0, nameWidth - 1)}\u2026`
      : element.name;
  const cells = STRIDE_COLUMNS.map((col) => {
    const impact = computeStrideCell(threats, element.id, col.category);
    return colorCell(impact);
  });
  return (
    <Box flexDirection="row">
      <Box width={idWidth} marginRight={2}>
        <Text>{tokens.muted(element.id)}</Text>
      </Box>
      <Box width={nameWidth} marginRight={2}>
        <Text>{tokens.value(name)}</Text>
      </Box>
      {cells.map((cell, index) => (
        <Box key={`${element.id}:${STRIDE_COLUMNS[index]?.category}`} width={3}>
          <Text>{cell}</Text>
        </Box>
      ))}
    </Box>
  );
}

function colorCell(impact: CellImpact): string {
  const glyph = cellGlyph(impact);
  if (impact === null) return tokens.muted(glyph);
  return heatToken(impact)(glyph);
}

function Legend(): React.ReactElement {
  return (
    <Box marginTop={SPACING.sm}>
      <Text>
        {tokens.hint("cells: ")}
        {heatToken("critical")("\u2588 crit")}
        {tokens.muted("  ")}
        {heatToken("high")("\u2593 high")}
        {tokens.muted("  ")}
        {heatToken("medium")("\u2592 med")}
        {tokens.muted("  ")}
        {heatToken("low")("\u2591 low")}
        {tokens.muted("  ")}
        {tokens.muted("\u00B7 none")}
      </Text>
    </Box>
  );
}

function PivotTable({
  pivot,
}: {
  pivot: ReturnType<typeof computeImpactLikelihoodPivot>;
}): React.ReactElement {
  const impacts: Array<"critical" | "high" | "medium" | "low"> = [
    "critical",
    "high",
    "medium",
    "low",
  ];
  const likelihoods: Array<"high" | "medium" | "low"> = ["high", "medium", "low"];
  return (
    <Box flexDirection="column">
      <Box flexDirection="row">
        <Box width={20} marginRight={2}>
          <Text>{tokens.muted("impact \\ likelihood")}</Text>
        </Box>
        {likelihoods.map((l) => (
          <Box key={l} width={8}>
            <Text>{tokens.muted(l)}</Text>
          </Box>
        ))}
      </Box>
      {impacts.map((impact) => (
        <Box key={impact} flexDirection="row">
          <Box width={20} marginRight={2}>
            <Text>{tokens.value(impact)}</Text>
          </Box>
          {likelihoods.map((l) => {
            const n = pivot[impact][l];
            const body = String(n);
            return (
              <Box key={`${impact}:${l}`} width={8}>
                <Text>{n === 0 ? tokens.muted(body) : heatToken(impact)(body)}</Text>
              </Box>
            );
          })}
        </Box>
      ))}
    </Box>
  );
}

function heatToken(impact: ThreatImpact): (text: string) => string {
  if (impact === "critical" || impact === "high") return tokens.danger;
  if (impact === "medium") return tokens.warn;
  return tokens.muted;
}
