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
  DfdElement,
  StrideCategory,
  StrideThreat,
} from "../../agents/tasks/threat-modeling/types.js";
import { formatThreatModelSource } from "../../copilot/threat-model-loader.js";
import { severityChalk } from "../severity.js";
import type { ShellState } from "../state.js";
import { tokens } from "../tokens.js";

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

export type CellImpact = "critical" | "high" | "medium" | "low" | null;

const IMPACT_RANK: Record<Exclude<CellImpact, null>, number> = {
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
    if (t.elementId !== elementId || t.category !== category) continue;
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
): Record<"critical" | "high" | "medium" | "low", Record<"high" | "medium" | "low", number>> {
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
  const tm = shell.threatModel;
  if (!tm) return <EmptyState />;

  const elements = tm.dfd.elements ?? [];
  const threats = tm.threats ?? [];
  // Stable but operator-useful ordering: elements that actually have at least
  // one threat come first (sorted by threat count desc), then the rest.
  const elementThreatCount = new Map<string, number>();
  for (const t of threats) {
    elementThreatCount.set(t.elementId, (elementThreatCount.get(t.elementId) ?? 0) + 1);
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
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Header shell={shell} elementCount={elements.length} threatCount={threats.length} />

      <Box flexDirection="column" marginTop={1}>
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

      <Box flexDirection="column" marginTop={1}>
        <Text>{tokens.label("impact × likelihood")}</Text>
        <PivotTable pivot={pivot} />
      </Box>

      <HintFooter />
    </Box>
  );
}

function EmptyState(): React.ReactElement {
  return (
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("STRIDE matrix")}
      </Text>
      <Box marginTop={1}>
        <Text>
          {tokens.warn("No threat model loaded. Run a scan with threat modelling enabled first.")}
        </Text>
      </Box>
    </Box>
  );
}

function Header({
  shell,
  elementCount,
  threatCount,
}: {
  shell: ShellState;
  elementCount: number;
  threatCount: number;
}): React.ReactElement {
  return (
    <Box flexDirection="column">
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("STRIDE matrix")}
        {tokens.muted("   \u2502   ")}
        {tokens.value(`${elementCount} elements`)}
        {tokens.muted("  \u00B7  ")}
        {tokens.value(`${threatCount} threats`)}
      </Text>
      {shell.threatModelSource ? (
        <Text>
          {tokens.hint(
            formatThreatModelSource({
              sourcePath: shell.threatModelSource.path,
              mtimeMs: shell.threatModelSource.mtimeMs,
            }),
          )}
        </Text>
      ) : null}
    </Box>
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
    <Box flexDirection="column">
      <Text>
        {tokens.muted("id".padEnd(idWidth))}
        {"  "}
        {tokens.muted("element".padEnd(nameWidth))}
        {"  "}
        {STRIDE_COLUMNS.map((col) => tokens.label(` ${col.letter} `)).join("")}
      </Text>
      <Text>
        {tokens.muted("\u2500".repeat(idWidth))}
        {"  "}
        {tokens.muted("\u2500".repeat(nameWidth))}
        {"  "}
        {tokens.muted("\u2500".repeat(STRIDE_COLUMNS.length * 3))}
      </Text>
    </Box>
  );
}

function MatrixRow({
  element,
  threats,
  idWidth,
  nameWidth,
}: {
  element: DfdElement;
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
    <Text>
      {tokens.muted(element.id.padEnd(idWidth))}
      {"  "}
      {tokens.value(name.padEnd(nameWidth))}
      {"  "}
      {cells.join("")}
    </Text>
  );
}

function colorCell(impact: CellImpact): string {
  const glyph = cellGlyph(impact);
  const padded = ` ${glyph} `;
  if (impact === null) return tokens.muted(padded);
  // Pure severity pass-through: the cell glyph already carries the tier
  // visually, so colorblind/NO_COLOR readers still parse the matrix.
  return severityChalk(impact)(padded);
}

function Legend(): React.ReactElement {
  return (
    <Box marginTop={1}>
      <Text>
        {tokens.hint("cells: ")}
        {severityChalk("critical")("\u2588 crit")}
        {tokens.muted("  ")}
        {severityChalk("high")("\u2593 high")}
        {tokens.muted("  ")}
        {severityChalk("medium")("\u2592 med")}
        {tokens.muted("  ")}
        {severityChalk("low")("\u2591 low")}
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
      <Text>
        {tokens.muted("impact \\ likelihood   ")}
        {likelihoods.map((l) => tokens.muted(l.padEnd(8))).join("")}
      </Text>
      {impacts.map((impact) => (
        <Text key={impact}>
          {tokens.value(impact.padEnd(22))}
          {likelihoods
            .map((l) => {
              const n = pivot[impact][l];
              const body = String(n).padEnd(8);
              if (n === 0) return tokens.muted(body);
              return severityChalk(impact)(body);
            })
            .join("")}
        </Text>
      ))}
    </Box>
  );
}

function HintFooter(): React.ReactElement {
  return (
    <Box marginTop={1}>
      <Text>
        {tokens.muted("1 dfd  ")}
        {tokens.hint("2 stride  ")}
        {tokens.muted("3 stories  4 scope  5 summary")}
        {tokens.hint("   q back")}
      </Text>
    </Box>
  );
}
