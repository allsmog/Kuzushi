/**
 * ThreatDfdView — Phase C.1 ASCII data-flow diagram.
 *
 * Renders the randori PASTA DFD in three sections:
 *
 *   1. One block per trust zone, listing its entities / processes / data
 *      stores grouped by glyph: ( external ), [ process ], << store >>.
 *   2. Dashed gutters for each TrustBoundary with its id + name, plus the
 *      number of flows crossing it.
 *   3. Flow table at the bottom showing source → target per data-flow,
 *      with protocol + dataClassification chips and a (crosses Bn) tag
 *      when the flow appears in a boundary's `crossingFlows`.
 *
 * The rendering is deliberately static — Ink's reflow model makes real
 * graph layout painful in narrow terminals. Grouping by trust zone keeps
 * the visual read "network-diagram shaped" without fighting the layout.
 */

import { Box, Text } from "ink";
import type React from "react";
import type { DfdElement, TrustBoundary } from "../../agents/tasks/threat-modeling/types.js";
import { formatThreatModelSource } from "../../copilot/threat-model-loader.js";
import type { ShellState } from "../state.js";
import { tokens } from "../tokens.js";

interface ThreatDfdViewProps {
  shell: ShellState;
}

export function ThreatDfdView({ shell }: ThreatDfdViewProps): React.ReactElement {
  const tm = shell.threatModel;
  if (!tm) return <EmptyState />;

  const elements = tm.dfd.elements ?? [];
  const boundaries = tm.dfd.trustBoundaries ?? [];
  const flows = elements.filter((e) => e.type === "data-flow");
  const nonFlows = elements.filter((e) => e.type !== "data-flow");

  // Group non-flow elements by trust zone so each rendered block reads as
  // "this is what lives inside this zone". Unknown zones are bucketed
  // under "(unzoned)" so nothing gets silently dropped.
  const zones = new Map<string, DfdElement[]>();
  for (const el of nonFlows) {
    const key = el.trustZone || "(unzoned)";
    const bucket = zones.get(key) ?? [];
    bucket.push(el);
    zones.set(key, bucket);
  }
  const zoneOrder = [...zones.keys()].sort(zoneSortFn);

  return (
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Header shell={shell} elementCount={elements.length} threatCount={tm.threats.length} />

      <Box flexDirection="column" marginTop={1}>
        {zoneOrder.map((zone) => (
          <ZoneBlock key={zone} zone={zone} elements={zones.get(zone) ?? []} />
        ))}
      </Box>

      {boundaries.length > 0 && (
        <Box flexDirection="column" marginTop={1}>
          <Text>{tokens.label("trust boundaries")}</Text>
          <Box flexDirection="column" marginTop={1}>
            {boundaries.map((b) => (
              <BoundaryRow key={b.id} boundary={b} />
            ))}
          </Box>
        </Box>
      )}

      {flows.length > 0 && (
        <Box flexDirection="column" marginTop={1}>
          <Text>{tokens.label("data flows")}</Text>
          <Box flexDirection="column" marginTop={1}>
            {flows.map((flow) => (
              <FlowRow
                key={flow.id}
                flow={flow}
                crossingBoundaries={boundaries.filter((b) => b.crossingFlows.includes(flow.id))}
              />
            ))}
          </Box>
        </Box>
      )}

      <HintFooter />
    </Box>
  );
}

function EmptyState(): React.ReactElement {
  return (
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("data flow diagram")}
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
        {tokens.strong("data flow diagram")}
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

function ZoneBlock({
  zone,
  elements,
}: {
  zone: string;
  elements: DfdElement[];
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginBottom={1}>
      <Text>
        {tokens.muted("\u256D\u2500 ")}
        {tokens.accent(zone)}
        {tokens.muted(` \u2500${"\u2500".repeat(Math.max(0, 70 - zone.length - 5))}\u256E`)}
      </Text>
      {elements.map((el) => (
        <ZoneRow key={el.id} element={el} />
      ))}
      <Text>{tokens.muted(`\u2570${"\u2500".repeat(72)}\u256F`)}</Text>
    </Box>
  );
}

function ZoneRow({ element }: { element: DfdElement }): React.ReactElement {
  const glyph = formatGlyph(element);
  const id = tokens.muted(element.id.padEnd(6));
  const name = tokens.strong(element.name);
  const desc = element.description ? tokens.muted(` — ${truncate(element.description, 44)}`) : "";
  return (
    <Text>
      {tokens.muted("\u2502 ")}
      {id}
      {"  "}
      {glyph}
      {"  "}
      {name}
      {desc}
    </Text>
  );
}

function formatGlyph(element: DfdElement): string {
  switch (element.type) {
    case "external-entity":
      return tokens.accent("( ext )");
    case "process":
      return tokens.strong("[ proc ]");
    case "data-store":
      return tokens.info("<< data >>");
    default:
      return tokens.muted("(?)");
  }
}

function BoundaryRow({ boundary }: { boundary: TrustBoundary }): React.ReactElement {
  const crossings = boundary.crossingFlows.length;
  return (
    <Text>
      {"   "}
      {tokens.warn("\u254C\u254C\u254C ")}
      {tokens.strong(boundary.id)}
      {"  "}
      {tokens.value(boundary.name)}
      {tokens.muted(`   ${boundary.innerZone} \u2194 ${boundary.outerZone}`)}
      {tokens.muted(`   ${crossings} crossing${crossings === 1 ? "" : "s"}`)}
    </Text>
  );
}

function FlowRow({
  flow,
  crossingBoundaries,
}: {
  flow: DfdElement;
  crossingBoundaries: TrustBoundary[];
}): React.ReactElement {
  const src = flow.source ?? "?";
  const dst = flow.target ?? "?";
  const protocol = flow.protocol ? tokens.muted(` [${flow.protocol}]`) : "";
  const classification = flow.dataClassification
    ? tokens.info(` {${flow.dataClassification}}`)
    : "";
  const crossing =
    crossingBoundaries.length > 0
      ? tokens.warn(`  crosses ${crossingBoundaries.map((b) => b.id).join(", ")}`)
      : "";
  return (
    <Text>
      {"   "}
      {tokens.muted(flow.id.padEnd(6))}
      {"  "}
      {tokens.value(src)}
      {tokens.muted(" \u2192 ")}
      {tokens.value(dst)}
      {protocol}
      {classification}
      {crossing}
    </Text>
  );
}

function HintFooter(): React.ReactElement {
  return (
    <Box marginTop={1}>
      <Text>
        {tokens.hint("1 dfd  ")}
        {tokens.muted("2 stride  3 stories  4 scope  5 summary")}
        {tokens.hint("   q back")}
      </Text>
    </Box>
  );
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}\u2026`;
}

function zoneSortFn(a: string, b: string): number {
  // Heuristic: "internet" first (external-most), "(unzoned)" last. Anything
  // matching "meta" / "cloud" goes near the bottom since metadata / cloud
  // internals tend to sit deepest in the trust graph.
  const order = (z: string): number => {
    const lz = z.toLowerCase();
    if (lz === "(unzoned)") return 99;
    if (lz.includes("internet") || lz.includes("external")) return 0;
    if (lz.includes("vpc") || lz.includes("app")) return 10;
    if (lz.includes("db") || lz.includes("store")) return 20;
    if (lz.includes("meta") || lz.includes("cloud")) return 30;
    return 50;
  };
  return order(a) - order(b) || a.localeCompare(b);
}
