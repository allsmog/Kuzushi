/**
 * ThreatDfdView — attack-surface workspace.
 *
 * This is intentionally more than a static DFD. It turns the generated
 * context/threat model into an operator navigation surface: zones, trust
 * boundaries, hot paths, selected node detail, regeneration affordances, and
 * reviewable AI patches.
 */

import { Box, Text } from "ink";
import type React from "react";
import {
  type AttackSurfaceDfdModel,
  type AttackSurfaceFlow,
  type AttackSurfaceNode,
  deriveAttackSurfaceDfdModel,
  flowsForNode,
  selectedAttackSurfaceNode,
} from "../../attack-surface-dfd.js";
import { formatThreatModelSource } from "../../copilot/threat-model-loader.js";
import { truncateEnd } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { useTerminalSize } from "../hooks/useTerminalSize.js";
import type { ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { RuleHeader } from "./RuleHeader.js";
import { ScreenContent } from "./ScreenContent.js";

interface ThreatDfdViewProps {
  shell: ShellState;
}

export function ThreatDfdView({ shell }: ThreatDfdViewProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "1", label: "dfd" },
    { keys: "2", label: "stride", secondary: true },
    { keys: "3", label: "stories", secondary: true },
    { keys: "4", label: "scope", secondary: true },
    { keys: "5", label: "summary", secondary: true },
    { keys: "r", label: "regen", secondary: true },
    { keys: "q", label: "back", secondary: true },
  ]);

  const sourceLabel = shell.threatModelSource
    ? formatThreatModelSource({
        sourcePath: shell.threatModelSource.path,
        mtimeMs: shell.threatModelSource.mtimeMs,
      })
    : undefined;
  const model = deriveAttackSurfaceDfdModel({
    threatModel: shell.threatModel,
    contextSnapshot: shell.contextSnapshot,
    sourceKind: shell.threatModelSource?.path.endsWith("context-snapshot.json")
      ? "context"
      : shell.threatModel
        ? "persistent"
        : shell.contextSnapshot
          ? "context"
          : "empty",
    sourceLabel,
    selectedId: shell.threatDfdSelection,
  });

  const status = [
    `${model.nodes.length} nodes`,
    `${model.flows.length} flows`,
    `${model.boundaries.length} boundaries`,
    `${model.stats.threats} threats`,
  ].join(" · ");
  return (
    <ScreenContent>
      <RuleHeader breadcrumb="kuzushi/threats/dfd" status={status} />
      {model.sourceLabel ? (
        <Box marginBottom={SPACING.sm}>
          <Text>{tokens.muted(formatSourceLine(model))}</Text>
        </Box>
      ) : null}
      {model.qualityNotice ? <QualityNotice notice={model.qualityNotice} /> : null}
      <Legend validated={model.basis === "threat-model"} />
      {model.nodes.length === 0 ? <EmptyWorkspace /> : <AttackSurfaceMap model={model} />}
      <SelectedPanel model={model} />
      <StrideOverlay model={model} />
      {shell.contextRegenPaletteOpen ? (
        <RegenerationPalette stale={shell.contextSnapshot?.staleSlices} />
      ) : null}
      {shell.pendingThreatPatch ? <PatchProposalCard shell={shell} /> : null}
      <ControlHint hasPatch={Boolean(shell.pendingThreatPatch)} />
    </ScreenContent>
  );
}

function formatSourceLine(model: AttackSurfaceDfdModel): string {
  if (model.basis === "app-model-inferred") {
    const loadedPrefix = "loaded from ";
    const source = model.sourceLabel.startsWith(loadedPrefix)
      ? model.sourceLabel.slice(loadedPrefix.length)
      : model.sourceLabel;
    return `inferred from ${source}`;
  }
  return model.sourceLabel;
}

function QualityNotice({ notice }: { notice: string }): React.ReactElement {
  return (
    <Box marginBottom={SPACING.sm}>
      <Text>{tokens.warn(notice)}</Text>
    </Box>
  );
}

function Legend({ validated }: { validated: boolean }): React.ReactElement {
  return (
    <Box marginTop={SPACING.sm}>
      <Text>
        {tokens.danger("! hot path")}
        {tokens.muted("   ")}
        {tokens.warn("B boundary")}
        {tokens.muted("   ")}
        {tokens.accent("> selected")}
        {validated ? tokens.muted("   ") : ""}
        {validated ? tokens.success("✓ validated") : ""}
      </Text>
    </Box>
  );
}

function EmptyWorkspace(): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.warn("No context-backed DFD is available yet.")}</Text>
      <Text>
        {tokens.muted("Run /context, /context regen dfd, or /threats edit to create one.")}
      </Text>
    </Box>
  );
}

function AttackSurfaceMap({ model }: { model: AttackSurfaceDfdModel }): React.ReactElement {
  const { columns } = useTerminalSize();
  // Box draws inside the available width; ScreenContent/host padding takes
  // a couple of cells, so reserve 4 (matches the legacy 76-of-80 ratio).
  // Clamp [60..140] so the box stays readable on ultrawide panes too.
  const boxWidth = Math.max(60, Math.min(columns - 4, 140));
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      {model.zones.map((zone, index) => (
        <Box key={zone.id} flexDirection="column">
          <ZoneBlock
            title={zone.title}
            nodes={zone.nodes}
            selectedId={model.selectedId}
            width={boxWidth}
          />
          {index < model.zones.length - 1 ? <BoundaryBetween model={model} zone={zone.id} /> : null}
        </Box>
      ))}
      {model.flows.length > 0 ? <HotPaths model={model} /> : null}
    </Box>
  );
}

function ZoneBlock({
  title,
  nodes,
  selectedId,
  width,
}: {
  title: string;
  nodes: AttackSurfaceNode[];
  selectedId?: string;
  width: number;
}): React.ReactElement {
  const heading = ` ${title} `;
  const fill = "─".repeat(Math.max(0, width - heading.length - 2));
  return (
    <Box flexDirection="column" marginBottom={SPACING.xs}>
      <Text>
        {tokens.muted("┌")}
        {tokens.muted("─")}
        {tokens.warn(heading)}
        {tokens.muted(fill)}
        {tokens.muted("┐")}
      </Text>
      {nodes.map((node) => (
        <NodeRow key={node.id} node={node} selected={node.id === selectedId} width={width} />
      ))}
      <Text>{tokens.muted(`└${"─".repeat(width - 1)}┘`)}</Text>
    </Box>
  );
}

function NodeRow({
  node,
  selected,
  width,
}: {
  node: AttackSurfaceNode;
  selected: boolean;
  width: number;
}): React.ReactElement {
  const marker = selected ? tokens.accent(">") : node.risk === "hot" ? tokens.danger("!") : " ";
  const glyph = nodeGlyph(node);
  const label = `${node.id.padEnd(4)} ${glyph} ${node.name}`;
  const detail = node.tags.length > 0 ? node.tags.slice(0, 3).join(" · ") : node.description;
  // Inner content is `│ ` + marker + " " + label + detail + `│` = width.
  // Reserve 6 cells for the frame (`│ `, marker, space, trailing `│`)
  // then split label/detail at the legacy 34/36 ratio so labels keep
  // priority on narrow panes while ultrawide adds room to both columns.
  const inner = Math.max(20, width - 6);
  const labelWidth = Math.max(12, Math.floor((inner * 34) / 70));
  const detailWidth = Math.max(8, inner - labelWidth);
  const color = selected
    ? tokens.accent
    : node.risk === "hot"
      ? tokens.danger
      : node.risk === "watch"
        ? tokens.warn
        : tokens.value;
  return (
    <Text>
      {tokens.muted("│ ")}
      {marker} {color(truncateEnd(label, labelWidth).padEnd(labelWidth))}
      {tokens.muted(truncateEnd(detail, detailWidth).padEnd(detailWidth))}
      {tokens.muted("│")}
    </Text>
  );
}

function BoundaryBetween({
  model,
  zone,
}: {
  model: AttackSurfaceDfdModel;
  zone: string;
}): React.ReactElement | null {
  const boundary = model.boundaries.find((b) => b.from === zone);
  if (!boundary) {
    return (
      <Text>
        {"   "}
        {tokens.muted("│")}
      </Text>
    );
  }
  return (
    <Text>
      {"   "}
      {tokens.muted("│")} {tokens.warn(boundary.id)}
      {tokens.muted(` ${boundary.name} · ${boundary.crossingFlows.length} crossing`)}
    </Text>
  );
}

function HotPaths({ model }: { model: AttackSurfaceDfdModel }): React.ReactElement {
  const hot = model.flows.filter((flow) => flow.hot).slice(0, 5);
  const shown = hot.length > 0 ? hot : model.flows.slice(0, 5);
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("hot paths")}</Text>
      {shown.map((flow) => (
        <FlowLine key={flow.id} flow={flow} />
      ))}
    </Box>
  );
}

function FlowLine({ flow }: { flow: AttackSurfaceFlow }): React.ReactElement {
  const label = `${flow.id.padEnd(4)} ${flow.source} -> ${flow.target}`;
  const meta = [
    flow.protocol,
    flow.dataClassification,
    flow.crosses.length > 0 ? `crosses ${flow.crosses.join(",")}` : undefined,
  ].filter(Boolean);
  return (
    <Text>
      {"  "}
      {flow.hot ? tokens.danger("!") : tokens.muted("·")} {tokens.value(label.padEnd(24))}
      {flow.hot ? tokens.danger(meta.join(" · ")) : tokens.muted(meta.join(" · "))}
    </Text>
  );
}

function SelectedPanel({ model }: { model: AttackSurfaceDfdModel }): React.ReactElement | null {
  const node = selectedAttackSurfaceNode(model);
  if (!node) return null;
  const flows = flowsForNode(model, node.id);
  const risks = node.tags.length > 0 ? node.tags.join(" · ") : node.description;
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>
        {tokens.label("Selected")}
        {"  "}
        {tokens.accent(`${node.id} ${node.name}`)}
      </Text>
      <Text>
        {"  "}
        {tokens.muted("zone   ")}
        {tokens.value(node.zone)}
      </Text>
      <Text>
        {"  "}
        {tokens.muted("inputs ")}
        {tokens.value(formatFlowEndpoints(flows.inputs, "source"))}
      </Text>
      <Text>
        {"  "}
        {tokens.muted("outputs ")}
        {tokens.value(formatFlowEndpoints(flows.outputs, "target"))}
      </Text>
      <Text>
        {"  "}
        {tokens.muted("risks  ")}
        {node.risk === "hot" ? tokens.danger(risks) : tokens.warn(risks)}
      </Text>
      <Text>
        {"  "}
        {tokens.muted("next   ")}
        {tokens.value(model.nextActions.slice(0, 2).join(" · "))}
      </Text>
    </Box>
  );
}

function StrideOverlay({ model }: { model: AttackSurfaceDfdModel }): React.ReactElement {
  const counts = model.strideCounts;
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("STRIDE overlay")}</Text>
      <Text>
        {"  "}
        {tokens.value(`S:${counts.spoofing}`)}
        {tokens.muted("  ")}
        {tokens.value(`T:${counts.tampering}`)}
        {tokens.muted("  ")}
        {tokens.value(`R:${counts.repudiation}`)}
        {tokens.muted("  ")}
        {tokens.value(`I:${counts["information-disclosure"]}`)}
        {tokens.muted("  ")}
        {tokens.value(`D:${counts["denial-of-service"]}`)}
        {tokens.muted("  ")}
        {tokens.value(`E:${counts["elevation-of-privilege"]}`)}
        {model.stats.threats === 0
          ? tokens.warn("   no threats emitted; watch hot paths and privileged choke points")
          : null}
      </Text>
    </Box>
  );
}

function RegenerationPalette({ stale }: { stale?: readonly string[] }): React.ReactElement {
  const staleLabel = stale && stale.length > 0 ? `stale: ${stale.join(", ")}` : "no stale slices";
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("Regenerate generated slice")}</Text>
      <Text>{tokens.muted(`  ${staleLabel}`)}</Text>
      <Text>{tokens.value("  /context regen repo        repo/file signals")}</Text>
      <Text>{tokens.value("  /context regen app-model   routes, stores, boundaries")}</Text>
      <Text>{tokens.value("  /context regen dfd         data-flow diagram")}</Text>
      <Text>{tokens.value("  /context regen stride      STRIDE overlay")}</Text>
      <Text>{tokens.value("  /context regen scenarios   downstream probes")}</Text>
    </Box>
  );
}

function PatchProposalCard({ shell }: { shell: ShellState }): React.ReactElement | null {
  const patch = shell.pendingThreatPatch;
  if (!patch) return null;
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("AI proposed DFD patch")}</Text>
      <Text>
        {"  "}
        {tokens.muted("instruction ")}
        {tokens.value(patch.instruction)}
      </Text>
      <Text>
        {"  "}
        {tokens.muted("summary     ")}
        {tokens.value(patch.summary)}
      </Text>
      {patch.diffLines.slice(0, 8).map((line) => (
        <Text key={line}>
          {"  "}
          {line.startsWith("-")
            ? tokens.danger(line)
            : line.startsWith("+")
              ? tokens.success(line)
              : tokens.warn(line)}
        </Text>
      ))}
      {patch.validationErrors.length > 0 ? (
        <Text>
          {"  "}
          {tokens.warn(`warnings: ${patch.validationErrors.join(" · ")}`)}
        </Text>
      ) : null}
      <Text>{tokens.muted("  y accept and save · n reject · /threats ask <revision>")}</Text>
    </Box>
  );
}

function ControlHint({ hasPatch }: { hasPatch: boolean }): React.ReactElement {
  return (
    <Box marginTop={SPACING.sm} flexDirection="column">
      <Text>
        {tokens.muted("1 dfd · 2 stride · 3 stories · 4 scope · 5 summary · r regen · q back")}
      </Text>
      <Text>{tokens.muted("AI edits: /threats ask <instruction>")}</Text>
      {hasPatch ? (
        <Text>{tokens.muted("patch proposal: y accept · n reject · /threats ask <revision>")}</Text>
      ) : null}
    </Box>
  );
}

function nodeGlyph(node: AttackSurfaceNode): string {
  switch (node.type) {
    case "external-entity":
      return "(ext)";
    case "process":
      return "[proc]";
    case "data-store":
      return "<<data>>";
  }
}

function formatFlowEndpoints(flows: AttackSurfaceFlow[], side: "source" | "target"): string {
  if (flows.length === 0) return "(none)";
  return flows
    .slice(0, 4)
    .map((flow) => flow[side])
    .join(" · ");
}
